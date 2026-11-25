from django import forms
from django.contrib import messages
from django.core import signing
from django.db import IntegrityError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from .categories import (
    CategoryError, KITCHEN_RULES, WordPressCategories, category_in_permalink, eligible,
    parse_rules, post_title, suggested_category,
)
from .models import CategoryBackfill, Site
from .tasks import enqueue_category_backfill

PREVIEW_SALT = 'dashboard-category-backfill'
RULE_FORMAT = 'Category name: phrase one, phrase two'


class BackfillForm(forms.Form):
    source = forms.SlugField(
        label='Current category slug', max_length=90, initial='uncategorized',
        widget=forms.TextInput(attrs={'class': 'form-input'}),
    )
    rules = forms.CharField(
        label='Title rules', max_length=8000,
        help_text=f'One category per line. Use {RULE_FORMAT}',
        widget=forms.Textarea(attrs={'rows': 7, 'placeholder': RULE_FORMAT, 'class': 'form-input'}),
    )
    page = forms.IntegerField(
        label='Preview page', min_value=1, max_value=100000, initial=1,
        widget=forms.NumberInput(attrs={'class': 'form-input'}),
    )


def preview_backfill(site, form, create_missing):
    source = form.cleaned_data['source']
    rules = parse_rules(form.cleaned_data['rules'])
    if source in rules:
        raise CategoryError('Choose a different category for the assignments.')
    wp = WordPressCategories(site)
    terms = wp.categories([source, *rules])
    if source not in terms:
        raise CategoryError('The current category slug was not found in WordPress.')

    missing = [slug for slug in rules if slug not in terms]
    if create_missing:
        for slug in missing:
            wp.create_category(slug, rules[slug]['name'])
        terms = wp.categories([source, *rules])
        missing = [slug for slug in rules if slug not in terms]

    page = form.cleaned_data['page']
    posts, total_pages = wp.posts(page)
    source_id = terms[source]['id']
    targets = {slug: terms[slug]['id'] for slug in rules if slug in terms}
    rows = []
    candidates = {}
    matched = 0
    skipped_urls = 0
    for post in posts:
        if not eligible(post, source_id):
            continue
        if category_in_permalink(post, source):
            skipped_urls += 1
            continue
        title = post_title(post)
        slug = suggested_category(title, rules)
        proposed = targets.get(slug)
        matched += proposed is not None
        candidates[post['id']] = title
        rows.append({
            'id': post['id'], 'title': title, 'proposed': proposed,
            'suggestion': rules[slug]['name'] if slug else '',
        })

    token = signing.dumps({
        'site': site.pk, 'source': source, 'source_id': source_id, 'rules': rules, 'targets': targets,
        'rule_text': form.cleaned_data['rules'],
        'candidates': candidates, 'missing': bool(missing), 'max_id': wp.newest_id(),
    }, salt=PREVIEW_SALT, compress=True)
    return {
        'rows': rows, 'token': token, 'matched': matched, 'total_pages': total_pages, 'skipped_urls': skipped_urls,
        'choices': [(term_id, rules[slug]['name']) for slug, term_id in targets.items()],
        'missing': [rules[slug]['name'] for slug in missing], 'page': page,
    }


def launch_backfill(request, site, archive):
    try:
        config = signing.loads(request.POST.get('preview', ''), salt=PREVIEW_SALT, max_age=3600)
    except signing.BadSignature as exc:
        raise CategoryError('Generate a fresh preview before applying a backfill.') from exc
    if config['site'] != site.pk:
        raise CategoryError('Generate a preview for this site before applying changes.')
    candidates = config.pop('candidates')
    if archive:
        if config['missing'] or not config['max_id']:
            raise CategoryError('Create the missing categories and preview the rules before starting a full backfill.')
    else:
        choices = {str(term_id): term_id for term_id in config['targets'].values()}
        config['selected'] = {}
        for post_id, title in candidates.items():
            choice = request.POST.get(f'category_{post_id}', '')
            if not choice:
                continue
            if choice not in choices:
                raise CategoryError('Select a category from this site’s preview.')
            config['selected'][post_id] = {'title': title, 'category_id': choices[choice]}
        if not config['selected']:
            raise CategoryError('Select a category for at least one post.')
    try:
        run = CategoryBackfill.objects.create(site=site, configuration=config)
    except IntegrityError as exc:
        raise CategoryError('Resume or close the existing run before starting another.') from exc
    enqueue_category_backfill(run.pk, run.page)


@require_http_methods(['GET', 'POST'])
def site_categories(request, site_domain):
    site = get_object_or_404(Site, domain=site_domain)
    runs = site.category_backfills
    latest = runs.order_by('-pk').first()
    initial = {'rules': KITCHEN_RULES} if site.domain.removeprefix('www.') == 'kitchenwisdom.info' else {}
    if latest:
        initial.update(source=latest.configuration['source'], rules=latest.configuration['rule_text'])
    action = request.POST.get('action')
    preview_actions = ('preview', 'create_categories')
    form = BackfillForm(request.POST if action in preview_actions else None, initial=initial)
    context = {'site': site, 'form': form, 'run': latest}

    try:
        if action in preview_actions and form.is_valid():
            context['preview'] = preview_backfill(site, form, create_missing=action == 'create_categories')
        elif action in ('apply_preview', 'apply_archive'):
            launch_backfill(request, site, archive=action == 'apply_archive')
            return redirect('dashboard:site_categories', site_domain=site.domain)
        elif action in ('resume', 'close'):
            if latest is None or request.POST.get('run_id') != str(latest.pk):
                raise CategoryError('The run has changed. Refresh the page and try again.')
            active = runs.filter(pk=latest.pk, status__in=['failed', 'queued'])
            if action == 'close':
                active.update(status='cancelled')
            elif active.update(status='queued', last_error=''):
                latest.refresh_from_db()
                enqueue_category_backfill(latest.pk, latest.page)
            return redirect('dashboard:site_categories', site_domain=site.domain)
    except CategoryError as exc:
        messages.error(request, str(exc))

    return render(request, 'dashboard/sites/categories.html', context)
