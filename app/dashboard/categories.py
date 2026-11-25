"""Title rules and WordPress operations for category backfills."""

import re
from html import unescape
from urllib.parse import unquote, urlsplit

import requests
from django.utils.text import slugify

PAGE_SIZE = 50
BATCH_SIZE = 20
POST_FIELDS = 'id,title,categories,status,link,slug'
KITCHEN_RULES = '''Cooking Techniques: how to grill, how to cook, how do i cook, how to sear, how to smoke, cooking techniques
Ingredients & Substitutions: substitute for, instead of, can i substitute, swap for, difference between
Kitchen Tools: espresso machine, food processor, immersion blender, cookware, kitchen scale, air fryer basket
Food Storage & Safety: how long can, can i freeze, how to store, food poisoning, safe to eat, shelf life
Recipes: recipe, recipes, how to make sauce, homemade recipe'''


class CategoryError(Exception):
    pass


def normalize(text):
    return ' '.join(re.findall(r'[^\W_]+', unescape(text).casefold()))


def parse_rules(text):
    rules = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        name, separator, phrases = line.partition(':')
        name = name.strip()
        slug = slugify(name)
        terms = sorted({phrase for raw in phrases.split(',') if (phrase := normalize(raw))})
        if not separator or not slug or not terms or slug in rules or len(name) > 100 or len(slug) > 90:
            raise CategoryError('Use one unique category name per line, followed by a colon and comma-separated phrases.')
        rules[slug] = {'name': name, 'phrases': terms}
    if not rules or len(rules) > 30:
        raise CategoryError('Enter rules for between 1 and 30 categories.')
    return rules


def suggested_category(title, rules):
    title = f' {normalize(title)} '
    scores = {}
    for slug, rule in rules.items():
        matches = [phrase for phrase in rule['phrases'] if f' {phrase} ' in title]
        if matches:
            scores[slug] = max(len(phrase.split()) for phrase in matches), len(matches)
    if not scores:
        return None
    best_score = max(scores.values())
    winners = [slug for slug, score in scores.items() if score == best_score]
    return winners[0] if len(winners) == 1 else None


def post_title(post):
    return unescape(post['title']['rendered'])


def eligible(post, source_id):
    return post['status'] == 'publish' and set(post['categories']) in (set(), {source_id})


def category_in_permalink(post, source):
    segments = [unquote(part) for part in urlsplit(post.get('link', '')).path.split('/')]
    return segments.count(source) > int(unquote(post.get('slug', '')) == source)


class WordPressCategories:
    def __init__(self, site):
        if not site.wp_app_password or not site.wp_username:
            raise CategoryError('Set the site’s WordPress username and Application Password first.')
        self.base = f'https://{site.domain}/wp-json'
        self.session = requests.Session()
        self.session.auth = (site.wp_username, site.wp_app_password)

    def request(self, method, path, **kwargs):
        try:
            response = self.session.request(
                method, self.base + path, timeout=(4, 10), allow_redirects=False, **kwargs
            )
            if response.status_code in (401, 403):
                raise CategoryError('The WordPress account needs permission to edit these posts or categories.')
            if response.status_code == 400 and response.json().get('code') == 'rest_post_invalid_page_number':
                return [], response.headers
            if not 200 <= response.status_code < 300:
                raise CategoryError(f'WordPress returned HTTP {response.status_code}.')
            return response.json(), response.headers
        except (requests.RequestException, ValueError) as exc:
            raise CategoryError('WordPress did not return a valid response. Check the site and try again.') from exc

    def categories(self, slugs):
        terms, _ = self.request('GET', '/wp/v2/categories', params={'slug': ','.join(slugs), 'per_page': 100})
        return {term['slug']: term for term in terms}

    def create_category(self, slug, name):
        self.request('POST', '/wp/v2/categories', json={'slug': slug, 'name': name})

    def posts(self, page):
        posts, headers = self.request('GET', '/wp/v2/posts', params={
            'page': page, 'per_page': PAGE_SIZE, 'order': 'asc', 'orderby': 'id',
            'status': 'publish', '_fields': POST_FIELDS,
        })
        return posts, int(headers.get('X-WP-TotalPages', 0))

    def newest_id(self):
        posts, _ = self.request('GET', '/wp/v2/posts', params={
            'per_page': 1, 'order': 'desc', 'orderby': 'id', '_fields': 'id',
        })
        return posts[0]['id'] if posts else 0

    def selected_posts(self, ids):
        posts, _ = self.request('GET', '/wp/v2/posts', params={
            'include': ','.join(str(post_id) for post_id in ids), 'per_page': len(ids),
            'status': 'publish', '_fields': POST_FIELDS,
        })
        return posts

    def assign(self, assignments):
        payload, _ = self.request('POST', '/batch/v1', json={'requests': [
            {'path': f'/wp/v2/posts/{post_id}?_fields=id,categories', 'body': {'categories': [category_id]}}
            for post_id, category_id in assignments
        ]})
        confirmed = 0
        for (post_id, category_id), result in zip(assignments, payload.get('responses', [])):
            data = result.get('body') or {}
            if result.get('status') == 200 and data.get('id') == post_id and data.get('categories') == [category_id]:
                confirmed += 1
        return confirmed
