import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_http_methods
from django.contrib import messages

from .models import Site, APIKey, ProxySettings, CloudflareSettings, SiteLog
from .utils import (
    generate_secure_password, 
    generate_username,
    verify_wp_credentials,
    verify_proxy,
    create_cloudflare_dns_record,
    get_cloudflare_zones
)
from .auth import authenticate_user, generate_jwt_token, jwt_required


# ============================================
# Authentication Views
# ============================================

def login_view(request):
    """Login page with JWT authentication."""
    # If already logged in, redirect to dashboard
    if request.COOKIES.get('jwt_token'):
        from .auth import get_user_from_token
        if get_user_from_token(request.COOKIES.get('jwt_token')):
            return redirect('dashboard:home')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        user = authenticate_user(username, password)
        
        if user:
            token = generate_jwt_token(user)
            response = redirect('dashboard:home')
            # Set cookie with 7 day expiry, httponly for security
            response.set_cookie(
                'jwt_token', 
                token, 
                max_age=7*24*60*60,  # 7 days
                httponly=True,
                samesite='Lax'
            )
            return response
        else:
            messages.error(request, 'Invalid username or password')
    
    return render(request, 'dashboard/auth/login.html')


def logout_view(request):
    """Logout and clear JWT cookie."""
    response = redirect('dashboard:login')
    response.delete_cookie('jwt_token')
    messages.success(request, 'You have been logged out')
    return response


# ============================================
# Dashboard Views
# ============================================

def dashboard_home(request):
    """Main dashboard view - optimized: ~8 bulk queries total (was ~150)."""
    import datetime
    import json
    from django.utils import timezone
    from .models import SiteAutomation, DailyRun, Article, GroqUsage
    from .groq_quota import daily_token_capacity, live_pool_counts
    from django.db.models import Count, Sum

    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - datetime.timedelta(days=6)
    sparkline_start = today_start - datetime.timedelta(days=13)

    sites = list(Site.objects.all().prefetch_related('api_keys'))
    site_ids = [s.id for s in sites]

    # ── KPI strip (6 simple count queries) ────────────────────────────
    total_sites = len(sites)
    autopilot_enabled = SiteAutomation.objects.filter(is_enabled=True).count()
    articles_today = Article.objects.filter(status='published', published_at__gte=today_start).count()
    articles_week = Article.objects.filter(status='published', published_at__gte=week_start).count()
    total_published = Article.objects.filter(status='published').count()
    active_key_objects = [
        key
        for site in sites
        for key in site.api_keys.all()
        if key.is_active and key.provider == 'groq'
    ]
    active_keys = len(active_key_objects)
    usage_by_site = {
        row['api_key__site_id']: row
        for row in (
            GroqUsage.objects
            .filter(usage_date=timezone.localdate())
            .values('api_key__site_id')
            .annotate(
                tokens=Sum('total_tokens'),
                requests=Sum('request_count'),
                rate_limits=Sum('rate_limit_count'),
                payload_errors=Sum('payload_too_large_count'),
            )
        )
    }
    groq_tokens_today = sum(row['tokens'] or 0 for row in usage_by_site.values())
    groq_requests_today = sum(row['requests'] or 0 for row in usage_by_site.values())
    groq_rate_limits_today = sum(row['rate_limits'] or 0 for row in usage_by_site.values())
    groq_payload_errors_today = sum(row['payload_errors'] or 0 for row in usage_by_site.values())
    groq_token_capacity = daily_token_capacity(active_key_objects)
    cooling_pools, leased_pools = live_pool_counts(active_key_objects)
    groq_usage_pct = round((groq_tokens_today / groq_token_capacity) * 100, 1) if groq_token_capacity else 0

    # ── Running and resumable runs ───────────────────────────────────────────
    running_runs_qs = list(DailyRun.objects.filter(status='running').select_related('site', 'keyword_list'))
    # Keep the paused section bounded so years of history cannot make the
    # dashboard heavy again.
    paused_runs_qs = list(
        DailyRun.objects
        .filter(status='paused')
        .select_related('site', 'keyword_list')
        .order_by('-started_at')[:100]
    )
    visible_run_ids = [r.id for r in running_runs_qs] + [r.id for r in paused_runs_qs]
    live_counts_map = (
        {
            row['daily_run_id']: row['cnt']
            for row in Article.objects
                .filter(daily_run_id__in=visible_run_ids, status__in=['ready', 'published'])
                .values('daily_run_id').annotate(cnt=Count('id'))
        }
        if visible_run_ids else {}
    )

    def build_run_cards(runs):
        cards = []
        for run in runs:
            live_count = live_counts_map.get(run.id, 0)
            progress = round((live_count / run.target_count) * 100, 1) if run.target_count > 0 else 0
            cards.append({'run': run, 'live_count': live_count, 'progress': progress})
        return cards

    running_runs = build_run_cards(running_runs_qs)
    paused_runs = build_run_cards(paused_runs_qs)

    # ── Sparklines: 1 grouped query replaces 112 individual ones ────────────
    sparkline_map = {}  # { site_id: { date_obj: count } }
    for row in (
        Article.objects
        .filter(site_id__in=site_ids, status='published', published_at__gte=sparkline_start)
        .values('site_id', 'published_at__date')
        .annotate(cnt=Count('id'))
    ):
        sparkline_map.setdefault(row['site_id'], {})[row['published_at__date']] = row['cnt']

    # ── Per-site totals (2 queries) ──────────────────────────────────────────
    total_per_site = {
        row['site_id']: row['cnt']
        for row in Article.objects
            .filter(status='published', site_id__in=site_ids)
            .values('site_id').annotate(cnt=Count('id'))
    }
    today_per_site = {
        row['site_id']: row['cnt']
        for row in Article.objects
            .filter(status='published', published_at__gte=today_start, site_id__in=site_ids)
            .values('site_id').annotate(cnt=Count('id'))
    }

    # ── Automations dict (1 query) ───────────────────────────────────────────
    automations = {a.site_id: a for a in SiteAutomation.objects.filter(site_id__in=site_ids)}

    # ── Last run per site (1 bounded query) ──────────────────────────────────
    # PostgreSQL DISTINCT ON keeps this result proportional to the number of
    # sites. The previous Python grouping transferred every historical run
    # from PostgreSQL and discarded all but one row per site.
    last_runs = (
        DailyRun.objects
        .filter(site_id__in=site_ids)
        .order_by('site_id', '-created_at')
        .distinct('site_id')
        .only('id', 'site_id', 'status', 'created_at')
    )
    last_run_map = {run.site_id: run for run in last_runs}

    # Pre-compute 14 date labels/keys once
    date_labels, date_keys = [], []
    for i in range(13, -1, -1):
        day = today_start - datetime.timedelta(days=i)
        date_labels.append(day.strftime('%b %d'))
        date_keys.append(day.date())

    # ── Assemble per-site rows — pure Python, zero extra DB hits ─────────────
    sites_data = []
    for site in sites:
        site_spark = sparkline_map.get(site.id, {})
        chart_data = [site_spark.get(dk, 0) for dk in date_keys]

        automation     = automations.get(site.id)
        last_run       = last_run_map.get(site.id)
        total_for_site = total_per_site.get(site.id, 0)
        today_for_site = today_per_site.get(site.id, 0)

        # Next cycle countdown (pure Python)
        next_cycle_str = None
        if automation and automation.next_run_time:
            delta = automation.next_run_time - now
            if delta.total_seconds() > 0:
                s = int(delta.total_seconds())
                next_cycle_str = f"{s // 3600}h {(s % 3600) // 60}m"
            else:
                next_cycle_str = "Due now"

        # Key count and quota capacity from prefetched data — no extra query.
        site_keys = [
            key for key in site.api_keys.all()
            if key.is_active and key.provider == 'groq'
        ]
        key_count = len(site_keys)
        site_usage = usage_by_site.get(site.id, {})
        site_token_capacity = daily_token_capacity(site_keys)
        site_tokens = site_usage.get('tokens') or 0
        site_quota_pct = round(
            (site_tokens / site_token_capacity) * 100, 1
        ) if site_token_capacity else 0

        alerts = []
        if automation and automation.is_enabled and key_count == 0:
            alerts.append('No active API keys')
        if last_run and last_run.status == 'failed':
            alerts.append('Last run failed')
        if automation and automation.is_enabled and last_run:
            hours_since = (now - last_run.created_at).total_seconds() / 3600
            if hours_since > 48 and today_for_site == 0:
                alerts.append('No output in 48h')

        sites_data.append({
            'site': site,
            'automation': automation,
            'last_run': last_run,
            'total_published': total_for_site,
            'today_published': today_for_site,
            'chart_data': json.dumps(chart_data),
            'chart_dates': json.dumps(date_labels),
            'key_count': key_count,
            'alerts': alerts,
            'next_cycle': next_cycle_str,
            'groq_tokens': site_tokens,
            'groq_capacity': site_token_capacity,
            'groq_quota_pct': site_quota_pct,
            'groq_requests': site_usage.get('requests') or 0,
            'groq_rate_limits': site_usage.get('rate_limits') or 0,
            'groq_payload_errors': site_usage.get('payload_errors') or 0,
        })

    all_alerts = [(row['site'], row['alerts']) for row in sites_data if row['alerts']]

    context = {
        'sites_data': sites_data,
        'running_runs': running_runs,
        'all_alerts': all_alerts,
        'total_sites': total_sites,
        'autopilot_enabled': autopilot_enabled,
        'articles_today': articles_today,
        'articles_week': articles_week,
        'total_published': total_published,
        'paused_runs': paused_runs,
        'active_keys': active_keys,
        'groq_health': {
            'tokens': groq_tokens_today,
            'capacity': groq_token_capacity,
            'usage_pct': groq_usage_pct,
            'requests': groq_requests_today,
            'rate_limits': groq_rate_limits_today,
            'payload_errors': groq_payload_errors_today,
            'cooling_pools': cooling_pools,
            'leased_pools': leased_pools,
        },
    }
    return render(request, 'dashboard/dashboard.html', context)



def site_list(request):
    """List all sites."""
    sites = Site.objects.all()
    return render(request, 'dashboard/sites/list.html', {'sites': sites})


@require_http_methods(["GET", "POST"])
def add_site(request):
    """Add a new site."""
    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip().lower()
        installation_type = request.POST.get('installation_type')
        
        if not domain:
            messages.error(request, 'Domain is required')
            return redirect('dashboard:add_site')
        
        # Check if site already exists
        if Site.objects.filter(domain=domain).exists():
            messages.error(request, f'Site {domain} already exists')
            return redirect('dashboard:add_site')
        
        if installation_type == 'fresh':
            # Generate credentials for fresh installation
            username = generate_username(domain)
            password = generate_secure_password()
            
            site = Site.objects.create(
                domain=domain,
                wp_username=username,
                wp_password=password,
                is_fresh_installation=True,
                is_verified=False
            )
            
            messages.success(
                request, 
                f'Site {domain} created! Username: {username}, Password: {password}'
            )
            
        elif installation_type == 'existing':
            # Existing site - need credentials
            username = request.POST.get('username', '').strip()
            app_password = request.POST.get('app_password', '').strip()
            
            if not username or not app_password:
                messages.error(request, 'Username and Application Password are required')
                return redirect('dashboard:add_site')
            
            site = Site.objects.create(
                domain=domain,
                wp_username=username,
                wp_password='[Using App Password]', # Placeholder or empty
                wp_app_password=app_password,
                is_fresh_installation=False,
                is_verified=False
            )
            
            # Optionally verify credentials
            if request.POST.get('verify_now'):
                # Pass app_password as the password for verification
                success, message = verify_wp_credentials(domain, username, app_password)
                if success:
                    site.is_verified = True
                    site.save()
                    messages.success(request, f'Site {domain} added and verified!')
                else:
                    messages.warning(request, f'Site added but verification failed: {message}')
            else:
                messages.success(request, f'Site {domain} added successfully')
        
        return redirect('dashboard:home')
    
    initial_domain = request.GET.get('domain', '')
    return render(request, 'dashboard/sites/add.html', {'initial_domain': initial_domain})


def site_detail(request, site_domain):
    """View site details and analytics."""
    site = get_object_or_404(Site, domain=site_domain)
    api_keys = site.api_keys.all()
    proxies = site.proxies.all()
    
    # Analytics
    articles = site.articles.all()
    stats = {
        'total': articles.count(),
        'published': articles.filter(status='published').count(),
        'ready': articles.filter(status='ready').count(),
        'failed': articles.filter(status='failed').count(),
        'generating': articles.filter(status='generating').count(),
        'pending': articles.filter(status='pending').count(),
    }
    
    context = {
        'site': site,
        'api_keys': api_keys,
        'proxies': proxies,
        'stats': stats,
    }
    return render(request, 'dashboard/sites/detail.html', context)


def site_logs(request, site_domain):
    """View site error logs."""
    from .models import SiteLog
    site = get_object_or_404(Site, domain=site_domain)
    logs = site.logs.all().order_by('-created_at')
    
    level = request.GET.get('level')
    if level:
        logs = logs.filter(level=level)
    
    return render(request, 'dashboard/sites/logs.html', {
        'site': site,
        'logs': logs,
        'current_level': level
    })


def edit_site(request, site_domain):
    """Edit site details."""
    site = get_object_or_404(Site, domain=site_domain)
    
    if request.method == 'POST':
        # Update fields
        site.wp_username = request.POST.get('wp_username', site.wp_username).strip()
        
        # Only update passwords if provided (non-empty)
        new_password = request.POST.get('wp_password', '')
        if new_password:
            site.wp_password = new_password
        
        new_app_password = request.POST.get('wp_app_password', '')
        if new_app_password:
            site.wp_app_password = new_app_password
        
        site.wp_admin_email = request.POST.get('wp_admin_email', site.wp_admin_email).strip()
        
        site.save()
        messages.success(request, f'Site {site.domain} updated successfully')
        return redirect('dashboard:site_detail', site_domain=site.domain)
    
    return render(request, 'dashboard/sites/edit.html', {'site': site})


@require_http_methods(["POST"])
def delete_site(request, site_domain):
    """Delete a site."""
    site = get_object_or_404(Site, domain=site_domain)
    domain = site.domain
    site.delete()
    messages.success(request, f'Site {domain} deleted')
    return redirect('dashboard:home')


@require_http_methods(["POST"])
def verify_site(request, site_domain):
    """Verify site credentials."""
    site = get_object_or_404(Site, domain=site_domain)
    
    # Get proxy if configured
    proxy = None
    active_proxy = site.proxies.filter(is_active=True).first()
    if active_proxy:
        proxy = {
            'http': active_proxy.get_proxy_url(),
            'https': active_proxy.get_proxy_url()
        }

    
    # Prioritize Application Password
    password_to_use = site.wp_app_password if site.wp_app_password else site.wp_password
    
    success, message = verify_wp_credentials(
        site.domain, 
        site.wp_username, 
        password_to_use,
        proxy
    )
    
    if success:
        site.is_verified = True
        site.save()
        messages.success(request, message)
    else:
        site.is_verified = False
        site.save()
        messages.error(request, message)
    
    return redirect('dashboard:site_detail', site_domain=site_domain)


@require_http_methods(["GET", "POST"])
def manage_api_keys(request, site_domain):
    """Manage API keys for a site."""
    site = get_object_or_404(Site, domain=site_domain)
    
    if request.method == 'POST':
        provider = request.POST.get('provider')
        api_key = request.POST.get('api_key')
        bulk_keys = request.POST.get('bulk_keys')
        model_name = request.POST.get('model_name', '')
        
        if provider:
            if bulk_keys:
                keys = [k.strip() for k in bulk_keys.replace('\r', '').split('\n') if k.strip()]
                if keys:
                    added_count = 0
                    skipped_count = 0
                    for k in keys:
                        # Prevent duplication anywhere in the database
                        if APIKey.objects.filter(api_key=k).exists():
                            skipped_count += 1
                            continue
                            
                        APIKey.objects.create(
                            site=site,
                            provider=provider,
                            api_key=k,
                            model_name=model_name,
                            is_active=True
                        )
                        added_count += 1
                        
                    if added_count > 0:
                        messages.success(request, f'Successfully added {added_count} {provider.title()} API keys.')
                    if skipped_count > 0:
                        messages.error(request, f'Skipped {skipped_count} keys because they already exist in the database.')
            elif api_key:
                # Prevent duplication anywhere in the database
                if APIKey.objects.filter(api_key=api_key).exists():
                    messages.error(request, 'This API key already exists in the database.')
                else:
                    APIKey.objects.create(
                        site=site,
                        provider=provider,
                        api_key=api_key,
                        model_name=model_name,
                        is_active=True
                    )
                    messages.success(request, f'{provider.title()} API key saved')
        
        return redirect('dashboard:manage_api_keys', site_domain=site_domain)
    
    api_keys = site.api_keys.all()
    return render(request, 'dashboard/sites/api_keys.html', {
        'site': site,
        'api_keys': api_keys,
        'providers': APIKey.PROVIDER_CHOICES
    })


@require_http_methods(["POST"])
def delete_api_key(request, site_domain, key_id):
    """Delete an API key."""
    site = get_object_or_404(Site, domain=site_domain)
    api_key = get_object_or_404(APIKey, id=key_id, site=site)
    api_key.delete()
    messages.success(request, 'API key deleted')
    return redirect('dashboard:manage_api_keys', site_domain=site_domain)


def bulk_key_tester(request):
    """View to load all API keys across all sites for bulk testing."""
    api_keys = APIKey.objects.filter(provider='groq').select_related('site').all()
    proxies = ProxySettings.objects.select_related('site').all().order_by('site__domain')
    return render(request, 'dashboard/tools/bulk_tester.html', {
        'api_keys': api_keys, 
        'proxies': proxies
    })


@require_http_methods(["POST"])
def stream_key_test(request):
    """SSE endpoint for continuously testing a list of API keys."""
    try:
        data = json.loads(request.body)
        keys_to_test = data.get('keys', [])
        proxy_id = data.get('proxy_id')
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    proxy_dict = None
    if proxy_id:
        try:
            proxy = ProxySettings.objects.get(id=proxy_id)
            if proxy.username:
                proxy_url = f"{proxy.proxy_type}://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}"
            else:
                proxy_url = f"{proxy.proxy_type}://{proxy.host}:{proxy.port}"
            proxy_dict = {"http": proxy_url, "https": proxy_url}
        except ProxySettings.DoesNotExist:
            pass

    def generate_events():
        import requests
        import time
        
        url = "https://api.groq.com/openai/v1/models"
        total = len(keys_to_test)
        yield f"data: {json.dumps({'type': 'init', 'total': total})}\n\n"
        
        for idx, item in enumerate(keys_to_test):
            if isinstance(item, dict):
                key = item.get('key', '').strip()
                created_at = item.get('created_at', 'N/A')
                key_id = item.get('key_id')
            else:
                key = str(item).strip()
                created_at = 'N/A'
                key_id = None
                
            if not key:
                continue
                
            masked_key = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else "INVALID_LEN"
            headers = {"Authorization": f"Bearer {key}"}
            
            success = False
            response_text = ""
            status_str = "Error"
            attempts = 0
            restricted = False
            
            for attempt in range(1, 6):
                attempts = attempt
                try:
                    res = requests.get(url, headers=headers, proxies=proxy_dict, timeout=10)
                    if res.status_code == 200:
                        success = True
                        status_str = "Valid"
                        response_text = "200 OK"
                        break
                    elif res.status_code == 429:
                        response_text = f"429 Rate Limit"
                        time.sleep(2)
                        continue
                    elif res.status_code >= 500:
                        response_text = f"{res.status_code} Server Error"
                        time.sleep(2)
                        continue
                    else:
                        status_str = "Invalid"
                        try:
                            error_msg = res.json().get('error', {}).get('message', res.text[:50])
                        except:
                            error_msg = res.text[:50]
                        restricted = 'restricted' in error_msg.lower()
                        if restricted:
                            status_str = "Restricted"
                        response_text = f"{res.status_code} - {error_msg}"
                        break
                except Exception as e:
                    response_text = f"Connection error: {str(e)[:40]}"
                    time.sleep(2)
            
            yield f"data: {json.dumps({'type': 'result', 'key': masked_key, 'key_id': key_id, 'created_at': created_at, 'status': status_str, 'restricted': restricted, 'response': response_text, 'attempts': attempts})}\n\n"
            
            # Tiny sleep to avoid completely saturating local network instantly
            time.sleep(0.1)
            
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    response = StreamingHttpResponse(generate_events(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


@require_http_methods(["POST"])
def delete_restricted_api_keys(request):
    """Delete the exact database keys classified as restricted by the tester."""
    try:
        data = json.loads(request.body)
        key_ids = {int(key_id) for key_id in data.get('key_ids', [])}
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return JsonResponse({'error': f'Invalid key list: {exc}'}, status=400)

    if not key_ids:
        return JsonResponse({'deleted': 0})

    keys = APIKey.objects.filter(provider='groq', id__in=key_ids)
    deleted_count = keys.count()
    keys.delete()
    return JsonResponse({'deleted': deleted_count})


def proxy_list(request):
    """List all proxies for all sites."""
    proxies = ProxySettings.objects.select_related('site').all().order_by('site__domain', '-created_at')
    sites = Site.objects.all().order_by('domain')
    return render(request, 'dashboard/proxies/list.html', {'proxies': proxies, 'sites': sites})


@require_http_methods(["GET", "POST"])
def manage_proxies(request, site_domain):
    """Manage proxy settings for a site."""
    site = get_object_or_404(Site, domain=site_domain)
    
    if request.method == 'POST':
        proxy_type = request.POST.get('proxy_type', 'http')
        host = request.POST.get('host')
        port = request.POST.get('port')
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        if host and port:
            ProxySettings.objects.create(
                site=site,
                proxy_type=proxy_type,
                host=host,
                port=int(port),
                username=username,
                password=password,
                is_active=True
            )
            messages.success(request, 'Proxy added')
        
        return redirect('dashboard:manage_proxies', site_domain=site_domain)
    
    proxies = site.proxies.all()
    return render(request, 'dashboard/sites/proxies.html', {
        'site': site,
        'proxies': proxies
    })


@require_http_methods(["POST"])
def delete_proxy(request, site_domain, proxy_id):
    """Delete a proxy."""
    site = get_object_or_404(Site, domain=site_domain)
    proxy = get_object_or_404(ProxySettings, id=proxy_id, site=site)
    proxy.delete()
    messages.success(request, 'Proxy deleted')
    return redirect('dashboard:manage_proxies', site_domain=site_domain)


def settings_view(request):
    """Main settings view."""
    cloudflare = CloudflareSettings.objects.first()
    return render(request, 'dashboard/settings/index.html', {
        'cloudflare': cloudflare
    })


@require_http_methods(["GET", "POST"])
def cloudflare_settings(request):
    """Cloudflare settings."""
    cloudflare = CloudflareSettings.objects.first()
    
    if request.method == 'POST':
        api_token = request.POST.get('api_token')
        default_zone_id = request.POST.get('default_zone_id', '')
        
        if api_token:
            if cloudflare:
                cloudflare.api_token = api_token
                cloudflare.default_zone_id = default_zone_id
                cloudflare.save()
            else:
                CloudflareSettings.objects.create(
                    api_token=api_token,
                    default_zone_id=default_zone_id
                )
            messages.success(request, 'Cloudflare settings saved')
        
        return redirect('dashboard:settings')
    
    zones = []
    if cloudflare and cloudflare.api_token:
        success, zones = get_cloudflare_zones(cloudflare.api_token)
        
        existing_sites = {
            site.domain: site
            for site in Site.objects.filter(domain__in=[zone['name'] for zone in zones])
        }
        from .models import WordPressProvisionJob
        jobs = {
            job.cloudflare_zone_id: job
            for job in WordPressProvisionJob.objects
                .filter(cloudflare_zone_id__in=[zone['id'] for zone in zones])
                .select_related('site')
        }
        for zone in zones:
            zone['site'] = existing_sites.get(zone['name'])
            zone['job'] = jobs.get(zone['id'])
            zone['is_added'] = zone['site'] is not None
    
    return render(request, 'dashboard/settings/cloudflare.html', {
        'cloudflare': cloudflare,
        'zones': zones
    })


def _provision_job_payload(job):
    return {
        'id': job.id,
        'domain': job.site.domain,
        'status': job.status,
        'status_label': job.get_status_display(),
        'step': job.current_step,
        'progress': job.progress,
        'error': job.last_error,
        'site_url': f'https://{job.site.domain}',
        'admin_url': f'https://{job.site.domain}/wp-admin/',
        'site_detail_url': (
            f'/sites/{job.site.domain}/'
            if job.status == 'ready' else ''
        ),
    }


@require_http_methods(["POST"])
def provision_cloudflare_zone(request, zone_id):
    """Queue one active Cloudflare zone for CloudPanel WordPress installation."""
    import re
    import secrets
    from django.conf import settings
    from django.db import IntegrityError, transaction
    from .models import WordPressProvisionJob
    from .secret_store import encrypt_secret
    from .tasks import provision_wordpress_site

    cloudflare = CloudflareSettings.objects.filter(is_active=True).first()
    if not cloudflare or not cloudflare.api_token:
        return JsonResponse({'success': False, 'error': 'Cloudflare is not configured'}, status=400)
    if not settings.CLOUDPANEL_ORIGIN_IP:
        return JsonResponse({'success': False, 'error': 'CLOUDPANEL_ORIGIN_IP is not configured'}, status=400)

    success, zones = get_cloudflare_zones(cloudflare.api_token)
    zone = next((item for item in zones if item['id'] == zone_id), None) if success else None
    if not zone:
        return JsonResponse({'success': False, 'error': 'Cloudflare zone not found'}, status=404)
    if zone.get('status') != 'active' or zone.get('paused'):
        return JsonResponse({'success': False, 'error': 'The Cloudflare zone must be active'}, status=409)

    existing_job = WordPressProvisionJob.objects.filter(cloudflare_zone_id=zone_id).select_related('site').first()
    if existing_job:
        return JsonResponse({'success': True, 'job': _provision_job_payload(existing_job)}, status=200)
    if Site.objects.filter(domain=zone['name']).exists():
        return JsonResponse({'success': False, 'error': 'This domain is already managed'}, status=409)

    admin_email = (request.POST.get('admin_email') or settings.CLOUDPANEL_ADMIN_EMAIL).strip()
    if not admin_email or '@' not in admin_email:
        return JsonResponse({'success': False, 'error': 'Configure CLOUDPANEL_ADMIN_EMAIL first'}, status=400)

    domain = zone['name'].lower()
    compact = re.sub(r'[^a-z0-9]', '', domain)[:18] or 'site'
    suffix = secrets.token_hex(2)
    site_user = f'wp{compact}{suffix}'[:32]
    database_name = f'wp-{compact}-{suffix}'[:32]
    database_user = f'wp{compact}{suffix}'[:32]
    admin_password = generate_secure_password(24)
    site_user_password = generate_secure_password(24)
    database_password = generate_secure_password(24)
    site_title = (request.POST.get('site_title') or domain.split('.')[0]).strip()[:255]

    try:
        with transaction.atomic():
            site = Site.objects.create(
                domain=domain,
                wp_username=generate_username(domain),
                wp_password=admin_password,
                wp_admin_email=admin_email,
                cloudflare_zone_id=zone_id,
                server_ip=settings.CLOUDPANEL_ORIGIN_IP,
                is_fresh_installation=True,
                is_verified=False,
            )
            job = WordPressProvisionJob.objects.create(
                site=site,
                cloudflare_zone_id=zone_id,
                site_title=site_title,
                site_user=site_user,
                database_name=database_name,
                database_user=database_user,
                encrypted_site_user_password=encrypt_secret(site_user_password),
                encrypted_database_password=encrypt_secret(database_password),
                encrypted_admin_password=encrypt_secret(admin_password),
            )
    except IntegrityError:
        return JsonResponse({'success': False, 'error': 'This domain is already being provisioned'}, status=409)

    try:
        task = provision_wordpress_site.delay(job.id)
        job.celery_task_id = task.id
        job.current_step = 'Queued for installation'
        job.save(update_fields=['celery_task_id', 'current_step', 'updated_at'])
    except Exception as exc:
        job.status = 'failed'
        job.current_step = 'Could not queue provisioning task'
        job.last_error = str(exc)[:1000]
        job.save(update_fields=['status', 'current_step', 'last_error', 'updated_at'])
        return JsonResponse({'success': False, 'job': _provision_job_payload(job)}, status=503)

    return JsonResponse({'success': True, 'job': _provision_job_payload(job)}, status=202)


@require_http_methods(["GET"])
def wordpress_provision_status(request, job_id):
    from .models import WordPressProvisionJob
    job = get_object_or_404(WordPressProvisionJob.objects.select_related('site'), id=job_id)
    return JsonResponse({'success': True, 'job': _provision_job_payload(job)})


@require_http_methods(["POST"])
def retry_wordpress_provision(request, job_id):
    from .models import WordPressProvisionJob
    from .tasks import provision_wordpress_site
    job = get_object_or_404(WordPressProvisionJob.objects.select_related('site'), id=job_id)
    if job.status != 'failed':
        return JsonResponse({'success': False, 'error': 'Only failed jobs can be retried'}, status=409)
    job.status = 'queued'
    job.current_step = 'Queued for retry'
    job.last_error = ''
    job.completed_at = None
    task = provision_wordpress_site.delay(job.id)
    job.celery_task_id = task.id
    job.save(update_fields=[
        'status', 'current_step', 'last_error', 'completed_at',
        'celery_task_id', 'updated_at',
    ])
    return JsonResponse({'success': True, 'job': _provision_job_payload(job)}, status=202)


@require_http_methods(["POST"])
def test_cloudflare(request):
    """Test Cloudflare connection."""
    cloudflare = CloudflareSettings.objects.first()
    
    if not cloudflare or not cloudflare.api_token:
        return JsonResponse({'success': False, 'message': 'No API token configured'})
    
    success, zones = get_cloudflare_zones(cloudflare.api_token)
    
    if success:
        return JsonResponse({
            'success': True, 
            'message': f'Connection successful! Found {len(zones)} zone(s)',
            'zones': zones
        })
    else:
        return JsonResponse({'success': False, 'message': 'Could not connect to Cloudflare'})


# AJAX Endpoints
@require_http_methods(["POST"])
def api_validate_credentials(request):
    """AJAX endpoint to validate WordPress credentials."""
    try:
        data = json.loads(request.body)
        domain = data.get('domain')
        username = data.get('username')
        password = data.get('password')
        
        if not all([domain, username, password]):
            return JsonResponse({'success': False, 'message': 'Missing required fields'})
        
        success, message = verify_wp_credentials(domain, username, password)
        return JsonResponse({'success': success, 'message': message})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON'})


@require_http_methods(["POST"])
def api_create_dns(request):
    """AJAX endpoint to create DNS record."""
    try:
        data = json.loads(request.body)
        domain = data.get('domain')
        server_ip = data.get('server_ip')
        
        if not all([domain, server_ip]):
            return JsonResponse({'success': False, 'message': 'Missing required fields'})
        
        cloudflare = CloudflareSettings.objects.first()
        if not cloudflare or not cloudflare.api_token:
            return JsonResponse({'success': False, 'message': 'Cloudflare not configured'})
        
        zone_id = data.get('zone_id') or cloudflare.default_zone_id
        if not zone_id:
            return JsonResponse({'success': False, 'message': 'Zone ID required'})
        
        success, message = create_cloudflare_dns_record(
            cloudflare.api_token,
            zone_id,
            domain,
            server_ip
        )
        
        return JsonResponse({'success': success, 'message': message})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON'})


@require_http_methods(["POST"])
def test_proxy(request, site_domain, proxy_id):
    """AJAX endpoint to test proxy connectivity."""
    site = get_object_or_404(Site, domain=site_domain)
    proxy = get_object_or_404(ProxySettings, id=proxy_id, site=site)
    
    success, message, info = verify_proxy(
        proxy_type=proxy.proxy_type,
        host=proxy.host,
        port=proxy.port,
        username=proxy.username if proxy.username else None,
        password=proxy.password if proxy.password else None
    )
    
    return JsonResponse({
        'success': success,
        'message': message,
        'info': info
    })


@require_http_methods(["POST"])
def api_test_proxy(request):
    """AJAX endpoint to test proxy credentials before adding."""
    try:
        data = json.loads(request.body)
        proxy_type = data.get('proxy_type', 'http')
        host = data.get('host')
        port = data.get('port')
        username = data.get('username', '')
        password = data.get('password', '')
        
        if not host or not port:
            return JsonResponse({'success': False, 'message': 'Host and port are required'})
        
        try:
            port = int(port)
        except ValueError:
            return JsonResponse({'success': False, 'message': 'Invalid port number'})
        
        success, message, info = verify_proxy(
            proxy_type=proxy_type,
            host=host,
            port=port,
            username=username if username else None,
            password=password if password else None
        )
        
        return JsonResponse({
            'success': success,
            'message': message,
            'info': info
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON'})


# ============================================
# Keyword List Views
# ============================================

from .models import KeywordList, Article

@require_http_methods(["GET", "POST"])
def keyword_lists(request):
    """Manage keyword lists (global)."""
    if request.method == 'POST':
        uploaded_file = request.FILES.get('keyword_file')
        
        if not uploaded_file:
            messages.error(request, 'Please select a file to upload')
            return redirect('dashboard:keyword_lists')
        
        if not uploaded_file.name.endswith('.json'):
            messages.error(request, 'Only JSON files are supported')
            return redirect('dashboard:keyword_lists')
        
        try:
            content = uploaded_file.read().decode('utf-8')
            keywords_data = json.loads(content)
            
            # Validate structure
            if not isinstance(keywords_data, list):
                messages.error(request, 'JSON must be an array of objects with "h2s" key')
                return redirect('dashboard:keyword_lists')
            
            item_count = len(keywords_data)
            name = uploaded_file.name.replace('.json', '')
            
            KeywordList.objects.create(
                name=name,
                keywords_json=keywords_data,
                item_count=item_count
            )
            
            messages.success(request, f'Uploaded "{name}" with {item_count} keyword sets')
            
        except json.JSONDecodeError:
            messages.error(request, 'Invalid JSON file')
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
        
        return redirect('dashboard:keyword_lists')
    
    lists = KeywordList.objects.all()
    return render(request, 'dashboard/keywords/list.html', {'lists': lists})


@require_http_methods(["POST"])
def delete_keyword_list(request, list_id):
    """Delete a keyword list."""
    kw_list = get_object_or_404(KeywordList, id=list_id)
    name = kw_list.name
    kw_list.delete()
    messages.success(request, f'Deleted keyword list: {name}')
    return redirect('dashboard:keyword_lists')


# ============================================
# Article Views
# ============================================

def article_list(request, site_domain):
    """List all articles for a site with pagination."""
    from django.core.paginator import Paginator
    
    site = get_object_or_404(Site, domain=site_domain)
    articles_qs = site.articles.all()
    
    # Get page size from query param (default 20)
    per_page = request.GET.get('per_page', '20')
    try:
        per_page = int(per_page)
        if per_page not in [10, 20, 50, 100]:
            per_page = 20
    except (ValueError, TypeError):
        per_page = 20
    
    # Paginate
    paginator = Paginator(articles_qs, per_page)
    page_number = request.GET.get('page', 1)
    articles = paginator.get_page(page_number)
    
    return render(request, 'dashboard/articles/list.html', {
        'site': site,
        'articles': articles,
        'ready_count': articles_qs.filter(status='ready').count(),
        'total_count': articles_qs.count(),
        'per_page': per_page,
    })


@require_http_methods(["GET", "POST"])
def write_articles(request, site_domain):
    """Start article generation from a keyword list."""
    site = get_object_or_404(Site, domain=site_domain)
    keyword_lists_qs = KeywordList.objects.all()
    print(f"[DEBUG] write_articles: Found {keyword_lists_qs.count()} keyword lists")
    
    # Check if site has Groq API key
    has_groq_key = site.api_keys.filter(provider='groq', is_active=True).exists()
    
    if request.method == 'POST':
        list_id = request.POST.get('keyword_list')
        selected_indices = request.POST.getlist('selected_indices')  # For selective creation
        
        if not list_id:
            messages.error(request, 'Please select a keyword list')
            return redirect('dashboard:write_articles', site_domain=site_domain)
        
        try:
            kw_list = get_object_or_404(KeywordList, id=list_id)
            
            # Offload to Celery to prevent timeout
            from .tasks import create_pending_articles_task
            create_pending_articles_task.delay(site.id, int(list_id), selected_indices or None)
            
            messages.success(request, f'Creating pending articles from "{kw_list.name}" in background. Check logs for progress.')
            return redirect('dashboard:article_list', site_domain=site_domain)
            
        except Exception as e:
            messages.error(request, f'Error creating articles: {str(e)}')
            return redirect('dashboard:write_articles', site_domain=site_domain)
    
    # Build preview data for template
    keyword_lists_data = []
    for kw_list in keyword_lists_qs:
        # Count site-specific usage
        site_articles_count = Article.objects.filter(
            site=site,
            keyword_list=kw_list
        ).count()
        total_keywords = kw_list.item_count or 0
        remaining = max(0, total_keywords - site_articles_count)
        
        items = []
        for i, item in enumerate(kw_list.keywords_json or []):
            if isinstance(item, dict) and 'h2s' in item:
                h2s = item.get('h2s', [])
                preview = h2s[0][:50] + '...' if h2s and len(h2s[0]) > 50 else (h2s[0] if h2s else 'No H2s')
                items.append({'index': i, 'preview': preview, 'count': len(h2s)})
        
        # JSON encode items for safe HTML embedding (limit to first 100 for UI)
        import json
        items_json = json.dumps(items[:100])
        
        keyword_lists_data.append({
            'id': kw_list.id,
            'name': kw_list.name,
            'item_count': kw_list.item_count,
            'remaining': remaining,
            'site_articles': site_articles_count,
            'items': items_json  # Now a JSON string
        })
    
    return render(request, 'dashboard/articles/write.html', {
        'site': site,
        'keyword_lists': keyword_lists_data,
        'has_groq_key': has_groq_key,
    })


def article_detail(request, site_domain, article_id):
    """View/edit a single article."""
    site = get_object_or_404(Site, domain=site_domain)
    article = get_object_or_404(Article, id=article_id, site=site)
    
    if request.method == 'POST':
        article.title = request.POST.get('title', article.title)
        article.content_html = request.POST.get('content_html', article.content_html)
        article.save()
        messages.success(request, 'Article saved')
        return redirect('dashboard:article_detail', site_domain=site_domain, article_id=article_id)
    
    # Extract H2s used for this article
    h2s = []
    if article.keyword_list and article.keyword_index is not None:
        try:
            h2_data = article.keyword_list.keywords_json[article.keyword_index]
            # Handle different formats
            if isinstance(h2_data, dict) and 'h2s' in h2_data:
                h2s = h2_data['h2s']
            elif isinstance(h2_data, list):
                h2s = h2_data
            elif isinstance(h2_data, str):
                h2s = [h2_data]
            else:
                h2s = []
        except (IndexError, KeyError, TypeError):
            pass
    
    return render(request, 'dashboard/articles/detail.html', {
        'site': site,
        'article': article,
        'h2s': h2s,
    })


@require_http_methods(["POST"])
def publish_article(request, site_domain, article_id):
    """Publish a single article to WordPress."""
    site = get_object_or_404(Site, domain=site_domain)
    article = get_object_or_404(Article, id=article_id, site=site)
    
    from .utils import publish_to_wordpress
    from django.utils import timezone
    
    success, message, post_id, post_url = publish_to_wordpress(site, article)
    
    if success:
        article.status = 'published'
        article.wp_post_id = post_id
        article.wp_post_url = post_url
        article.published_at = timezone.now()
        article.save()
        messages.success(request, f'Published: {message}')
    else:
        messages.error(request, f'Failed: {message}')
    
    return redirect('dashboard:article_detail', site_domain=site_domain, article_id=article_id)


@require_http_methods(["POST"])
def mass_publish_articles(request, site_domain):
    """Publish all ready articles to WordPress."""
    site = get_object_or_404(Site, domain=site_domain)
    ready_articles = site.articles.filter(status='ready')
    
    from .utils import publish_to_wordpress
    from django.utils import timezone
    
    published = 0
    failed = 0
    
    for article in ready_articles:
        success, message, post_id, post_url = publish_to_wordpress(site, article)
        if success:
            article.status = 'published'
            article.wp_post_id = post_id
            article.wp_post_url = post_url
            article.published_at = timezone.now()
            article.save()
            published += 1
        else:
            article.error_message = message
            article.save()
            failed += 1
    
    messages.success(request, f'Published {published} articles. Failed: {failed}')
    return redirect('dashboard:article_list', site_domain=site_domain)


@require_http_methods(["POST"])
def api_generate_article(request):
    """AJAX endpoint to generate a single article using Groq."""
    try:
        data = json.loads(request.body)
        article_id = data.get('article_id')
        
        if not article_id:
            return JsonResponse({'success': False, 'message': 'Article ID required'})
        
        article = get_object_or_404(Article, id=article_id)
        site = article.site
        
        # Get Groq API key from site
        api_keys_objs = site.api_keys.filter(is_active=True)
        if not api_keys_objs.exists():
            return JsonResponse({'success': False, 'message': 'No API keys configured for this site'})
        
        # Build api_keys list in correct format for generate_article_content
        api_keys = [{'provider': k.provider, 'api_key': k.api_key, 'is_active': k.is_active} for k in api_keys_objs]
        
        # Get proxy from site (if configured)
        proxy = None
        active_proxy = site.proxies.filter(is_active=True).first()
        if active_proxy:
            proxy_url = active_proxy.get_proxy_url()
            proxy = {
                'http': proxy_url,
                'https': proxy_url
            }
        
        # Get H2s for this article
        kw_list = article.keyword_list
        if not kw_list or article.keyword_index >= len(kw_list.keywords_json):
            return JsonResponse({'success': False, 'message': 'Invalid keyword data'})
        
        h2_data = kw_list.keywords_json[article.keyword_index]
        
        # Handle different formats (dict with 'h2s' key, list, or string)
        if isinstance(h2_data, dict) and 'h2s' in h2_data:
            h2s = h2_data['h2s']
        elif isinstance(h2_data, list):
            h2s = h2_data
        elif isinstance(h2_data, str):
            h2s = [h2_data]
        else:
            h2s = []
        
        if not h2s:
            return JsonResponse({'success': False, 'message': f'No H2s found. Data type: {type(h2_data).__name__}'})
        
        # Generate article with retry logic
        from .utils import generate_article_content
        from .models import SiteLog
        import time
        
        article.status = 'generating'
        article.save()
        
        max_retries = 3
        last_error = None
        
        for attempt in range(max_retries):
            try:
                result = generate_article_content(h2s, api_keys, proxy=proxy)
                
                article.title = result['title']
                article.introduction = result['introduction']
                article.faq_json = result['faq']
                article.content_html = result['html']
                article.status = 'ready'
                article.error_message = ''
                article.save()
                
                return JsonResponse({
                    'success': True,
                    'message': 'Article generated!',
                    'article': {
                        'id': article.id,
                        'title': article.title,
                        'status': article.status,
                    }
                })
                
            except Exception as e:
                last_error = str(e)
                
                # Parse error for better message
                error_msg = last_error
                if '503' in last_error:
                    error_msg = 'Groq API temporarily unavailable (503). Retrying...'
                elif '429' in last_error:
                    error_msg = 'Rate limited by Groq API (429). Retrying...'
                elif '401' in last_error:
                    error_msg = 'Invalid Groq API key (401)'
                elif '400' in last_error:
                    error_msg = 'Bad request to Groq API (400)'
                
                # Log the error
                SiteLog.objects.create(
                    site=site,
                    level='error',
                    source='groq',
                    message=error_msg,
                    details={
                        'article_id': article.id,
                        'attempt': attempt + 1,
                        'raw_error': last_error[:500]
                    }
                )
                
                # For transient errors (503, 429), retry with backoff
                if '503' in last_error or '429' in last_error:
                    if attempt < max_retries - 1:
                        time.sleep(5 * (attempt + 1))  # 5s, 10s, 15s
                        continue
                
                # For permanent errors, don't retry
                if '401' in last_error or '400' in last_error:
                    break
        
        # All retries exhausted or permanent error
        article.status = 'failed'
        article.error_message = last_error or 'Unknown error'
        article.save()
        
        return JsonResponse({'success': False, 'message': article.error_message})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON'})


def api_bulk_generate_articles(request):
    """
    SSE endpoint for bulk article generation with rate limiting.
    Generates pending articles one at a time with delays to avoid rate limits.
    """
    from django.http import StreamingHttpResponse
    from .utils import generate_article_content
    import time
    
    site_id = request.GET.get('site_id')
    if not site_id:
        return JsonResponse({'success': False, 'message': 'site_id required'})
    
    site = get_object_or_404(Site, id=site_id)
    
    # Get Groq API key
    api_key_obj = site.api_keys.filter(provider='groq', is_active=True).first()
    if not api_key_obj:
        return JsonResponse({'success': False, 'message': 'No Groq API key configured'})
    
    # Get proxy if available
    proxy = None
    active_proxy = site.proxies.filter(is_active=True).first()
    if active_proxy:
        proxy_url = active_proxy.get_proxy_url()
        proxy = {'http': proxy_url, 'https': proxy_url}
    
    # Get pending articles - optionally filter by specific IDs
    article_ids = request.GET.get('article_ids', '')
    if article_ids:
        # Parse comma-separated IDs
        try:
            ids = [int(x) for x in article_ids.split(',') if x.strip()]
            pending_articles = list(site.articles.filter(status='pending', id__in=ids).order_by('id'))
        except ValueError:
            pending_articles = list(site.articles.filter(status='pending').order_by('id'))
    else:
        pending_articles = list(site.articles.filter(status='pending').order_by('id'))
    
    total = len(pending_articles)
    
    def generate_events():
        """Generator for SSE events."""
        completed = 0
        failed = 0
        
        # Send initial status
        yield f"data: {json.dumps({'type': 'start', 'total': total})}\n\n"
        
        for i, article in enumerate(pending_articles):
            article_id = article.id
            
            # Get H2s for this article
            kw_list = article.keyword_list
            if not kw_list or article.keyword_index >= len(kw_list.keywords_json):
                failed += 1
                yield f"data: {json.dumps({'type': 'error', 'article_id': article_id, 'message': 'Invalid keyword data'})}\n\n"
                continue
            
            h2_data = kw_list.keywords_json[article.keyword_index]
            # Handle different formats
            if isinstance(h2_data, dict) and 'h2s' in h2_data:
                h2s = h2_data['h2s']
            elif isinstance(h2_data, list):
                h2s = h2_data
            elif isinstance(h2_data, str):
                h2s = [h2_data]
            else:
                h2s = []
            
            if not h2s:
                failed += 1
                yield f"data: {json.dumps({'type': 'error', 'article_id': article_id, 'message': 'No H2s found'})}\n\n"
                continue
            
            # Update status to generating
            article.status = 'generating'
            article.save()
            yield f"data: {json.dumps({'type': 'generating', 'article_id': article_id, 'index': i+1, 'total': total})}\n\n"
            
            # Try to generate with exponential backoff
            max_retries = 3
            base_delay = 30  # seconds for rate limit backoff
            success = False
            
            for retry in range(max_retries):
                try:
                    # Log start
                    SiteLog.objects.create(
                        site=site, 
                        level='info',
                        source='groq_bulk',
                        message=f"Starting generation for article ID {article_id} (Attempt {retry+1})",
                        details={'article_id': article_id}
                    )
                    
                    result = generate_article_content(h2s, api_key_obj.api_key, proxy=proxy)
                    
                    article.title = result['title']
                    article.introduction = result['introduction']
                    article.faq_json = result['faq']
                    article.content_html = result['html']
                    article.status = 'ready'
                    article.save()
                    
                    # Log success
                    SiteLog.objects.create(
                        site=site, 
                        level='info',
                        source='groq_bulk',
                        message=f"Successfully generated article: {article.title}",
                        details={'article_id': article_id, 'title': article.title}
                    )
                    
                    completed += 1
                    success = True
                    
                    yield f"data: {json.dumps({'type': 'completed', 'article_id': article_id, 'title': result['title'], 'index': i+1, 'total': total, 'completed': completed})}\n\n"
                    break
                    
                except Exception as e:
                    error_msg = str(e)
                    
                    # Log to SiteLog
                    try:
                        SiteLog.objects.create(
                            site=site,
                            level='warning' if '429' in error_msg else 'error',
                            source='groq_bulk',
                            message=error_msg[:255],  # Truncate for message field
                            details={
                                'article_id': article_id,
                                'retry': retry + 1,
                                'full_error': error_msg
                            }
                        )
                    except:
                        pass  # Don't let logging failure stop the process
                    
                    # Check if rate limited
                    if 'rate limit' in error_msg.lower() or '429' in error_msg:
                        # If utils.py exhausted all models and raised a rate limit error,
                        # we should stop this article immediately to avoid hanging the worker.
                        article.status = 'failed'
                        article.error_message = f"Rate limit exhausted: {error_msg}"
                        article.save()
                        failed += 1
                        yield f"data: {json.dumps({'type': 'error', 'article_id': article_id, 'message': error_msg})}\n\n"
                        break
                    else:
                        # Non-rate-limit error (e.g. prompt too long, network, etc)
                        # Retry short sleep if not last retry
                        if retry < max_retries - 1:
                            time.sleep(2)
                            continue
                        
                        article.status = 'failed'
                        article.error_message = error_msg
                        article.save()
                        failed += 1
                        yield f"data: {json.dumps({'type': 'error', 'article_id': article_id, 'message': error_msg})}\n\n"
                        break
            
            if not success and article.status != 'failed':
                # Max retries exhausted
                article.status = 'failed'
                article.error_message = 'Max retries exhausted due to rate limiting'
                article.save()
                failed += 1
                yield f"data: {json.dumps({'type': 'error', 'article_id': article_id, 'message': 'Max retries exhausted'})}\n\n"
            
            # Wait 3 seconds between articles to avoid rate limits
            if i < total - 1:  # Don't wait after the last one
                time.sleep(3)
        
        # Send completion event
        yield f"data: {json.dumps({'type': 'done', 'completed': completed, 'failed': failed, 'total': total})}\n\n"
    
    response = StreamingHttpResponse(
        generate_events(),
        content_type='text/event-stream'
    )
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


# ============================================
# Daily Run Views
# ============================================

from .models import DailyRun
from .tasks import process_daily_run

@require_http_methods(["GET", "POST"])
def start_daily_run(request, site_domain):
    """Configuration page to start a daily article generation run."""
    from django.utils import timezone
    import datetime

    site = get_object_or_404(Site, domain=site_domain)
    
    # Get all keyword lists with site-specific article counts
    from .models import KeywordList, Article
    from django.db.models import Count, Q
    
    # Fetch all keyword lists with their total keywords count
    keyword_lists_raw = KeywordList.objects.all().order_by('-created_at')
    
    # Annotate with site-specific usage
    keyword_lists = []
    for kl in keyword_lists_raw:
        # Count how many articles from this list exist for THIS site
        # BUT only count articles that have been published or are actively generating. 
        # "Pending" articles haven't been generated yet and shouldn't count against remaining keywords.
        site_articles_count = Article.objects.filter(
            site=site,
            keyword_list=kl
        ).exclude(status='pending').count()
        
        # Total keywords in the list (use item_count field)
        total_keywords = kl.item_count or 0
        
        # Remaining = total keywords - articles already created for this site
        remaining = max(0, total_keywords - site_articles_count)
        
        keyword_lists.append({
            'id': kl.id,
            'name': kl.name,
            'total_keywords': total_keywords,
            'site_articles': site_articles_count,
            'remaining': remaining,
            'created_at': kl.created_at
        })
        
    # Fetch or Create Automation Settings
    from .models import SiteAutomation
    automation, _ = SiteAutomation.objects.get_or_create(site=site)
    
    # Use the same quota-derived capacity as Celery Beat.
    from .groq_quota import daily_article_capacity
    active_key_objects = list(site.api_keys.filter(is_active=True, provider='groq'))
    active_keys_count = len(active_key_objects)
    estimated_capacity = daily_article_capacity(active_key_objects)

    if request.method == 'POST':
        keyword_list_id = request.POST.get('keyword_list')
        is_enabled = request.POST.get('is_enabled') == 'on'
        
        try:
            automation.keyword_list_id = keyword_list_id if keyword_list_id else None
            automation.is_enabled = is_enabled
            
            if 'run_now' in request.POST:
                from .models import DailyRun
                from .tasks import process_daily_run
                from django.utils import timezone
                import datetime
                
                now = timezone.now()
                target_count = daily_article_capacity(active_key_objects)
                
                # Force the next background beat to happen exactly 24 hours from this second
                automation.next_run_time = now + datetime.timedelta(hours=24)
                
                start_time_str = now.strftime('%H:%M')
                end_dt_20h = now + datetime.timedelta(hours=20)
                end_time_str = end_dt_20h.strftime('%H:%M')
                
                automation.save()
                
                if target_count > 0:
                    run = DailyRun.objects.create(
                        site=automation.site,
                        keyword_list=automation.keyword_list,
                        target_count=target_count,
                        start_time=start_time_str,
                        end_time=end_time_str,
                        status='running'
                    )
                    process_daily_run.delay(run.id)
                    messages.success(request, f'Automation Saved. Started 24-Hour Cycle ({target_count} articles)!')
                    return redirect('dashboard:daily_run_status', site_domain=site.domain, run_id=run.run_number)
                else:
                    messages.error(request, 'You must add API Keys before generating articles.')
                    return redirect('dashboard:site_detail', site_domain=site.domain)
            
            # If standard save:
            automation.save()
            messages.success(request, 'Automation settings updated successfully!')
            return redirect('dashboard:site_detail', site_domain=site.domain)
            
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            
    return render(request, 'dashboard/daily_runs/start.html', {
        'site': site,
        'automation': automation,
        'keyword_lists': keyword_lists,
        'active_keys_count': active_keys_count,
        'estimated_capacity': estimated_capacity
    })


def daily_run_status(request, site_domain, run_id):
    """Monitor progress of a daily run."""
    site = get_object_or_404(Site, domain=site_domain)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)
    
    # Get articles actually generated by this run
    from .models import Article
    
    # Always derive counts live from the DB — never trust the potentially stale counter field
    completed_count = Article.objects.filter(daily_run=run, status__in=['ready', 'published']).count()
    failed_count = Article.objects.filter(daily_run=run, status='failed').count()
    
    # If real counts differ significantly from stored field, silently sync it
    if completed_count != run.completed_count or failed_count != run.failed_count:
        DailyRun.objects.filter(id=run.id).update(
            completed_count=completed_count,
            failed_count=failed_count
        )
        run.completed_count = completed_count
        run.failed_count = failed_count
    
    # Calculate progress percentage
    progress = 0
    if run.target_count > 0:
        progress = (completed_count / run.target_count) * 100
    
    # Last 10 articles for this run
    articles = Article.objects.filter(
        daily_run=run,
        status__in=['ready', 'published']
    ).order_by('-created_at')[:10]
    
    # Get logs only for this run (created after run started)
    from .models import SiteLog
    run_logs = SiteLog.objects.filter(
        site=site,
        created_at__gte=run.started_at
    ).order_by('-created_at')[:10]
        
    return render(request, 'dashboard/daily_runs/status.html', {
        'site': site,
        'run': run,
        'completed_count': completed_count,
        'failed_count': failed_count,
        'progress': round(progress, 1),
        'articles': articles,
        'run_logs': run_logs
    })


def _pause_run_ids(run_ids):
    """Pause runs with constant-memory DB updates and only kill active work."""
    from app.celery import app as celery_app
    from .models import Article

    run_ids = list(run_ids)
    if not run_ids:
        return {'runs': 0, 'active_tasks': 0, 'checkpointed': 0}

    # Status is the primary stop signal. Future ETA tasks consult this before
    # generating, so broadcasting every pending task ID is unnecessary.
    paused_count = DailyRun.objects.filter(
        id__in=run_ids,
        status='running',
    ).update(status='paused')

    active_task_ids = list(
        Article.objects
        .filter(daily_run_id__in=run_ids, status='generating')
        .exclude(task_id='')
        .values_list('task_id', flat=True)
    )

    # Checkpoint only in-flight rows. Pending rows already retain their run,
    # keyword list and keyword_index and require no write during a pause.
    checkpointed_count = Article.objects.filter(
        daily_run_id__in=run_ids,
        status='generating',
    ).update(status='pending', task_id='paused', error_message='')

    terminated_count = len(active_task_ids)
    if active_task_ids:
        try:
            # At most worker concurrency tasks should be generating, rather
            # than the hundreds of future ETA tasks revoked by the old code.
            celery_app.control.revoke(
                active_task_ids,
                terminate=True,
                signal='SIGTERM',
            )
        except Exception as e:
            terminated_count = 0
            print(f"Failed to terminate active tasks for runs {run_ids}: {e}")

    return {
        'runs': paused_count,
        'active_tasks': terminated_count,
        'checkpointed': checkpointed_count,
    }


@require_http_methods(["POST"])
def pause_daily_run(request, site_domain, run_id):
    """Stop a run's active work while preserving its resumable database state."""
    site = get_object_or_404(Site, domain=site_domain)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)

    if run.status == 'running':
        result = _pause_run_ids([run.id])
        print(
            f"[PAUSE] Daily run {run.id} for {site.domain} paused. "
            f"Terminated {result['active_tasks']} active task(s); "
            f"checkpointed {result['checkpointed']} article(s)."
        )
        messages.info(
            request,
            f"Run paused. {result['active_tasks']} active task(s) terminated; "
            "all article and keyword progress was preserved."
        )

    if request.POST.get('return_to') == 'dashboard':
        return redirect('dashboard:home')
    return redirect('dashboard:daily_run_status', site_domain=site_domain, run_id=run.run_number)


@require_http_methods(["POST"])
def pause_all_daily_runs(request):
    """Pause every running run without materializing its pending task IDs."""
    run_ids = list(
        DailyRun.objects
        .filter(status='running')
        .values_list('id', flat=True)
    )
    result = _pause_run_ids(run_ids)
    messages.warning(
        request,
        f"Paused {result['runs']} run(s) and terminated "
        f"{result['active_tasks']} active task(s). All progress was preserved."
    )
    return redirect('dashboard:home')


def _cancel_run_ids(run_ids):
    """Permanently cancel runs and discard all unfinished work for their sites."""
    from app.celery import app as celery_app
    from django.db.models import Q
    from django.utils import timezone
    import datetime
    from .models import Article, SiteAutomation

    run_ids = list(run_ids)
    if not run_ids:
        return {
            'runs': 0,
            'revoked_tasks': 0,
            'active_tasks': 0,
            'deleted_articles': 0,
            'deferred_automations': 0,
        }

    site_ids = list(
        DailyRun.objects
        .filter(id__in=run_ids)
        .values_list('site_id', flat=True)
        .distinct()
    )

    # Flip the stop signal first so tasks that wake during cancellation exit.
    cancelled_count = DailyRun.objects.filter(
        id__in=run_ids,
        status__in=['running', 'paused'],
    ).update(status='cancelled')

    # Include legacy orphan rows. Older schedulers created pending articles
    # without a run and later automation cycles adopted them as new work.
    unfinished_scope = Q(daily_run_id__in=run_ids) | Q(
        site_id__in=site_ids,
        daily_run__isnull=True,
    )
    unfinished_articles = Article.objects.filter(
        unfinished_scope,
        status__in=['pending', 'generating'],
    )
    unfinished_tasks = list(
        unfinished_articles
        .exclude(task_id='')
        .exclude(task_id='paused')
        .values_list('task_id', 'status')
    )
    task_ids = list({task_id for task_id, _status in unfinished_tasks})
    active_task_ids = [
        task_id for task_id, status in unfinished_tasks
        if status == 'generating'
    ]

    revoked_count = len(task_ids)
    if task_ids:
        try:
            # One broadcast replaces the old per-task revoke loop.
            celery_app.control.revoke(task_ids)
        except Exception as exc:
            revoked_count = 0
            print(f"Failed to revoke tasks for cancelled runs {run_ids}: {exc}")

    terminated_count = len(active_task_ids)
    if active_task_ids:
        try:
            celery_app.control.revoke(active_task_ids, terminate=True, signal='SIGTERM')
        except Exception as exc:
            terminated_count = 0
            print(f"Failed to terminate active tasks for cancelled runs {run_ids}: {exc}")

    # Prevent Celery Beat from recreating the workload immediately after a
    # restart. Manual runs remain available; auto-pilot resumes tomorrow.
    deferred_automations = SiteAutomation.objects.filter(
        site_id__in=site_ids,
        is_enabled=True,
    ).update(
        next_run_time=timezone.now() + datetime.timedelta(hours=24),
    )

    # Ready/published work is deliberately preserved. Removing unfinished rows
    # releases their keyword indices for a genuinely new run.
    deleted_articles = unfinished_articles.count()
    unfinished_articles.delete()

    return {
        'runs': cancelled_count,
        'revoked_tasks': revoked_count,
        'active_tasks': terminated_count,
        'deleted_articles': deleted_articles,
        'deferred_automations': deferred_automations,
    }


@require_http_methods(["POST"])
def cancel_all_daily_runs(request):
    """Permanently cancel every running or paused run in one bounded operation."""
    run_ids = list(
        DailyRun.objects
        .filter(status__in=['running', 'paused'])
        .values_list('id', flat=True)
    )
    result = _cancel_run_ids(run_ids)
    messages.warning(
        request,
        f"Permanently cancelled {result['runs']} run(s), revoked "
        f"{result['revoked_tasks']} queued task(s), terminated "
        f"{result['active_tasks']} active task(s), and removed "
        f"{result['deleted_articles']} unfinished article checkpoint(s). "
        f"Deferred {result['deferred_automations']} automation(s) for 24 hours. "
        "Ready and published articles were preserved."
    )
    return redirect('dashboard:home')


@require_http_methods(["POST"])
def resume_daily_run(request, site_domain, run_id):
    """Resume a paused daily run."""
    site = get_object_or_404(Site, domain=site_domain)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)

    if run.status == 'paused':
        from .models import Article

        # Invalidate old ETA messages before making the run executable again.
        # process_daily_run will assign fresh IDs as it re-schedules each row.
        Article.objects.filter(
            daily_run=run,
            status='pending',
        ).update(task_id='paused')
        DailyRun.objects.filter(id=run.id).update(status='running')

        from .tasks import process_daily_run
        process_daily_run.delay(run.id)

        messages.success(request, 'Daily run resumed!')

    if request.POST.get('return_to') == 'dashboard':
        return redirect('dashboard:home')
    return redirect('dashboard:daily_run_status', site_domain=site_domain, run_id=run.run_number)


@require_http_methods(["POST"])
def cancel_daily_run(request, site_domain, run_id):
    """Permanently cancel one run and discard its unfinished checkpoints."""
    site = get_object_or_404(Site, domain=site_domain)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)
    
    if run.status in ['running', 'paused']:
        result = _cancel_run_ids([run.id])
        messages.warning(
            request,
            f"Run permanently cancelled. {result['revoked_tasks']} queued task(s) revoked, "
            f"{result['active_tasks']} active task(s) "
            f"terminated and {result['deleted_articles']} unfinished checkpoint(s) removed. "
            "Auto-pilot was deferred for 24 hours."
        )
    
    return redirect('dashboard:daily_run_status', site_domain=site_domain, run_id=run.run_number)


# Keep old name for backwards compatibility with existing URL
stop_daily_run = pause_daily_run


def daily_run_history(request, site_domain):
    """View history of all daily runs for a site."""
    site = get_object_or_404(Site, domain=site_domain)
    runs = site.daily_runs.order_by('-started_at')
    
    return render(request, 'dashboard/daily_runs/history.html', {
        'site': site,
        'runs': runs
    })

