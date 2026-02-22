import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
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
    """Main dashboard view."""
    sites = Site.objects.all()
    context = {
        'sites': sites,
        'total_sites': sites.count(),
        'verified_sites': sites.filter(is_verified=True).count(),
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


def site_detail(request, site_id):
    """View site details and analytics."""
    site = get_object_or_404(Site, id=site_id)
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


def site_logs(request, site_id):
    """View site error logs."""
    from .models import SiteLog
    site = get_object_or_404(Site, id=site_id)
    logs = site.logs.all().order_by('-created_at')
    
    level = request.GET.get('level')
    if level:
        logs = logs.filter(level=level)
    
    return render(request, 'dashboard/sites/logs.html', {
        'site': site,
        'logs': logs,
        'current_level': level
    })


def edit_site(request, site_id):
    """Edit site details."""
    site = get_object_or_404(Site, id=site_id)
    
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
        return redirect('dashboard:site_detail', site_id=site.id)
    
    return render(request, 'dashboard/sites/edit.html', {'site': site})


@require_http_methods(["POST"])
def delete_site(request, site_id):
    """Delete a site."""
    site = get_object_or_404(Site, id=site_id)
    domain = site.domain
    site.delete()
    messages.success(request, f'Site {domain} deleted')
    return redirect('dashboard:home')


@require_http_methods(["POST"])
def verify_site(request, site_id):
    """Verify site credentials."""
    site = get_object_or_404(Site, id=site_id)
    
    # Get proxy if configured
    proxy = None
    active_proxy = site.proxies.filter(is_active=True).first()
    if active_proxy:
        proxy = {
            'http': active_proxy.get_proxy_url(),
            'https': active_proxy.get_proxy_url()
        }

    print('site==>', site)
    print('username==>', site.wp_username)
    print('password==>', site.wp_password)
	
    
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
    
    return redirect('dashboard:site_detail', site_id=site_id)


@require_http_methods(["GET", "POST"])
def manage_api_keys(request, site_id):
    """Manage API keys for a site."""
    site = get_object_or_404(Site, id=site_id)
    
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
        
        return redirect('dashboard:manage_api_keys', site_id=site_id)
    
    api_keys = site.api_keys.all()
    return render(request, 'dashboard/sites/api_keys.html', {
        'site': site,
        'api_keys': api_keys,
        'providers': APIKey.PROVIDER_CHOICES
    })


@require_http_methods(["POST"])
def delete_api_key(request, site_id, key_id):
    """Delete an API key."""
    api_key = get_object_or_404(APIKey, id=key_id, site_id=site_id)
    api_key.delete()
    messages.success(request, 'API key deleted')
    return redirect('dashboard:manage_api_keys', site_id=site_id)


def proxy_list(request):
    """List all proxies for all sites."""
    proxies = ProxySettings.objects.select_related('site').all().order_by('site__domain', '-created_at')
    sites = Site.objects.all().order_by('domain')
    return render(request, 'dashboard/proxies/list.html', {'proxies': proxies, 'sites': sites})


@require_http_methods(["GET", "POST"])
def manage_proxies(request, site_id):
    """Manage proxy settings for a site."""
    site = get_object_or_404(Site, id=site_id)
    
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
        
        return redirect('dashboard:manage_proxies', site_id=site_id)
    
    proxies = site.proxies.all()
    return render(request, 'dashboard/sites/proxies.html', {
        'site': site,
        'proxies': proxies
    })


@require_http_methods(["POST"])
def delete_proxy(request, site_id, proxy_id):
    """Delete a proxy."""
    proxy = get_object_or_404(ProxySettings, id=proxy_id, site_id=site_id)
    proxy.delete()
    messages.success(request, 'Proxy deleted')
    return redirect('dashboard:manage_proxies', site_id=site_id)


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
        
        # Mark existing sites
        existing_domains = set(Site.objects.values_list('domain', flat=True))
        for zone in zones:
            zone['is_added'] = zone['name'] in existing_domains
    
    return render(request, 'dashboard/settings/cloudflare.html', {
        'cloudflare': cloudflare,
        'zones': zones
    })


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
def test_proxy(request, site_id, proxy_id):
    """AJAX endpoint to test proxy connectivity."""
    proxy = get_object_or_404(ProxySettings, id=proxy_id, site_id=site_id)
    
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

def article_list(request, site_id):
    """List all articles for a site with pagination."""
    from django.core.paginator import Paginator
    
    site = get_object_or_404(Site, id=site_id)
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
def write_articles(request, site_id):
    """Start article generation from a keyword list."""
    site = get_object_or_404(Site, id=site_id)
    keyword_lists_qs = KeywordList.objects.all()
    print(f"[DEBUG] write_articles: Found {keyword_lists_qs.count()} keyword lists")
    
    # Check if site has Groq API key
    has_groq_key = site.api_keys.filter(provider='groq', is_active=True).exists()
    
    if request.method == 'POST':
        list_id = request.POST.get('keyword_list')
        selected_indices = request.POST.getlist('selected_indices')  # For selective creation
        
        if not list_id:
            messages.error(request, 'Please select a keyword list')
            return redirect('dashboard:write_articles', site_id=site_id)
        
        try:
            kw_list = get_object_or_404(KeywordList, id=list_id)
            
            # Offload to Celery to prevent timeout
            from .tasks import create_pending_articles_task
            create_pending_articles_task.delay(site_id, int(list_id), selected_indices or None)
            
            messages.success(request, f'Creating pending articles from "{kw_list.name}" in background. Check logs for progress.')
            return redirect('dashboard:article_list', site_id=site_id)
            
        except Exception as e:
            messages.error(request, f'Error creating articles: {str(e)}')
            return redirect('dashboard:write_articles', site_id=site_id)
    
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


def article_detail(request, site_id, article_id):
    """View/edit a single article."""
    site = get_object_or_404(Site, id=site_id)
    article = get_object_or_404(Article, id=article_id, site=site)
    
    if request.method == 'POST':
        article.title = request.POST.get('title', article.title)
        article.content_html = request.POST.get('content_html', article.content_html)
        article.save()
        messages.success(request, 'Article saved')
        return redirect('dashboard:article_detail', site_id=site_id, article_id=article_id)
    
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
def publish_article(request, site_id, article_id):
    """Publish a single article to WordPress."""
    site = get_object_or_404(Site, id=site_id)
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
    
    return redirect('dashboard:article_detail', site_id=site_id, article_id=article_id)


@require_http_methods(["POST"])
def mass_publish_articles(request, site_id):
    """Publish all ready articles to WordPress."""
    site = get_object_or_404(Site, id=site_id)
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
    return redirect('dashboard:article_list', site_id=site_id)


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
def start_daily_run(request, site_id):
    """Configuration page to start a daily article generation run."""
    from django.utils import timezone
    import datetime

    site = get_object_or_404(Site, id=site_id)
    
    # Check for active run
    active_run = site.daily_runs.filter(status='running').first()
    if active_run:
        return redirect('dashboard:daily_run_status', site_id=site_id, run_id=active_run.run_number)
    
    # Get all keyword lists with site-specific article counts
    from .models import KeywordList, Article
    from django.db.models import Count, Q
    
    # Fetch all keyword lists with their total keywords count
    keyword_lists_raw = KeywordList.objects.all().order_by('-created_at')
    
    # Annotate with site-specific usage
    keyword_lists = []
    for kl in keyword_lists_raw:
        # Count how many articles from this list exist for THIS site
        site_articles_count = Article.objects.filter(
            site=site,
            keyword_list=kl
        ).count()
        
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
        
    if request.method == 'POST':
        target_count = request.POST.get('target_count')
        keyword_list_id = request.POST.get('keyword_list')
        
        # Default to "Now" and "20 hours later" if not provided
        start_time_str = request.POST.get('start_time')
        end_time_str = request.POST.get('end_time')
        
        if not start_time_str:
            # Current UTC time
            start_time_str = timezone.now().strftime('%H:%M')
            
        if not end_time_str:
            # Default window: 20 hours to be safe for high volume
            # Logic in tasks.py handles wrapping to next day if end < start
            end_dt = timezone.now() + datetime.timedelta(hours=20)
            end_time_str = end_dt.strftime('%H:%M')
        
        try:
            target_count = int(target_count)
            keyword_list_obj = KeywordList.objects.get(id=keyword_list_id) if keyword_list_id else None
            
            run = DailyRun.objects.create(
                site=site,
                keyword_list=keyword_list_obj,
                target_count=target_count,
                start_time=start_time_str,
                end_time=end_time_str,
                status='running'
            )
            
            # Trigger Celery task to schedule initial batch
            process_daily_run.delay(run.id)
            
            messages.success(request, f'Daily run started! Target: {target_count} articles.')
            return redirect('dashboard:daily_run_status', site_id=site_id, run_id=run.run_number)
            
        except ValueError:
            messages.error(request, 'Invalid target count')
        except KeywordList.DoesNotExist:
            messages.error(request, 'Invalid keyword list selected')
        except Exception as e:
            messages.error(request, f'Error: {str(e)}')
            
    return render(request, 'dashboard/daily_runs/start.html', {
        'site': site,
        'keyword_lists': keyword_lists
    })


def daily_run_status(request, site_id, run_id):
    """Monitor progress of a daily run."""
    site = get_object_or_404(Site, id=site_id)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)
    
    # Calculate progress percentage
    progress = 0
    if run.target_count > 0:
        progress = (run.completed_count / run.target_count) * 100
    
    # Get articles actually generated by this run (only ready/published, not pending)
    from .models import Article
    articles = Article.objects.filter(
        site=site,
        keyword_list=run.keyword_list,
        created_at__gte=run.started_at,
        status__in=['ready', 'published']
    ).order_by('-created_at')
    
    # Get logs only for this run (created after run started)
    from .models import SiteLog
    run_logs = SiteLog.objects.filter(
        site=site,
        created_at__gte=run.started_at
    ).order_by('-created_at')[:10]
        
    return render(request, 'dashboard/daily_runs/status.html', {
        'site': site,
        'run': run,
        'progress': round(progress, 1),
        'articles': articles,
        'run_logs': run_logs
    })


@require_http_methods(["POST"])
def pause_daily_run(request, site_id, run_id):
    """Pause a daily run (can be resumed later)."""
    site = get_object_or_404(Site, id=site_id)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)
    
    if run.status == 'running':
        run.status = 'paused'
        run.save()
        print(f"[PAUSE] Daily run {run.id} for site {site.domain} paused by user")
        messages.info(request, 'Daily run paused. New articles will not start. You can resume anytime.')
    
    return redirect('dashboard:daily_run_status', site_id=site_id, run_id=run.run_number)


@require_http_methods(["POST"])
def resume_daily_run(request, site_id, run_id):
    """Resume a paused daily run."""
    site = get_object_or_404(Site, id=site_id)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)
    
    if run.status == 'paused':
        run.status = 'running'
        run.save()
        
        # Re-trigger the scheduler to continue processing
        from .tasks import process_daily_run
        process_daily_run.delay(run.id)
        
        messages.success(request, 'Daily run resumed!')
    
    return redirect('dashboard:daily_run_status', site_id=site_id, run_id=run.run_number)


@require_http_methods(["POST"])
def cancel_daily_run(request, site_id, run_id):
    """Cancel a daily run and FORCE KILL active tasks."""
    site = get_object_or_404(Site, id=site_id)
    run = get_object_or_404(DailyRun, run_number=run_id, site=site)
    
    if run.status in ['running', 'paused']:
        run.status = 'cancelled'
        run.save()
        
        # Force Kill: Find all articles currently generating for this run
        from .models import Article
        from app.celery import app as celery_app
        
        active_articles = Article.objects.filter(
            daily_run=run,
            status='generating'
        ).exclude(task_id='')
        
        killed_count = 0
        for article in active_articles:
            try:
                celery_app.control.revoke(article.task_id, terminate=True)
                article.status = 'failed'
                article.error_message = 'Cancelled by user'
                article.save(update_fields=['status', 'error_message'])
                killed_count += 1
            except Exception as e:
                print(f"Failed to kill task {article.task_id}: {e}")
                
        messages.warning(request, f'Daily run cancelled. {killed_count} active tasks were terminated.')
    
    return redirect('dashboard:daily_run_status', site_id=site_id, run_id=run.run_number)


# Keep old name for backwards compatibility with existing URL
stop_daily_run = pause_daily_run


def daily_run_history(request, site_id):
    """View history of all daily runs for a site."""
    site = get_object_or_404(Site, id=site_id)
    runs = site.daily_runs.order_by('-started_at')
    
    return render(request, 'dashboard/daily_runs/history.html', {
        'site': site,
        'runs': runs
    })

