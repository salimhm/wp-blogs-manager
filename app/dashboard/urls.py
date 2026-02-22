from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Main dashboard
    path('', views.dashboard_home, name='home'),
    
    # Site management
    path('sites/', views.site_list, name='site_list'),
    path('sites/add/', views.add_site, name='add_site'),
    path('sites/<int:site_id>/', views.site_detail, name='site_detail'),
    path('sites/<int:site_id>/edit/', views.edit_site, name='edit_site'),
    path('sites/<int:site_id>/delete/', views.delete_site, name='delete_site'),
    path('sites/<int:site_id>/verify/', views.verify_site, name='verify_site'),
    path('sites/<int:site_id>/logs/', views.site_logs, name='site_logs'),
    
    # API Key management
    path('sites/<int:site_id>/api-keys/', views.manage_api_keys, name='manage_api_keys'),
    path('sites/<int:site_id>/api-keys/<int:key_id>/delete/', views.delete_api_key, name='delete_api_key'),
    
    # Proxy management
    path('proxies/', views.proxy_list, name='proxy_list'),
    path('proxies/bulk-tester/', views.bulk_key_tester, name='bulk_key_tester'),
    path('proxies/bulk-tester/stream/', views.stream_key_test, name='stream_key_test'),
    path('sites/<int:site_id>/proxies/', views.manage_proxies, name='manage_proxies'),
    path('sites/<int:site_id>/proxies/<int:proxy_id>/delete/', views.delete_proxy, name='delete_proxy'),
    path('sites/<int:site_id>/proxies/<int:proxy_id>/test/', views.test_proxy, name='test_proxy'),
    
    # Keyword Lists (global)
    path('keywords/', views.keyword_lists, name='keyword_lists'),
    path('keywords/<int:list_id>/delete/', views.delete_keyword_list, name='delete_keyword_list'),
    
    # Articles
    path('sites/<int:site_id>/articles/', views.article_list, name='article_list'),
    path('sites/<int:site_id>/articles/write/', views.write_articles, name='write_articles'),
    path('sites/<int:site_id>/articles/<int:article_id>/', views.article_detail, name='article_detail'),
    path('sites/<int:site_id>/articles/<int:article_id>/publish/', views.publish_article, name='publish_article'),
    path('sites/<int:site_id>/articles/mass-publish/', views.mass_publish_articles, name='mass_publish_articles'),
    
    # Daily Runs
    path('sites/<int:site_id>/daily-run/start/', views.start_daily_run, name='start_daily_run'),
    path('sites/<int:site_id>/daily-run/history/', views.daily_run_history, name='daily_run_history'),
    path('sites/<int:site_id>/daily-run/<int:run_id>/', views.daily_run_status, name='daily_run_status'),
    path('sites/<int:site_id>/daily-run/<int:run_id>/stop/', views.stop_daily_run, name='stop_daily_run'),
    path('sites/<int:site_id>/daily-run/<int:run_id>/pause/', views.pause_daily_run, name='pause_daily_run'),
    path('sites/<int:site_id>/daily-run/<int:run_id>/resume/', views.resume_daily_run, name='resume_daily_run'),
    path('sites/<int:site_id>/daily-run/<int:run_id>/cancel/', views.cancel_daily_run, name='cancel_daily_run'),

    # Settings
    path('settings/', views.settings_view, name='settings'),
    path('settings/cloudflare/', views.cloudflare_settings, name='cloudflare_settings'),
    path('settings/cloudflare/test/', views.test_cloudflare, name='test_cloudflare'),
    
    # AJAX endpoints
    path('api/validate-credentials/', views.api_validate_credentials, name='api_validate_credentials'),
    path('api/create-dns/', views.api_create_dns, name='api_create_dns'),
    path('api/test-proxy/', views.api_test_proxy, name='api_test_proxy'),
    path('api/generate-article/', views.api_generate_article, name='api_generate_article'),
    path('api/bulk-generate/', views.api_bulk_generate_articles, name='api_bulk_generate'),
]

