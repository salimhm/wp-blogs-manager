from django.contrib import admin

from .models import (
    APIKey,
    Article,
    CloudflareSettings,
    KeywordList,
    ProxySettings,
    Site,
    WordPressProvisionJob,
)


@admin.register(CloudflareSettings)
class CloudflareSettingsAdmin(admin.ModelAdmin):
    list_display = ('id', 'is_active', 'created_at')


@admin.register(Site)
class SiteAdmin(admin.ModelAdmin):
    list_display = ('domain', 'is_fresh_installation', 'is_verified', 'created_at')
    list_filter = ('is_fresh_installation', 'is_verified')
    search_fields = ('domain',)


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('site', 'provider', 'model_name', 'is_active')
    list_filter = ('provider', 'is_active')


@admin.register(ProxySettings)
class ProxySettingsAdmin(admin.ModelAdmin):
    list_display = ('site', 'proxy_type', 'host', 'port', 'is_active')
    list_filter = ('proxy_type', 'is_active')


@admin.register(KeywordList)
class KeywordListAdmin(admin.ModelAdmin):
    list_display = ('name', 'item_count', 'created_at')
    search_fields = ('name',)


@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    list_display = ('title', 'site', 'status', 'created_at', 'published_at')
    list_filter = ('status', 'site')
    search_fields = ('title',)


@admin.register(WordPressProvisionJob)
class WordPressProvisionJobAdmin(admin.ModelAdmin):
    list_display = ('site', 'status', 'progress', 'current_step', 'updated_at')
    list_filter = ('status',)
    search_fields = ('site__domain', 'cloudflare_zone_id')
    readonly_fields = (
        'encrypted_site_user_password',
        'encrypted_database_password',
        'encrypted_admin_password',
    )
