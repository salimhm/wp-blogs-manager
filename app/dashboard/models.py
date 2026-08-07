from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator


class CloudflareSettings(models.Model):
    """Global Cloudflare API settings."""
    api_token = models.CharField(max_length=255, help_text="Cloudflare API token with DNS edit permission")
    default_zone_id = models.CharField(max_length=64, blank=True, help_text="Default Zone ID for domains")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Cloudflare Settings"
        verbose_name_plural = "Cloudflare Settings"

    def __str__(self):
        return f"Cloudflare Settings (Active: {self.is_active})"


class Site(models.Model):
    """WordPress site configuration."""
    domain = models.CharField(max_length=255, unique=True, help_text="Domain name (e.g., example.com)")
    wp_username = models.CharField(max_length=150, blank=True)
    wp_password = models.CharField(max_length=255, blank=True, help_text="WP Admin password")
    wp_app_password = models.CharField(max_length=255, blank=True, help_text="WordPress Application Password for REST API")
    wp_admin_email = models.EmailField(blank=True)
    
    is_fresh_installation = models.BooleanField(default=False, help_text="True if credentials were auto-generated")
    is_verified = models.BooleanField(default=False, help_text="True if credentials have been verified")
    
    # Cloudflare DNS
    cloudflare_zone_id = models.CharField(max_length=64, blank=True, help_text="Override zone ID for this domain")
    server_ip = models.GenericIPAddressField(blank=True, null=True, help_text="Server IP for DNS A record")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        status = "✓" if self.is_verified else "○"
        return f"{status} {self.domain}"


class WordPressProvisionJob(models.Model):
    """Durable progress and secrets for a CloudPanel WordPress installation."""

    STATUS_CHOICES = [
        ('queued', 'Queued'),
        ('dns', 'Configuring DNS'),
        ('cloudpanel', 'Installing on CloudPanel'),
        ('proxy', 'Enabling Cloudflare'),
        ('verifying', 'Verifying WordPress'),
        ('ready', 'Ready'),
        ('failed', 'Failed'),
    ]

    site = models.OneToOneField(
        Site,
        on_delete=models.CASCADE,
        related_name='provision_job',
    )
    cloudflare_zone_id = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    current_step = models.CharField(max_length=160, default='Waiting to start')
    progress = models.PositiveSmallIntegerField(default=0)
    last_error = models.TextField(blank=True)
    celery_task_id = models.CharField(max_length=100, blank=True)
    cloudflare_apex_record_id = models.CharField(max_length=64, blank=True)
    cloudflare_www_record_id = models.CharField(max_length=64, blank=True)
    site_title = models.CharField(max_length=255)
    site_user = models.CharField(max_length=32)
    database_name = models.CharField(max_length=64)
    database_user = models.CharField(max_length=64)
    encrypted_site_user_password = models.TextField()
    encrypted_database_password = models.TextField()
    encrypted_admin_password = models.TextField()
    attempt_count = models.PositiveSmallIntegerField(default=0)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.site.domain}: {self.get_status_display()}"

    @property
    def is_active(self):
        return self.status not in {'ready', 'failed'}


class APIKey(models.Model):
    """API keys for AI services - multiple per site."""
    PROVIDER_CHOICES = [
        ('groq', 'Groq'),
        ('sambanova', 'SambaNova'),
        ('cerebras', 'Cerebras'),
    ]

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='api_keys')
    provider = models.CharField(max_length=50, choices=PROVIDER_CHOICES)
    api_key = models.CharField(max_length=255, help_text="API key (encrypted)")
    model_name = models.CharField(max_length=100, blank=True, help_text="e.g., llama-3.3-70b-versatile")
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        ordering = ['provider']  # Consistent order for fallback

    def __str__(self):
        return f"{self.site.domain} - {self.get_provider_display()}"


class GroqUsage(models.Model):
    """Persistent daily Groq usage and error counters per API key/model."""

    api_key = models.ForeignKey(APIKey, on_delete=models.CASCADE, related_name='groq_usage')
    model_name = models.CharField(max_length=100)
    usage_date = models.DateField()
    request_count = models.PositiveIntegerField(default=0)
    prompt_tokens = models.PositiveBigIntegerField(default=0)
    completion_tokens = models.PositiveBigIntegerField(default=0)
    total_tokens = models.PositiveBigIntegerField(default=0)
    rate_limit_count = models.PositiveIntegerField(default=0)
    payload_too_large_count = models.PositiveIntegerField(default=0)
    error_count = models.PositiveIntegerField(default=0)
    last_status_code = models.PositiveIntegerField(default=0)
    last_error = models.CharField(max_length=500, blank=True)
    tpm_limit = models.PositiveIntegerField(default=0)
    tpd_limit = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-usage_date', 'api_key_id', 'model_name']
        constraints = [
            models.UniqueConstraint(
                fields=['api_key', 'model_name', 'usage_date'],
                name='unique_groq_usage_key_model_day',
            ),
        ]
        indexes = [
            models.Index(fields=['usage_date', 'api_key'], name='groq_usage_day_key_idx'),
        ]

    def __str__(self):
        return f"{self.api_key_id} {self.model_name} {self.usage_date}: {self.total_tokens}"


class ProxySettings(models.Model):
    """Proxy configuration per site."""
    PROXY_TYPE_CHOICES = [
        ('http', 'HTTP'),
        ('socks5', 'SOCKS5'),
    ]

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='proxies')
    proxy_type = models.CharField(max_length=10, choices=PROXY_TYPE_CHOICES, default='http')
    host = models.CharField(max_length=255)
    port = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)])
    username = models.CharField(max_length=150, blank=True)
    password = models.CharField(max_length=255, blank=True, help_text="Encrypted password")
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Proxy Settings"
        verbose_name_plural = "Proxy Settings"

    def __str__(self):
        return f"{self.site.domain} - {self.proxy_type}://{self.host}:{self.port}"
    
    def get_proxy_url(self):
        """Return formatted proxy URL."""
        if self.username and self.password:
            return f"{self.proxy_type}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.proxy_type}://{self.host}:{self.port}"


class KeywordList(models.Model):
    """Global keyword list for article generation."""
    name = models.CharField(max_length=255, help_text="Name of the keyword list (from filename)")
    keywords_json = models.JSONField(help_text="JSON array of H2 heading sets")
    item_count = models.IntegerField(default=0, help_text="Number of H2 sets in the list")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Keyword List"
        verbose_name_plural = "Keyword Lists"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.item_count} items)"


class Article(models.Model):
    """Generated article from keyword list."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('generating', 'Generating'),
        ('ready', 'Ready'),
        ('published', 'Published'),
        ('failed', 'Failed'),
    ]

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='articles')
    keyword_list = models.ForeignKey(KeywordList, on_delete=models.SET_NULL, null=True, related_name='articles')
    keyword_index = models.IntegerField(default=0, help_text="Index of H2 set in keyword list")
    
    # New fields for Force Kill & Logging
    daily_run = models.ForeignKey('DailyRun', on_delete=models.SET_NULL, null=True, blank=True, related_name='articles')
    task_id = models.CharField(max_length=100, blank=True, help_text="Celery task ID for force kill")
    generation_info = models.JSONField(default=dict, blank=True, help_text="Provider, model, and generation stats")
    
    title = models.CharField(max_length=500, blank=True)
    slug = models.SlugField(max_length=500, blank=True)
    introduction = models.TextField(blank=True)
    body = models.TextField(blank=True)
    faq_json = models.JSONField(default=dict, blank=True, help_text="H2 -> Answer pairs")
    content_html = models.TextField(blank=True, help_text="Full rendered HTML")
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    error_message = models.TextField(blank=True)
    
    wp_post_id = models.IntegerField(null=True, blank=True, help_text="WordPress post ID after publishing")
    wp_post_url = models.URLField(max_length=500, blank=True, help_text="WordPress post permalink")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Article"
        verbose_name_plural = "Articles"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title or 'Untitled'} ({self.get_status_display()})"


class SiteLog(models.Model):
    """Log entries for site events (errors, warnings, info)."""
    LEVEL_CHOICES = [
        ('error', 'Error'),
        ('warning', 'Warning'),
        ('info', 'Info'),
    ]
    SOURCE_CHOICES = [
        ('groq', 'Groq API'),
        ('wordpress', 'WordPress'),
        ('system', 'System'),
    ]

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default='info')
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES, default='system')
    message = models.TextField()
    details = models.JSONField(default=dict, blank=True, help_text="Extra context (article_id, etc)")
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Site Log"
        verbose_name_plural = "Site Logs"
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.level.upper()}] {self.source}: {self.message[:50]}"


class DailyRun(models.Model):
    """Configuration and progress for daily scheduled article generation."""
    STATUS_CHOICES = [
        ('running', 'Running'),
        ('paused', 'Paused'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]

    site = models.ForeignKey(Site, on_delete=models.CASCADE, related_name='daily_runs')
    run_number = models.PositiveIntegerField(default=0, help_text="Per-site run number (auto-incremented)")
    keyword_list = models.ForeignKey('KeywordList', on_delete=models.SET_NULL, null=True, blank=True, 
                                      help_text="Keyword list to use for article generation")
    target_count = models.IntegerField(help_text="Target number of articles to generate")
    completed_count = models.IntegerField(default=0)
    failed_count = models.IntegerField(default=0)
    
    start_time = models.TimeField(default='05:00', help_text="Time to start generating articles (UTC)")
    end_time = models.TimeField(default='01:00', help_text="Time to finish generating articles (UTC)")
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='running')
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Daily Run"
        verbose_name_plural = "Daily Runs"
        ordering = ['-created_at']
        unique_together = ['site', 'run_number']  # Ensure unique per site
        indexes = [
            models.Index(fields=['site', '-created_at'], name='daily_run_site_created_idx'),
        ]

    def save(self, *args, **kwargs):
        # Auto-increment run_number per site on first save
        if not self.pk and self.run_number == 0:
            last_run = DailyRun.objects.filter(site=self.site).order_by('-run_number').first()
            self.run_number = (last_run.run_number + 1) if last_run else 1
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Run #{self.run_number}: {self.completed_count}/{self.target_count} ({self.get_status_display()})"


class SiteAutomation(models.Model):
    """Persistent configuration for automated 24-hour Daily Runs."""
    site = models.OneToOneField(Site, on_delete=models.CASCADE, related_name='automation')
    is_enabled = models.BooleanField(default=False, help_text="Is auto-pilot turned on?")
    
    keyword_list = models.ForeignKey('KeywordList', on_delete=models.SET_NULL, null=True, blank=True,
                                     help_text="Keyword list to use for generation")
    
    next_run_time = models.DateTimeField(null=True, blank=True, help_text="The exact time when the next 24-hour cycle should fire.")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Site Automation"
        verbose_name_plural = "Site Automations"

    def __str__(self):
        status = "ON" if self.is_enabled else "OFF"
        return f"{self.site.domain} Automation ({status})"
