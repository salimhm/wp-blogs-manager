import datetime
from uuid import uuid4
from celery import shared_task
from django.utils import timezone
from .models import DailyRun, Article, APIKey, ProxySettings, Site, SiteLog, KeywordList
from .utils import (
    GroqRetryLater,
    generate_article_content,
    publish_to_wordpress,
)

@shared_task
def process_daily_run(run_id):
    """
    Manager task: Schedules the day's articles based on the target count and time window.
    Runs once when the daily run is started.
    """
    try:
        run = DailyRun.objects.get(id=run_id)
    except DailyRun.DoesNotExist:
        return f"DailyRun {run_id} not found"

    if run.status != 'running':
        return f"DailyRun {run_id} is {run.status}, stopping."

    # 1. Calculate time window natively linked to when the run was created.
    # This prevents the window from "shifting forward" if the run is resumed on a later date.
    now = timezone.now()
    base_date = run.created_at.astimezone(datetime.timezone.utc).date()
    # Combine the base date with start/end times
    start_dt = datetime.datetime.combine(base_date, run.start_time).replace(tzinfo=datetime.timezone.utc)
    end_dt = datetime.datetime.combine(base_date, run.end_time).replace(tzinfo=datetime.timezone.utc)
    
    # If end time is logically "earlier" in the clock than start time, it means the window crosses midnight.
    if run.end_time < run.start_time:
        end_dt += datetime.timedelta(days=1)
        # Handle case where user manually creates a run in the early morning hours 
        # (e.g., 1AM) while intending to run in the preceding 23:00 to 02:00 window.
        if now.time() <= run.end_time and now.time() >= run.start_time:
            pass # Explicit future scheduling
        elif now.time() < run.start_time and now.time() < run.end_time and base_date == now.date():
            # If created at 1 AM for a 23:00->02:00 window, the user likely meant "right now"
            # so we shift the start_dt to yesterday to place 'now' inside the window.
            start_dt -= datetime.timedelta(days=1)
            end_dt -= datetime.timedelta(days=1)

    # If the absolute end boundary has passed, immediately end the run.
    if now >= end_dt:
        run.status = 'completed'
        run.save(update_fields=['status'])
        _auto_schedule_next_run(run)
        return "Time window passed"

    # Important Resume Logic:
    # If we are partway into the window (e.g. paused & resumed, or restarting a crashed container),
    # we must squeeze the remaining needed tasks into the *remaining* time window smoothly.
    # Therefore, we override start_dt to 'now'.
    if now > start_dt:
        start_dt = now

    # 2. Get keywords from the selected list
    # If a specific keyword list was selected, use only that one
    if run.keyword_list:
        keyword_lists = [run.keyword_list]
    else:
        # Fallback to all lists if none selected
        keyword_lists = KeywordList.objects.all()
    
    # Determine how many we need
    needed = run.target_count - run.completed_count
    if needed <= 0:
        run.status = 'completed'
        run.save()
        _auto_schedule_next_run(run)
        return "Target reached"

    # Calculate interval
    total_seconds = (end_dt - start_dt).total_seconds()
    interval_seconds = total_seconds / needed if total_seconds > 0 else 0
    
    # Cap interval (e.g., don't go faster than 1 every 30s to be safe)
    if interval_seconds < 30:
        interval_seconds = 30

    print(f"Scheduling {needed} articles over {total_seconds/3600:.1f} hours. Interval: {interval_seconds:.1f}s")
    
    # Schedule tasks
    scheduled_count = 0
    
    # Re-schedule only checkpoints owned by this run. Orphaned legacy rows must
    # never be adopted: doing so can resurrect permanently cancelled work when
    # Celery Beat starts a later automation cycle.
    pending_articles = (
        Article.objects
        .filter(site=run.site, status='pending', daily_run=run)
        .order_by('id')
    )
    
    for p_article in pending_articles:
        if scheduled_count >= needed:
            break
        
        eta = start_dt + datetime.timedelta(seconds=scheduled_count * interval_seconds)
        task_id = str(uuid4())
        p_article.task_id = task_id
        p_article.daily_run = run
        p_article.save(update_fields=['daily_run', 'task_id'])
        generate_single_article.apply_async(
            args=[p_article.id, run.id],
            eta=eta,
            task_id=task_id,
        )
        
        scheduled_count += 1
        
    # 2. Iterate through keyword lists and pick sequential indexes not yet in Article table
    for k_list in keyword_lists:
        if scheduled_count >= needed:
            break
            
        # Check existing articles for this list to find next index
        existing_indices = Article.objects.filter(
            site=run.site, 
            keyword_list=k_list
        ).values_list('keyword_index', flat=True)
        
        existing_set = set(existing_indices)
        
        # Iterate through h2 sets in json
        if not k_list.keywords_json:
            continue
            
        for idx, h2_set in enumerate(k_list.keywords_json):
            if idx in existing_set:
                continue
                
            if scheduled_count >= needed:
                break
            
            # Create a PENDING article record to "claim" this spot
            article = Article.objects.create(
                site=run.site,
                keyword_list=k_list,
                keyword_index=idx,
                status='pending',
                daily_run=run,
                title=f"Pending Generation {idx}"
            )
            
            # Schedule execution
            eta = start_dt + datetime.timedelta(seconds=scheduled_count * interval_seconds)

            task_id = str(uuid4())
            article.task_id = task_id
            article.save(update_fields=['task_id'])
            generate_single_article.apply_async(
                args=[article.id, run.id],
                eta=eta,
                task_id=task_id,
            )
            
            scheduled_count += 1
            existing_set.add(idx)

    return f"Scheduled {scheduled_count} articles"


@shared_task(bind=True, max_retries=None)
def generate_single_article(self, article_id, run_id=None):
    """
    Worker task: Generates and publishes a single article.
    """
    article = None
    run = None
    try:
        article = Article.objects.select_related('daily_run').get(id=article_id)

        # Check for idempotency: if it isn't pending, it was already handled or is running
        if article.status != 'pending':
            print(f"[SKIP] Article {article_id} is '{article.status}'. Skipping duplicate execution.")
            return f"Already {article.status}"

        # A pause checkpoints pending work by replacing task_id with a sentinel,
        # and a resume assigns a fresh ID before publishing the replacement task.
        # Any older ETA message is therefore harmless even if it wakes later.
        request_task_id = str(self.request.id or '')
        if article.task_id and request_task_id and article.task_id != request_task_id:
            print(f"[SKIP] Stale task {request_task_id} for article {article_id}.")
            return "Stale task"

        # Support legacy tasks that were queued before task IDs were persisted
        # ahead of publication.
        if request_task_id and article.task_id != request_task_id:
            article.task_id = request_task_id
            article.save(update_fields=['task_id'])
            
        site = article.site
        # The article's durable relationship is authoritative even for legacy
        # Celery messages that were published without run_id.
        run = article.daily_run
        if run_id and (run is None or run.id != run_id):
            print(f"[SKIP] Article {article_id} no longer belongs to run {run_id}.")
            return "Run ownership changed"
        
        # Check if run is cancelled or paused
        if run:
            # Cancelled = skip immediately
            if run.status == 'cancelled':
                print(f"[SKIP] Run cancelled, skipping article {article_id}")
                return "Run cancelled"
            
            # Paused = exit cleanly so workers are not locked. 
            # `process_daily_run` will pick this pending article back up when resumed.
            if run.status == 'paused':
                print(f"[SKIP] Run paused. Leaving article {article_id} as pending. Exiting worker cleanly.")
                # We do NOT change article.status here. It remains 'pending'.
                return "Run paused"
            
            # Explicitly link run if not already
            if not article.daily_run:
                article.daily_run = run
                article.save(update_fields=['daily_run'])

        article.status = 'generating'
        article.error_message = ''
        article.save(update_fields=['status', 'error_message'])
        
        # 1. Get ALL active API keys for this site (for cross-provider fallback)
        api_key_objs = APIKey.objects.filter(site=site, is_active=True, provider='groq')
        if not api_key_objs.exists():
            raise Exception("No active API keys found for site")
        
        # Convert to list of dicts for the fallback function
        api_keys = []
        for k in api_key_objs:
            masked_key = f"{k.api_key[:4]}...{k.api_key[-4:]}" if len(k.api_key) > 8 else "***"
            print(f"Loaded API key for {k.provider}: {masked_key}")
            # api_keys list passed to utils needs simple dicts
            api_keys.append({
                'id': k.id,
                'provider': k.provider,
                'api_key': k.api_key,
                'model_name': k.model_name,
                'is_active': k.is_active,
            })
            
        # Get proxy
        proxy_obj = ProxySettings.objects.filter(site=site, is_active=True).first()
        proxy_dict = None
        if proxy_obj:
            proxy_url = proxy_obj.get_proxy_url()
            proxy_dict = {'http': proxy_url, 'https': proxy_url}

        # 2. Get keywords (H2s) - extract from dict structure
        h2_data = article.keyword_list.keywords_json[article.keyword_index]
        print(f"[DEBUG] h2_data type: {type(h2_data)}, value preview: {str(h2_data)[:100]}")
        
        # Handle different formats
        if isinstance(h2_data, dict) and 'h2s' in h2_data:
            h2s = h2_data['h2s']
        elif isinstance(h2_data, list):
            h2s = h2_data
        elif isinstance(h2_data, str):
            # Single keyword string - wrap in list
            h2s = [h2_data]
        else:
            h2s = []
        
        if not h2s:
            raise Exception(f"No H2s found in keyword data. Type: {type(h2_data)}")
        
        # 3. Generate Content with cross-provider fallback
        content_data = generate_article_content(h2s, api_keys, proxy_dict)
        
        # The API call above can outlive a cancellation request. Re-check the
        # durable stop signal before saving or publishing its result.
        if run:
            current_run_status = (
                DailyRun.objects
                .filter(id=run.id)
                .values_list('status', flat=True)
                .first()
            )
            if current_run_status != 'running':
                print(f"[SKIP] Run {current_run_status}; discarding generated result for article {article_id}.")
                return f"Run {current_run_status}"

        # 4. Update Article Record
        article.title = content_data['title']
        article.introduction = content_data['introduction']
        article.body = str(content_data['body_sections'])  # Store raw sections for debugging if needed
        article.faq_json = content_data['faq']
        article.content_html = content_data['html']
        
        # Save Logging Info
        if 'meta' in content_data:
            article.generation_info = content_data['meta']
            
        article.status = 'ready'
        article.save()
        
        # Log success with provider details
        try:
            # SiteLog is already imported at the top, no need to re-import
            provider_info = "Unknown"
            if 'meta' in content_data and 'provider_usage' in content_data['meta']:
                # Extract main provider from first step (usually title)
                stats = content_data['meta']['provider_usage']
                if stats:
                    first_stat = stats[0]
                    provider_info = f"{first_stat.get('provider', 'Unknown')} ({first_stat.get('model', 'auto')})"
            
            SiteLog.objects.create(
                site=site,
                level='info',
                source='generation',
                message=f"Generated: {article.title[:50]}... via {provider_info}",
                details={
                    'article_id': article.id,
                    'title': article.title,
                    'meta': content_data.get('meta', {})
                }
            )
        except Exception as log_error:
            print(f"Failed to create success log: {log_error}")
        
        # Cancellation can happen after content was saved but before the
        # WordPress request. Keep the completed draft, but never publish it.
        if run:
            current_run_status = (
                DailyRun.objects
                .filter(id=run.id)
                .values_list('status', flat=True)
                .first()
            )
            if current_run_status != 'running':
                return f"Run {current_run_status}"

        # 5. Publish to WordPress
        if site.is_verified:
            # We need to decrypt password? Assuming verify_wp_credentials logic handles it.
            # But publish_to_wordpress needs raw password. 
            # In a real app we'd use encryption. Here assume stored plain or check logic.
            # verify_wp_credentials uses the stored password directly.
            
            success, message, wp_post_id, post_url = publish_to_wordpress(site, article)
            
            if wp_post_id:
                article.wp_post_id = wp_post_id
                article.wp_post_url = post_url
                article.status = 'published'
                article.published_at = timezone.now()
                article.save()
                
                 # Update Run Stats atomically to prevent concurrent worker race conditions
                if run:
                    from django.db.models import F
                    # Fetch fresh to avoid overwriting state
                    # We must use F() expression because 20 workers could all read "15" at once 
                    # and all save "16", losing 19 counts.
                    DailyRun.objects.filter(id=run.id).update(completed_count=F('completed_count') + 1)
                    
                    # Refresh run instance from DB to check if complete
                    run.refresh_from_db()
                    
                    # Check if run is fully completed
                    if run.completed_count >= run.target_count:
                        run.status = 'completed'
                        run.save()
                        _auto_schedule_next_run(run)
                    
                # Log success
                SiteLog.objects.create(
                    site=site,
                    level='info',
                    source='system',
                    message=f"Published: {article.title}",
                    details={'post_id': wp_post_id}
                )
            else:
                print(f"[WP PUBLISH FAILED] Article {article_id}: {message}")
                raise Exception(f"WordPress publish failed: {message}")

    except GroqRetryLater as e:
        if article is None:
            return "Article no longer exists"

        if run:
            current_run_status = (
                DailyRun.objects
                .filter(id=run.id)
                .values_list('status', flat=True)
                .first()
            )
            if current_run_status != 'running':
                return f"Run {current_run_status}"

        Article.objects.filter(id=article_id, status='generating').update(
            status='pending',
            error_message=f'Groq cooling down: retrying in {e.retry_after}s',
        )
        print(
            f"[GROQ COOLDOWN] Article {article_id} rescheduled in "
            f"{e.retry_after}s: {e.reason}"
        )
        raise self.retry(exc=e, countdown=e.retry_after, max_retries=None)

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()

        if article is None:
            print(f"[SKIP] Article {article_id} no longer exists: {e}")
            return "Article no longer exists"

        # A termination requested by Pause must not race the checkpoint update
        # and turn resumable work into a failure.
        if run:
            current_run_status = (
                DailyRun.objects
                .filter(id=run.id)
                .values_list('status', flat=True)
                .first()
            )
            if current_run_status == 'cancelled':
                print(f"[CANCEL] Article {article_id} stopped without recreating its checkpoint.")
                return "Run cancelled"
            if current_run_status == 'paused':
                Article.objects.filter(id=article_id).update(status='pending', error_message='')
                print(f"[PAUSE] Article {article_id} checkpointed after task termination.")
                return "Run paused"

        print(f"Error generating article {article_id}: {e}\n{error_trace}")
        article.status = 'failed'
        article.error_message = str(e)
        article.save()
        
        # Update Run Stats atomically
        if run:
            from django.db.models import F
            DailyRun.objects.filter(id=run.id).update(failed_count=F('failed_count') + 1)
            
        SiteLog.objects.create(
            site=site,
            level='error',
            source='system',
            message=f"Failed: {article.title[:50]}...",
            details={'article_id': article_id, 'error': str(e)}
        )


@shared_task
def create_pending_articles_task(site_id, keyword_list_id, selected_indices=None):
    """
    Background task to create pending articles from a keyword list.
    This prevents timeout when creating many articles.
    """
    from .models import Site, KeywordList, Article, SiteLog
    
    try:
        site = Site.objects.get(id=site_id)
        kw_list = KeywordList.objects.get(id=keyword_list_id)
    except (Site.DoesNotExist, KeywordList.DoesNotExist) as e:
        return f"Error: {str(e)}"
    
    created = 0
    skipped = 0
    
    for index, item in enumerate(kw_list.keywords_json):
        # If specific indices selected, only create those
        if selected_indices and str(index) not in selected_indices:
            continue
        
        # Check if article already exists for this index
        exists = Article.objects.filter(
            site=site,
            keyword_list=kw_list,
            keyword_index=index
        ).exists()
        
        if not exists:
            Article.objects.create(
                site=site,
                keyword_list=kw_list,
                keyword_index=index,
                status='pending'
            )
            created += 1
        else:
            skipped += 1
    
    # Log completion
    SiteLog.objects.create(
        site=site,
        level='info',
        source='system',
        message=f"Created {created} pending articles from '{kw_list.name}' ({skipped} already existed)"
    )
    
    return f"Created {created} pending articles, skipped {skipped} existing"


@shared_task
def auto_resume_stalled_runs():
    """
    Heartbeat task to recover Daily Runs that were paused/killed by a Redis disconnect crash.
    Runs every 5 minutes. If a run hasn't produced a completed (ready/published) article in
    30+ minutes, it's considered stalled and gets re-triggered.

    Key fix: after a Redis crash, articles can be stuck in 'generating' with a recent updated_at,
    making the old 'any article activity' check think the run is healthy. We now explicitly check
    for COMPLETED output (ready/published), not just any article update.
    """
    from .models import DailyRun, Article
    from django.utils import timezone
    import datetime

    stalled_threshold = timezone.now() - datetime.timedelta(minutes=30)
    running_runs = DailyRun.objects.filter(status='running')

    recovered_count = 0
    for run in running_runs:
        # If target already reached, close it out
        needed = run.target_count - run.completed_count
        if needed <= 0:
            run.status = 'completed'
            run.save(update_fields=['status'])
            continue

        # Check the last time an article for this run was COMPLETED (ready or published).
        # We intentionally ignore 'generating' articles — they may be zombies from a crashed worker.
        last_completed = (
            Article.objects
            .filter(daily_run=run, status__in=['ready', 'published'])
            .order_by('-updated_at')
            .first()
        )

        # Determine if stalled:
        #   - Run started > 30 mins ago, AND
        #   - No completed articles at all, OR last completed was > 30 mins ago
        run_age_ok = run.started_at < stalled_threshold
        last_ok = last_completed is None or last_completed.updated_at < stalled_threshold

        if run_age_ok and last_ok:
            print(f"[AUTO-RECOVERY] Run {run.id} for {run.site.domain} stalled (no output in 30+ mins). Resuming...")

            # Reset any stuck 'generating' articles back to 'pending'
            # so process_daily_run can pick them up and reschedule them.
            stuck_count = Article.objects.filter(daily_run=run, status='generating').update(status='pending')
            if stuck_count:
                print(f"[AUTO-RECOVERY] Reset {stuck_count} stuck 'generating' articles to 'pending'.")

            from .tasks import process_daily_run
            process_daily_run.delay(run.id)
            recovered_count += 1

    return f"Recovered {recovered_count} stalled runs"


def _auto_schedule_next_run(completed_run):
    """
    Deprecated. We now use SiteAutomation + check_site_automations periodic task.
    Keeping function footprint empty to prevent import or zombie task errors 
    if any older tasks still attempt to call it upon completion.
    """
    pass

@shared_task
def schedule_tomorrow_run(*args, **kwargs):
    """
    Deprecated in favor of SiteAutomation.
    """
    return "Deprecated"

@shared_task
def check_site_automations():
    """
    Periodic task (e.g. every 10 mins).
    Evaluates all active SiteAutomations. If 'next_run_time' has passed, 
    it recalculates the daily quota natively and launches a 20-hour run, 
    pushing the next trigger out by 24 hours.
    """
    from .models import SiteAutomation, DailyRun
    from django.utils import timezone
    import datetime

    now = timezone.now()
    automations = SiteAutomation.objects.filter(is_enabled=True)
    triggered_count = 0
    
    for auto in automations:
        # If next_run_time is set and in the future, we just wait.
        if auto.next_run_time and now < auto.next_run_time:
            continue

        # Never overlap or revive a site's current run. A paused run remains a
        # deliberate stop signal until the user resumes or permanently cancels it.
        if DailyRun.objects.filter(
            site=auto.site,
            status__in=['running', 'paused'],
        ).exists():
            continue
            
        print(f"[Auto-Pilot 24H] Triggering cycle for {auto.site.domain}.")
        
        # 1. Calculate a safe target from each key's configured model and
        # free-tier daily token budget.
        active_keys = list(
            auto.site.api_keys.filter(is_active=True, provider='groq')
        )
        if not active_keys:
            print(f"[Auto-Pilot 24H] {auto.site.domain} has 0 active API keys. Skipping run.")
            # We defer checking again for a short duration (e.g. 1 hour) so we don't spam.
            auto.next_run_time = now + datetime.timedelta(hours=1)
            auto.save(update_fields=['next_run_time'])
            continue
            
        from .groq_quota import daily_article_capacity
        target_count = daily_article_capacity(active_keys)
        print(
            f"[Auto-Pilot 24H] Quota-aware target: {target_count} articles."
        )
        
        # 2. DailyRun boundaries are now to now+20h
        start_time_str = now.strftime('%H:%M')
        
        # End time is 20 hours from now
        end_dt_20h = now + datetime.timedelta(hours=20)
        end_time_str = end_dt_20h.strftime('%H:%M')
        
        # Create the Daily Run log
        run = DailyRun.objects.create(
            site=auto.site,
            keyword_list=auto.keyword_list,
            target_count=target_count,
            start_time=start_time_str,
            end_time=end_time_str,
            status='running'
        )
        
        # 3. Push the automation's next run out by exactly 24 hours
        # If it was significantly overdue, we anchor to NOW to prevent immediate cascading runs.
        auto.next_run_time = now + datetime.timedelta(hours=24)
        auto.save(update_fields=['next_run_time'])
        
        # Trigger the orchestrator immediately
        from .tasks import process_daily_run
        process_daily_run.delay(run.id)
        triggered_count += 1
            
    return f"Triggered {triggered_count} automations"



def _normalize_cloudpanel_database_identifiers(job):
    """Upgrade identifiers created before CloudPanel-compatible validation."""
    import re

    database_name = re.sub(r'[^a-z0-9-]+', '-', job.database_name.lower()).strip('-')
    database_user = re.sub(r'[^a-z0-9]+', '', job.database_user.lower())
    database_name = database_name[:32]
    database_user = database_user[:32]
    if not database_name or not database_name[0].isalpha():
        database_name = f'wp-{database_name}'[:32]
    if not database_user or not database_user[0].isalpha():
        database_user = f'wp{database_user}'[:32]
    changed = []
    if job.database_name != database_name:
        job.database_name = database_name
        changed.append('database_name')
    if job.database_user != database_user:
        job.database_user = database_user
        changed.append('database_user')
    if changed:
        job.save(update_fields=[*changed, 'updated_at'])


def _set_provision_step(job, status, step, progress, error=''):
    job.status = status
    job.current_step = step
    job.progress = progress
    job.last_error = error
    job.save(update_fields=[
        'status',
        'current_step',
        'progress',
        'last_error',
        'updated_at',
    ])


@shared_task(bind=True, max_retries=3)
def provision_wordpress_site(self, job_id):
    """Provision one Cloudflare zone through the restricted CloudPanel wrapper."""
    from django.conf import settings
    from django.utils import timezone

    from .cloudpanel import CloudPanelClient, CloudPanelError
    from .models import CloudflareSettings, WordPressProvisionJob
    from .secret_store import decrypt_secret
    from .utils import (
        CloudflareAPIError,
        set_cloudflare_record_proxied,
        upsert_cloudflare_dns_record,
        verify_wp_credentials,
    )

    try:
        job = WordPressProvisionJob.objects.select_related('site').get(id=job_id)
    except WordPressProvisionJob.DoesNotExist:
        return f'Provisioning job {job_id} no longer exists'

    if job.status == 'ready':
        return f'{job.site.domain} is already ready'

    cloudflare = CloudflareSettings.objects.filter(is_active=True).first()
    if not cloudflare or not cloudflare.api_token:
        _set_provision_step(job, 'failed', 'Cloudflare is not configured', 0, 'Missing Cloudflare API token')
        return 'Missing Cloudflare API token'
    if not settings.CLOUDPANEL_ORIGIN_IP:
        _set_provision_step(job, 'failed', 'CloudPanel origin IP is not configured', 0, 'Set CLOUDPANEL_ORIGIN_IP')
        return 'Missing CLOUDPANEL_ORIGIN_IP'

    job.attempt_count += 1
    job.save(update_fields=['attempt_count', 'updated_at'])
    domain = job.site.domain

    try:
        _set_provision_step(job, 'dns', 'Pointing the domain to CloudPanel', 15)
        apex_id = upsert_cloudflare_dns_record(
            cloudflare.api_token,
            job.cloudflare_zone_id,
            domain,
            'A',
            settings.CLOUDPANEL_ORIGIN_IP,
            proxied=False,
        )
        www_id = upsert_cloudflare_dns_record(
            cloudflare.api_token,
            job.cloudflare_zone_id,
            f'www.{domain}',
            'CNAME',
            domain,
            proxied=False,
        )
        job.cloudflare_apex_record_id = apex_id
        job.cloudflare_www_record_id = www_id
        job.save(update_fields=[
            'cloudflare_apex_record_id',
            'cloudflare_www_record_id',
            'updated_at',
        ])

        _set_provision_step(job, 'cloudpanel', 'CloudPanel is installing WordPress', 45)
        _normalize_cloudpanel_database_identifiers(job)
        response = CloudPanelClient().provision({
            'action': 'provision',
            'domain': domain,
            'site_title': job.site_title,
            'site_user': job.site_user,
            'site_user_password': decrypt_secret(job.encrypted_site_user_password),
            'database_name': job.database_name,
            'database_user': job.database_user,
            'database_password': decrypt_secret(job.encrypted_database_password),
            'admin_user': job.site.wp_username,
            'admin_password': decrypt_secret(job.encrypted_admin_password),
            'admin_email': job.site.wp_admin_email,
            'php_version': settings.CLOUDPANEL_PHP_VERSION,
            'vhost_template': settings.CLOUDPANEL_VHOST_TEMPLATE,
            'document_root': settings.CLOUDPANEL_DOCUMENT_ROOT_TEMPLATE.format(
                site_user=job.site_user,
                domain=domain,
            ),
        })
        application_password = str(response.get('application_password') or '').strip()
        if not application_password:
            raise CloudPanelError('CloudPanel did not return a WordPress application password')

        _set_provision_step(job, 'proxy', 'Enabling the Cloudflare proxy', 82)
        set_cloudflare_record_proxied(
            cloudflare.api_token, job.cloudflare_zone_id, apex_id, True
        )
        set_cloudflare_record_proxied(
            cloudflare.api_token, job.cloudflare_zone_id, www_id, True
        )

        _set_provision_step(job, 'verifying', 'Checking WordPress authentication', 94)
        verified, message = verify_wp_credentials(
            domain,
            job.site.wp_username,
            application_password,
        )
        if not verified:
            raise CloudPanelError(f'WordPress verification is not ready: {message}')

        job.site.wp_app_password = application_password
        job.site.is_verified = True
        job.site.is_fresh_installation = True
        job.site.cloudflare_zone_id = job.cloudflare_zone_id
        job.site.server_ip = settings.CLOUDPANEL_ORIGIN_IP
        job.site.save(update_fields=[
            'wp_app_password', 'is_verified', 'is_fresh_installation',
            'cloudflare_zone_id', 'server_ip', 'updated_at',
        ])
        job.completed_at = timezone.now()
        job.status = 'ready'
        job.current_step = 'WordPress is ready'
        job.progress = 100
        job.last_error = ''
        job.save(update_fields=[
            'completed_at', 'status', 'current_step', 'progress',
            'last_error', 'updated_at',
        ])
        return f'{domain} is ready'

    except (CloudPanelError, CloudflareAPIError, ValueError) as exc:
        message = str(exc)[:1000]
        if self.request.retries < self.max_retries:
            _set_provision_step(
                job,
                job.status,
                f'Retrying in 60 seconds: {message[:120]}',
                job.progress,
                message,
            )
            raise self.retry(exc=exc, countdown=60)
        _set_provision_step(job, 'failed', 'Provisioning failed', job.progress, message)
        return f'Provisioning failed: {message}'
    except Exception as exc:
        message = f'Unexpected provisioning error: {exc}'[:1000]
        _set_provision_step(job, 'failed', 'Provisioning failed', job.progress, message)
        raise
