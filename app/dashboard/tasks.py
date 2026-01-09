import datetime
from celery import shared_task
from django.utils import timezone
from .models import DailyRun, Article, APIKey, ProxySettings, Site, SiteLog, KeywordList
from .utils import generate_article_content, publish_to_wordpress, ensure_complete

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

    # 1. Calculate time window
    now = timezone.now()
    today = now.date()
    
    # Combine today's date with start/end times
    start_dt = datetime.datetime.combine(today, run.start_time).replace(tzinfo=datetime.timezone.utc)
    end_dt = datetime.datetime.combine(today, run.end_time).replace(tzinfo=datetime.timezone.utc)
    
    # If end time is before start time, assume it's the next day (e.g. 23:00 to 02:00)
    if end_dt < start_dt:
        end_dt += datetime.timedelta(days=1)
        
    # If we're already past the end time, schedule for "now" or stop? 
    # Let's assume we fit them in the remaining time or just spread them out from "now"
    current_time = timezone.now()
    if current_time > start_dt:
        start_dt = current_time
        
    if current_time >= end_dt:
        run.status = 'completed'
        run.save()
        return "Time window passed"

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
    
    # Iterate through keyword lists and pick sequential indexes not yet in Article table
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
                title=f"Pending Generation {idx}"
            )
            
            # Schedule execution
            eta = start_dt + datetime.timedelta(seconds=scheduled_count * interval_seconds)
            
            generate_single_article.apply_async(
                args=[article.id, run.id], 
                eta=eta
            )
            
            scheduled_count += 1
            existing_set.add(idx)

    return f"Scheduled {scheduled_count} articles"


@shared_task(bind=True)
def generate_single_article(self, article_id, run_id=None):
    """
    Worker task: Generates and publishes a single article.
    """
    try:
        article = Article.objects.get(id=article_id)
        
        # Save Task ID for Force Kill
        if self.request.id:
            article.task_id = self.request.id
            article.save(update_fields=['task_id'])
            
        site = article.site
        run = DailyRun.objects.get(id=run_id) if run_id else None
        
        # Check if run is cancelled or paused
        if run:
            # Cancelled = skip immediately
            if run.status == 'cancelled':
                print(f"[SKIP] Run cancelled, skipping article {article_id}")
                return "Run cancelled"
            
            # Paused = wait for resume (check every 30s, up to 10 min)
            if run.status == 'paused':
                import time
                max_wait = 600  # 10 minutes
                waited = 0
                while waited < max_wait:
                    print(f"[WAIT] Run paused, article {article_id} waiting for resume...")
                    time.sleep(30)
                    waited += 30
                    run.refresh_from_db()
                    if run.status == 'running':
                        print(f"[RESUME] Run resumed, continuing article {article_id}")
                        break
                    elif run.status == 'cancelled':
                        print(f"[SKIP] Run cancelled while waiting, skipping article {article_id}")
                        return "Run cancelled"
                else:
                    # Still paused after max wait
                    print(f"[SKIP] Run still paused after {max_wait}s, skipping article {article_id}")
                    return "Run paused too long"
            
            # Explicitly link run if not already
            if not article.daily_run:
                article.daily_run = run
                article.save(update_fields=['daily_run'])

        article.status = 'generating'
        article.save()
        
        # 1. Get ALL active API keys for this site (for cross-provider fallback)
        api_key_objs = APIKey.objects.filter(site=site, is_active=True)
        if not api_key_objs.exists():
            raise Exception("No active API keys found for site")
        
        # Convert to list of dicts for the fallback function
        api_keys = []
        for k in api_key_objs:
            masked_key = f"{k.api_key[:4]}...{k.api_key[-4:]}" if len(k.api_key) > 8 else "***"
            print(f"Loaded API key for {k.provider}: {masked_key}")
            # api_keys list passed to utils needs simple dicts
            api_keys.append({'provider': k.provider, 'api_key': k.api_key, 'is_active': k.is_active})
            
        # Get proxy
        proxy_obj = ProxySettings.objects.filter(site=site, is_active=True).first()
        proxy_dict = None
        if proxy_obj:
            proxy_url = proxy_obj.get_proxy_url()
            proxy_dict = {'http': proxy_url, 'https': proxy_url}

        # 2. Get keywords (H2s) - extract from dict structure
        h2_data = article.keyword_list.keywords_json[article.keyword_index]
        h2s = h2_data.get('h2s', []) if isinstance(h2_data, dict) else h2_data
        
        if not h2s:
            raise Exception("No H2s found in keyword data")
        
        # 3. Generate Content with cross-provider fallback
        content_data = generate_article_content(h2s, api_keys, proxy_dict)
        
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
                
                # Update Run Stats
                if run:
                    run.completed_count += 1
                    run.save()
                    
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

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error generating article {article_id}: {e}\n{error_trace}")
        article.status = 'failed'
        article.error_message = str(e)
        article.save()
        
        # Update Run Stats
        if run:
            run.failed_count += 1
            run.save()
            
        SiteLog.objects.create(
            site=site,
            level='error',
            source='system',
            message=f"Failed: {article.title[:50]}...",
            details={'article_id': article_id, 'error': str(e)}
        )
