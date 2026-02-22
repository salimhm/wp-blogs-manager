import os
import sys
import django

sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')
django.setup()

from dashboard.models import Article, DailyRun
from django.utils import timezone

stuck_runs = DailyRun.objects.filter(status='running')
for run in stuck_runs:
    print(f"\n[RUN {run.id}] Site: {run.site.domain}")
    pending = Article.objects.filter(daily_run=run, status__in=['pending', 'generating']).count()
    ready = Article.objects.filter(daily_run=run, status='ready').count()
    failed = Article.objects.filter(daily_run=run, status='failed').count()
    published = Article.objects.filter(daily_run=run, status='published').count()
    print(f"  Pending/Gen: {pending}")
    print(f"  Ready: {ready}")
    print(f"  Failed: {failed}")
    print(f"  Published: {published}")
    
    # Detailed pending
    articles = Article.objects.filter(daily_run=run, status__in=['pending', 'generating']).order_by('created_at')[:5]
    for a in articles:
        print(f"  - Article {a.id}: Status {a.status} (Task ID: {a.task_id})")

print("\nCelery Task States")
from django_celery_results.models import TaskResult
recent = TaskResult.objects.order_by('-date_done')[:10]
for t in recent:
    print(f"{t.task_id}: {t.status} - {t.result}")
