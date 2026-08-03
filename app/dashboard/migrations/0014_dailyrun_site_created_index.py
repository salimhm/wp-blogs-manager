from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ('dashboard', '0013_remove_siteautomation_end_time_and_more'),
    ]

    operations = [
        AddIndexConcurrently(
            model_name='dailyrun',
            index=models.Index(
                fields=['site', '-created_at'],
                name='daily_run_site_created_idx',
            ),
        ),
    ]
