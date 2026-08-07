from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0015_groqusage'),
    ]

    operations = [
        migrations.CreateModel(
            name='WordPressProvisionJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cloudflare_zone_id', models.CharField(max_length=64, unique=True)),
                ('status', models.CharField(choices=[('queued', 'Queued'), ('dns', 'Configuring DNS'), ('cloudpanel', 'Installing on CloudPanel'), ('proxy', 'Enabling Cloudflare'), ('verifying', 'Verifying WordPress'), ('ready', 'Ready'), ('failed', 'Failed')], default='queued', max_length=20)),
                ('current_step', models.CharField(default='Waiting to start', max_length=160)),
                ('progress', models.PositiveSmallIntegerField(default=0)),
                ('last_error', models.TextField(blank=True)),
                ('celery_task_id', models.CharField(blank=True, max_length=100)),
                ('cloudflare_apex_record_id', models.CharField(blank=True, max_length=64)),
                ('cloudflare_www_record_id', models.CharField(blank=True, max_length=64)),
                ('site_title', models.CharField(max_length=255)),
                ('site_user', models.CharField(max_length=32)),
                ('database_name', models.CharField(max_length=64)),
                ('database_user', models.CharField(max_length=64)),
                ('encrypted_site_user_password', models.TextField()),
                ('encrypted_database_password', models.TextField()),
                ('encrypted_admin_password', models.TextField()),
                ('attempt_count', models.PositiveSmallIntegerField(default=0)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('site', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='provision_job', to='dashboard.site')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
