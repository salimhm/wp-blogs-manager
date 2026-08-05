from django.db import migrations, models
import django.db.models.deletion


def migrate_deprecated_groq_models(apps, schema_editor):
    APIKey = apps.get_model('dashboard', 'APIKey')
    APIKey.objects.filter(model_name='llama-3.1-8b-instant').update(
        model_name='openai/gpt-oss-20b'
    )
    APIKey.objects.filter(model_name='llama-3.3-70b-versatile').update(
        model_name='openai/gpt-oss-120b'
    )


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0014_dailyrun_site_created_index'),
    ]

    operations = [
        migrations.CreateModel(
            name='GroqUsage',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                ('model_name', models.CharField(max_length=100)),
                ('usage_date', models.DateField()),
                ('request_count', models.PositiveIntegerField(default=0)),
                ('prompt_tokens', models.PositiveBigIntegerField(default=0)),
                ('completion_tokens', models.PositiveBigIntegerField(default=0)),
                ('total_tokens', models.PositiveBigIntegerField(default=0)),
                ('rate_limit_count', models.PositiveIntegerField(default=0)),
                ('payload_too_large_count', models.PositiveIntegerField(default=0)),
                ('error_count', models.PositiveIntegerField(default=0)),
                ('last_status_code', models.PositiveIntegerField(default=0)),
                ('last_error', models.CharField(blank=True, max_length=500)),
                ('tpm_limit', models.PositiveIntegerField(default=0)),
                ('tpd_limit', models.PositiveIntegerField(default=0)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'api_key',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='groq_usage',
                        to='dashboard.apikey',
                    ),
                ),
            ],
            options={
                'ordering': ['-usage_date', 'api_key_id', 'model_name'],
                'indexes': [
                    models.Index(
                        fields=['usage_date', 'api_key'],
                        name='groq_usage_day_key_idx',
                    ),
                ],
                'constraints': [
                    models.UniqueConstraint(
                        fields=('api_key', 'model_name', 'usage_date'),
                        name='unique_groq_usage_key_model_day',
                    ),
                ],
            },
        ),
        migrations.RunPython(
            migrate_deprecated_groq_models,
            migrations.RunPython.noop,
        ),
    ]
