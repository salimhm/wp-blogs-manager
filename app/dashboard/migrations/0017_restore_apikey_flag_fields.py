from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0016_wordpressprovisionjob'),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                ALTER TABLE dashboard_apikey
                    ADD COLUMN IF NOT EXISTS is_flagged BOOLEAN NOT NULL DEFAULT FALSE;
                ALTER TABLE dashboard_apikey
                    ADD COLUMN IF NOT EXISTS flag_reason VARCHAR(255) NOT NULL DEFAULT '';
                UPDATE dashboard_apikey SET is_flagged = FALSE WHERE is_flagged IS NULL;
                UPDATE dashboard_apikey SET flag_reason = '' WHERE flag_reason IS NULL;
                ALTER TABLE dashboard_apikey ALTER COLUMN is_flagged SET DEFAULT FALSE;
                ALTER TABLE dashboard_apikey ALTER COLUMN is_flagged SET NOT NULL;
                ALTER TABLE dashboard_apikey ALTER COLUMN flag_reason SET DEFAULT '';
                ALTER TABLE dashboard_apikey ALTER COLUMN flag_reason SET NOT NULL;
            """,
            reverse_sql=migrations.RunSQL.noop,
            state_operations=[
                migrations.AddField(
                    model_name='apikey',
                    name='is_flagged',
                    field=models.BooleanField(
                        default=False,
                        help_text='Key permanently banned/restricted by provider',
                    ),
                ),
                migrations.AddField(
                    model_name='apikey',
                    name='flag_reason',
                    field=models.CharField(
                        blank=True,
                        default='',
                        help_text='Reason the key was flagged',
                        max_length=255,
                    ),
                ),
            ],
        ),
    ]
