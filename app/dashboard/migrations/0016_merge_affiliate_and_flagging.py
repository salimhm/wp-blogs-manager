from django.db import migrations


class Migration(migrations.Migration):
    """
    Merge migration to resolve conflict between:
      - 0014_apikey_flag_reason_apikey_is_flagged  (server branch: only flag fields)
      - 0015_affiliatejob_slugs_json               (local branch: affiliate models + slugs_json)
    """

    dependencies = [
        ('dashboard', '0014_apikey_flag_reason_apikey_is_flagged'),
        ('dashboard', '0015_affiliatejob_slugs_json'),
    ]

    operations = []
