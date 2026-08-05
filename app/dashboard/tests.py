import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from .groq_quota import (
    GroqRetryLater,
    completion_budget,
    daily_article_capacity,
    models_for_key,
    parse_duration,
    record_attempt,
)
from .models import (
    APIKey,
    Article,
    DailyRun,
    GroqUsage,
    KeywordList,
    Site,
    SiteAutomation,
)
from .tasks import check_site_automations, process_daily_run
from .views import _cancel_run_ids
from .utils import call_groq_with_fallback


class GroqQuotaMathTests(SimpleTestCase):
    def test_completion_budget_stays_below_free_tier_tpm(self):
        prompt = 'x' * 3700  # approximately 1,000 estimated tokens
        self.assertEqual(
            completion_budget(prompt, 4400, 'openai/gpt-oss-20b'),
            4400,
        )
        self.assertLessEqual(
            completion_budget(prompt, 4400, 'llama-3.1-8b-instant'),
            4400,
        )

    def test_duration_parser_handles_groq_header_format(self):
        self.assertEqual(parse_duration('2h9m45.5s'), 7785.5)
        self.assertEqual(parse_duration('17.25s'), 17.25)

    def test_deprecated_model_pins_are_mapped_to_current_models(self):
        self.assertEqual(
            models_for_key({'model_name': 'llama-3.1-8b-instant'}),
            ('openai/gpt-oss-20b',),
        )

    def test_default_two_model_capacity_is_quota_derived(self):
        keys = [
            SimpleNamespace(
                is_active=True,
                provider='groq',
                model_name='',
                api_key=f'key-{index}',
            )
            for index in range(8)
        ]
        self.assertEqual(daily_article_capacity(keys), 960)


class GroqRequestFlowTests(SimpleTestCase):
    def _common_patches(self):
        return (
            patch('dashboard.utils.rotate_configs', side_effect=lambda configs: configs),
            patch('dashboard.utils.get_daily_usage_map', return_value={}),
            patch('dashboard.utils.learned_tpm', return_value=None),
            patch('dashboard.utils.cooldown_remaining', return_value=0),
            patch('dashboard.utils.lease_remaining', return_value=0),
            patch('dashboard.utils.acquire_lease', return_value=(True, 46)),
            patch('dashboard.utils.record_attempt'),
            patch('dashboard.utils.remember_tpm'),
            patch('dashboard.utils.release_lease'),
        )

    def test_413_retries_once_with_smaller_payload(self):
        too_large = Mock(
            status_code=413,
            text='TPM: Limit 5000, Requested 5400',
            headers={},
            content=b'',
        )
        success = Mock(
            status_code=200,
            text='',
            headers={'x-ratelimit-limit-tokens': '8000'},
            content=b'{}',
        )
        success.json.return_value = {
            'choices': [{'message': {'content': '{"title":"ok"}'}}],
            'usage': {'prompt_tokens': 1000, 'completion_tokens': 2500},
        }

        patches = self._common_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], \
                patch('dashboard.utils.requests.post', side_effect=[too_large, success]) as post:
            content, meta = call_groq_with_fallback(
                [{
                    'id': 1,
                    'provider': 'groq',
                    'api_key': 'test-key',
                    'model_name': 'openai/gpt-oss-20b',
                    'is_active': True,
                }],
                'x' * 3700,
                max_tokens=4400,
            )

        self.assertEqual(content, '{"title":"ok"}')
        self.assertEqual(meta['completion_tokens'], 2500)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args_list[0].kwargs['json']['max_tokens'], 4400)
        self.assertEqual(post.call_args_list[1].kwargs['json']['max_tokens'], 3744)

    def test_429_requests_non_blocking_retry(self):
        limited = Mock(
            status_code=429,
            text='rate limited',
            headers={'retry-after': '20'},
            content=b'',
        )
        patches = self._common_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], \
                patch('dashboard.utils.set_cooldown') as set_cooldown, \
                patch('dashboard.utils.jittered', side_effect=lambda value: value), \
                patch('dashboard.utils.requests.post', return_value=limited):
            with self.assertRaises(GroqRetryLater) as raised:
                call_groq_with_fallback(
                    [{
                        'id': 1,
                        'provider': 'groq',
                        'api_key': 'test-key',
                        'model_name': 'openai/gpt-oss-20b',
                        'is_active': True,
                    }],
                    'short prompt',
                    max_tokens=4400,
                )

        self.assertEqual(raised.exception.retry_after, 20)
        set_cooldown.assert_called_once()


class GroqUsageTests(TestCase):
    def test_record_attempt_accumulates_daily_usage(self):
        site = Site.objects.create(domain='quota-test.example')
        key = APIKey.objects.create(
            site=site,
            provider='groq',
            api_key='test-secret',
        )

        record_attempt(
            key.id,
            'openai/gpt-oss-20b',
            status_code=200,
            prompt_tokens=900,
            completion_tokens=2500,
            tpm_limit=8000,
        )
        record_attempt(
            key.id,
            'openai/gpt-oss-20b',
            status_code=429,
            rate_limited=True,
            tpm_limit=8000,
        )

        usage = GroqUsage.objects.get(
            api_key=key,
            model_name='openai/gpt-oss-20b',
            usage_date=timezone.localdate(),
        )
        self.assertEqual(usage.request_count, 2)
        self.assertEqual(usage.total_tokens, 3400)
        self.assertEqual(usage.rate_limit_count, 1)


class RunCancellationTests(TestCase):
    def setUp(self):
        self.site = Site.objects.create(domain='cancel-test.example')
        self.keyword_list = KeywordList.objects.create(
            name='cancel-test',
            keywords_json=[{'h2s': ['first heading']}],
            item_count=1,
        )

    def make_run(self, status='running'):
        return DailyRun.objects.create(
            site=self.site,
            keyword_list=self.keyword_list,
            target_count=1,
            start_time=datetime.time(0, 0),
            end_time=datetime.time(23, 59),
            status=status,
        )

    @patch('dashboard.tasks.generate_single_article.apply_async')
    def test_daily_run_does_not_adopt_orphaned_pending_article(self, apply_async):
        run = self.make_run()
        orphan = Article.objects.create(
            site=self.site,
            keyword_list=self.keyword_list,
            keyword_index=0,
            status='pending',
            task_id='legacy-task',
        )

        result = process_daily_run(run.id)

        orphan.refresh_from_db()
        self.assertEqual(result, 'Scheduled 0 articles')
        self.assertIsNone(orphan.daily_run_id)
        self.assertEqual(orphan.task_id, 'legacy-task')
        apply_async.assert_not_called()

    @patch('app.celery.app.control.revoke')
    def test_permanent_cancel_removes_orphans_and_defers_automation(self, revoke):
        run = self.make_run()
        SiteAutomation.objects.create(
            site=self.site,
            keyword_list=self.keyword_list,
            is_enabled=True,
            next_run_time=timezone.now(),
        )
        linked = Article.objects.create(
            site=self.site,
            keyword_list=self.keyword_list,
            keyword_index=0,
            daily_run=run,
            status='pending',
            task_id='linked-task',
        )
        orphan = Article.objects.create(
            site=self.site,
            keyword_list=self.keyword_list,
            keyword_index=1,
            status='generating',
            task_id='orphan-task',
        )
        ready = Article.objects.create(
            site=self.site,
            keyword_list=self.keyword_list,
            keyword_index=2,
            daily_run=run,
            status='ready',
        )

        before = timezone.now()
        result = _cancel_run_ids([run.id])

        run.refresh_from_db()
        automation = SiteAutomation.objects.get(site=self.site)
        self.assertEqual(run.status, 'cancelled')
        self.assertFalse(Article.objects.filter(id=linked.id).exists())
        self.assertFalse(Article.objects.filter(id=orphan.id).exists())
        self.assertTrue(Article.objects.filter(id=ready.id).exists())
        self.assertEqual(result['deleted_articles'], 2)
        self.assertEqual(result['deferred_automations'], 1)
        self.assertGreater(
            automation.next_run_time,
            before + datetime.timedelta(hours=23),
        )
        self.assertEqual(revoke.call_count, 2)

    @patch('dashboard.tasks.process_daily_run.delay')
    def test_automation_does_not_overlap_running_run(self, delay):
        existing_run = self.make_run()
        APIKey.objects.create(
            site=self.site,
            provider='groq',
            api_key='automation-key',
        )
        SiteAutomation.objects.create(
            site=self.site,
            keyword_list=self.keyword_list,
            is_enabled=True,
            next_run_time=timezone.now() - datetime.timedelta(minutes=1),
        )

        result = check_site_automations()

        self.assertEqual(result, 'Triggered 0 automations')
        self.assertEqual(DailyRun.objects.filter(site=self.site).count(), 1)
        self.assertTrue(DailyRun.objects.filter(id=existing_run.id).exists())
        delay.assert_not_called()
