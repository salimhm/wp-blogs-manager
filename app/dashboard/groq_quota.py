"""Shared Groq quota coordination for web and Celery processes."""

import hashlib
import math
import os
import random
import re
import time
from datetime import datetime, time as datetime_time, timedelta

from django.core.cache import cache
from django.db.models import F
from django.utils import timezone


MODEL_LIMITS = {
    'openai/gpt-oss-20b': {'tpm': 8_000, 'tpd': 200_000},
    'openai/gpt-oss-120b': {'tpm': 8_000, 'tpd': 200_000},
    'qwen/qwen3.6-27b': {'tpm': 8_000, 'tpd': 200_000},
    'llama-3.1-8b-instant': {'tpm': 6_000, 'tpd': 500_000},
    'llama-3.3-70b-versatile': {'tpm': 12_000, 'tpd': 100_000},
}

MODEL_REPLACEMENTS = {
    'llama-3.1-8b-instant': 'openai/gpt-oss-20b',
    'llama-3.3-70b-versatile': 'openai/gpt-oss-120b',
}

DEFAULT_GROQ_MODELS = tuple(
    model.strip()
    for model in os.environ.get(
        'GROQ_DEFAULT_MODELS',
        'openai/gpt-oss-20b,openai/gpt-oss-120b',
    ).split(',')
    if model.strip()
)
ARTICLE_MAX_TOKENS = int(os.environ.get('GROQ_ARTICLE_MAX_TOKENS', '4400'))
EXPECTED_ARTICLE_TOKENS = int(os.environ.get('GROQ_EXPECTED_ARTICLE_TOKENS', '3000'))
TOKEN_SAFETY_RATIO = float(os.environ.get('GROQ_TOKEN_SAFETY_RATIO', '0.90'))
DAILY_SAFETY_RATIO = float(os.environ.get('GROQ_DAILY_SAFETY_RATIO', '0.90'))
MIN_COMPLETION_TOKENS = int(os.environ.get('GROQ_MIN_COMPLETION_TOKENS', '1800'))


class GroqRetryLater(Exception):
    """No quota pool is currently available; the Celery task should retry."""

    def __init__(self, retry_after, reason='All Groq quota pools are cooling down'):
        self.retry_after = max(5, int(math.ceil(retry_after)))
        self.reason = reason
        super().__init__(f'{reason}; retry in {self.retry_after}s')


class GroqPermanentError(Exception):
    """The request cannot succeed unchanged and should not be cooled down."""


def model_limits(model):
    return MODEL_LIMITS.get(model, {'tpm': 8_000, 'tpd': 200_000})


def models_for_key(config):
    configured_model = (config.get('model_name') or '').strip()
    configured_model = MODEL_REPLACEMENTS.get(configured_model, configured_model)
    return (configured_model,) if configured_model else DEFAULT_GROQ_MODELS


def key_fingerprint(api_key):
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()[:20]


def quota_pool_id(config):
    return str(config.get('quota_pool') or key_fingerprint(config['api_key']))


def estimate_prompt_tokens(prompt):
    return max(1, math.ceil(len(prompt) / 3.7))


def completion_budget(prompt, requested_max_tokens, model, learned_tpm_value=None):
    limits = model_limits(model)
    tpm = int(learned_tpm_value or limits['tpm'])
    safe_request_tokens = int(tpm * TOKEN_SAFETY_RATIO)
    available_output = safe_request_tokens - estimate_prompt_tokens(prompt)
    return min(int(requested_max_tokens), max(0, available_output))


def seconds_until_utc_tomorrow():
    now = timezone.now()
    tomorrow = (now + timedelta(days=1)).date()
    boundary = timezone.make_aware(
        datetime.combine(tomorrow, datetime_time.min),
        timezone.get_current_timezone(),
    )
    return max(60, int((boundary - now).total_seconds()))


def parse_duration(value, default=60):
    if value is None:
        return float(default)
    text = str(value).strip()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass

    match = re.fullmatch(
        r'(?:(?P<hours>\d+(?:\.\d+)?)h)?'
        r'(?:(?P<minutes>\d+(?:\.\d+)?)m)?'
        r'(?:(?P<seconds>\d+(?:\.\d+)?)s)?',
        text,
    )
    if not match:
        return float(default)
    return (
        float(match.group('hours') or 0) * 3600
        + float(match.group('minutes') or 0) * 60
        + float(match.group('seconds') or 0)
    )


def _state_key(kind, pool_id, model):
    model_hash = hashlib.sha1(model.encode('utf-8')).hexdigest()[:12]
    return f'groq:{kind}:{pool_id}:{model_hash}'


def learned_tpm(pool_id, model):
    return cache.get(_state_key('tpm', pool_id, model))


def remember_tpm(pool_id, model, value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return
    if value > 0:
        cache.set(_state_key('tpm', pool_id, model), value, timeout=7 * 86400)


def cooldown_remaining(pool_id, model):
    available_at = cache.get(_state_key('cooldown', pool_id, model), 0)
    return max(0.0, float(available_at or 0) - time.time())


def set_cooldown(pool_id, model, wait_time):
    wait_time = max(1, int(math.ceil(wait_time)))
    cache.set(
        _state_key('cooldown', pool_id, model),
        time.time() + wait_time,
        timeout=wait_time + 60,
    )


def lease_remaining(pool_id, model):
    available_at = cache.get(_state_key('lease', pool_id, model), 0)
    return max(0.0, float(available_at or 0) - time.time())


def acquire_lease(pool_id, model, estimated_tokens, tpm):
    lease_seconds = max(10, int(math.ceil((estimated_tokens / max(1, tpm)) * 60)) + 5)
    available_at = time.time() + lease_seconds
    acquired = cache.add(
        _state_key('lease', pool_id, model),
        available_at,
        timeout=lease_seconds,
    )
    return acquired, lease_seconds


def release_lease(pool_id, model):
    cache.delete(_state_key('lease', pool_id, model))


def rotate_configs(configs):
    configs = sorted(configs, key=lambda item: item.get('api_key', ''))
    if not configs:
        return configs
    counter_key = 'groq:round-robin-index'
    cache.add(counter_key, 0, timeout=None)
    try:
        index = cache.incr(counter_key)
    except ValueError:
        cache.set(counter_key, 1, timeout=None)
        index = 1
    start = (index - 1) % len(configs)
    return configs[start:] + configs[:start]


def get_daily_usage_map(api_key_ids):
    from .models import GroqUsage

    if not api_key_ids:
        return {}
    rows = GroqUsage.objects.filter(
        api_key_id__in=api_key_ids,
        usage_date=timezone.localdate(),
    ).values_list('api_key_id', 'model_name', 'total_tokens')
    return {(key_id, model): total for key_id, model, total in rows}


def record_attempt(
    api_key_id,
    model,
    *,
    status_code,
    prompt_tokens=0,
    completion_tokens=0,
    rate_limited=False,
    payload_too_large=False,
    error=False,
    error_message='',
    tpm_limit=None,
):
    from .models import GroqUsage

    if not api_key_id:
        return
    limits = model_limits(model)
    usage, _created = GroqUsage.objects.get_or_create(
        api_key_id=api_key_id,
        model_name=model,
        usage_date=timezone.localdate(),
        defaults={
            'tpm_limit': int(tpm_limit or limits['tpm']),
            'tpd_limit': limits['tpd'],
        },
    )
    GroqUsage.objects.filter(pk=usage.pk).update(
        request_count=F('request_count') + 1,
        prompt_tokens=F('prompt_tokens') + int(prompt_tokens or 0),
        completion_tokens=F('completion_tokens') + int(completion_tokens or 0),
        total_tokens=F('total_tokens') + int(prompt_tokens or 0) + int(completion_tokens or 0),
        rate_limit_count=F('rate_limit_count') + int(bool(rate_limited)),
        payload_too_large_count=F('payload_too_large_count') + int(bool(payload_too_large)),
        error_count=F('error_count') + int(bool(error)),
        last_status_code=int(status_code or 0),
        last_error=str(error_message or '')[:500],
        tpm_limit=int(tpm_limit or limits['tpm']),
        tpd_limit=limits['tpd'],
        updated_at=timezone.now(),
    )


def parse_payload_limit(response_text):
    match = re.search(r'Limit\s+(\d+),\s+Requested\s+(\d+)', response_text or '')
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2))


def retry_after_from_response(response, default=60):
    if response.headers.get('retry-after'):
        return parse_duration(response.headers.get('retry-after'), default)
    if response.headers.get('x-ratelimit-reset-tokens'):
        return parse_duration(response.headers.get('x-ratelimit-reset-tokens'), default)
    if response.headers.get('x-ratelimit-reset-requests'):
        return parse_duration(response.headers.get('x-ratelimit-reset-requests'), default)
    return float(default)


def daily_article_capacity(api_keys):
    total_tokens = 0
    for key in api_keys:
        if not key.is_active or key.provider != 'groq':
            continue
        config = {'model_name': key.model_name, 'api_key': key.api_key}
        total_tokens += sum(
            model_limits(model)['tpd'] * DAILY_SAFETY_RATIO
            for model in models_for_key(config)
        )
    return max(0, int(total_tokens // max(1, EXPECTED_ARTICLE_TOKENS)))


def daily_token_capacity(api_keys):
    total_tokens = 0
    for key in api_keys:
        if not key.is_active or key.provider != 'groq':
            continue
        config = {'model_name': key.model_name, 'api_key': key.api_key}
        total_tokens += sum(
            model_limits(model)['tpd'] * DAILY_SAFETY_RATIO
            for model in models_for_key(config)
        )
    return int(total_tokens)


def live_pool_counts(api_keys):
    cooling_pools = set()
    leased_pools = set()
    for key in api_keys:
        if not key.is_active or key.provider != 'groq':
            continue
        config = {'model_name': key.model_name, 'api_key': key.api_key}
        pool_id = quota_pool_id(config)
        for model in models_for_key(config):
            pool_ref = (pool_id, model)
            try:
                if cooldown_remaining(pool_id, model) > 0:
                    cooling_pools.add(pool_ref)
                if lease_remaining(pool_id, model) > 0:
                    leased_pools.add(pool_ref)
            except Exception:
                # Quota telemetry must never make the dashboard unavailable.
                continue
    return len(cooling_pools), len(leased_pools)


def jittered(wait_time, ratio=0.10):
    wait_time = max(1.0, float(wait_time))
    return wait_time + random.uniform(1, max(2, wait_time * ratio))
