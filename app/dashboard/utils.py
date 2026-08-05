import requests
import secrets
import string
from typing import Optional, Tuple


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_username(domain: str) -> str:
    """Generate a username based on domain."""
    # Extract first part of domain
    name = domain.split('.')[0]
    # Add random suffix
    suffix = ''.join(secrets.choice(string.digits) for _ in range(4))
    return f"{name}_admin_{suffix}"


def verify_wp_credentials(
    domain: str, 
    username: str, 
    password: str,
    proxy: Optional[dict] = None
) -> Tuple[bool, str]:
    """
    Verify WordPress credentials using multiple methods.
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    # Try REST API first (best for Application Passwords)
    success, message = _verify_via_rest_api(domain, username, password, proxy)
    if success:
        return True, message

    # Try XML-RPC second (also supports App Passwords)
    success, message = _verify_via_xmlrpc(domain, username, password, proxy)
    if success:
        return True, message
    
    # Fall back to login form method (only works with real passwords)
    return _verify_via_login_form(domain, username, password, proxy)


def _verify_via_rest_api(
    domain: str,
    username: str,
    password: str,
    proxy: Optional[dict] = None
) -> Tuple[bool, str]:
    """Verify credentials via WordPress REST API."""
    import base64
    
    api_url = f"https://{domain}/wp-json/wp/v2/users/me"
    credentials = f"{username}:{password}"
    token = base64.b64encode(credentials.encode()).decode()
    
    headers = {
        'Authorization': f'Basic {token}',
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(
            api_url, 
            headers=headers, 
            timeout=15, 
            proxies=proxy,
            verify=True
        )
        
        if response.status_code == 200:
            return True, "Verified via REST API"
        elif response.status_code == 401:
            return False, "Invalid credentials (API)"
        elif response.status_code == 403:
            return False, "Permission denied (API)"
        else:
            return False, f"API Error: {response.status_code}"
            
    except Exception as e:
        return False, f"REST API error: {str(e)}"


def _verify_via_xmlrpc(
    domain: str,
    username: str,
    password: str,
    proxy: Optional[dict] = None
) -> Tuple[bool, str]:
    """Verify credentials via WordPress XML-RPC API."""
    import xml.etree.ElementTree as ET
    
    xmlrpc_url = f"https://{domain}/xmlrpc.php"
    
    # XML-RPC request to get user's blogs (requires valid auth)
    xml_payload = f'''<?xml version="1.0"?>
<methodCall>
    <methodName>wp.getUsersBlogs</methodName>
    <params>
        <param><value><string>{username}</string></value></param>
        <param><value><string>{password}</string></value></param>
    </params>
</methodCall>'''
    
    try:
        session = requests.Session()
        if proxy:
            session.proxies = proxy
        
        headers = {'Content-Type': 'application/xml'}
        response = session.post(
            xmlrpc_url, 
            data=xml_payload, 
            headers=headers, 
            timeout=15,
            verify=True
        )
        
        if response.status_code == 404:
            # XML-RPC disabled, try login form method
            return False, "XML-RPC not available"
        
        # Parse response to check for success or fault
        try:
            root = ET.fromstring(response.text)
            fault = root.find('.//fault')
            if fault is not None:
                fault_string = root.find('.//member[name="faultString"]/value/string')
                if fault_string is not None:
                    error_text = fault_string.text.lower()
                    if 'incorrect' in error_text or 'invalid' in error_text:
                        return False, "Invalid username or password"
                return False, "Authentication failed"
            
            # Check for successful response (array of blogs)
            if root.find('.//array') is not None:
                return True, "Credentials verified successfully!"
                
        except ET.ParseError:
            return False, "XML-RPC not available"
            
        return False, "Could not verify via XML-RPC"
        
    except requests.exceptions.SSLError:
        return False, "SSL certificate error"
    except requests.exceptions.ConnectionError:
        return False, f"Could not connect to {domain}"
    except requests.exceptions.Timeout:
        return False, "Connection timed out"
    except Exception as e:
        return False, f"XML-RPC error: {str(e)}"


def _verify_via_login_form(
    domain: str,
    username: str,
    password: str,
    proxy: Optional[dict] = None
) -> Tuple[bool, str]:
    """Verify credentials via WordPress login form."""
    login_url = f"https://{domain}/wp-login.php"
    admin_url = f"https://{domain}/wp-admin/"
    
    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        
        if proxy:
            session.proxies = proxy
        
        # Step 1: Get login page to set initial cookies
        response = session.get(login_url, timeout=15, verify=True)
        
        if response.status_code == 404:
            return False, "WordPress login page not found"
        
        if response.status_code != 200:
            return False, f"Could not reach login page (status: {response.status_code})"
        
        # Step 2: Manually set the WordPress test cookie (required for login)
        session.cookies.set('wordpress_test_cookie', 'WP Cookie check', domain=domain)
        
        # Step 3: Prepare login data
        login_data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': admin_url,
            'testcookie': '1'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url,
            'Origin': f'https://{domain}'
        }
        
        # Step 4: Attempt login (don't follow redirects so we can check cookies first)
        response = session.post(
            login_url, 
            data=login_data, 
            headers=headers,
            timeout=15,
            allow_redirects=False
        )
        
        print(f"[DEBUG] Login POST status: {response.status_code}")
        print(f"[DEBUG] Cookies after login: {[(c.name, c.domain) for c in session.cookies]}")
        
        # Step 5: Check for WordPress auth cookies (indicates successful login)
        cookie_names = [c.name for c in session.cookies]
        has_auth_cookie = any(
            name.startswith('wordpress_logged_in_') or 
            name.startswith('wordpress_sec_') or
            name.startswith('wp-settings-')
            for name in cookie_names
        )
        
        if has_auth_cookie:
            return True, "Credentials verified successfully!"
        
        # Step 6: If no auth cookie, check the response 
        if response.status_code in (302, 301):
            location = response.headers.get('Location', '')
            print(f"[DEBUG] Redirect location: {location}")
            
            # Successful login redirects to wp-admin
            if 'wp-admin' in location and 'login' not in location.lower():
                return True, "Credentials verified successfully!"
            
            # Login failed - redirected back to login with error
            if 'wp-login.php' in location:
                # Follow redirect to get error message
                error_response = session.get(location, timeout=15)
                error_text = error_response.text.lower()
                
                if 'invalid username' in error_text or 'unknown username' in error_text:
                    return False, "Invalid username"
                elif 'incorrect password' in error_text or 'password you entered' in error_text:
                    return False, "Incorrect password"
                elif 'empty password' in error_text:
                    return False, "Password cannot be empty"
                else:
                    return False, "Invalid username or password"
        
        # Step 7: Check response body for errors (status 200 means we stayed on login page)
        if response.status_code == 200:
            response_text = response.text.lower()
            
            if 'login_error' in response_text or 'id="login_error"' in response_text:
                if 'invalid username' in response_text or 'unknown username' in response_text:
                    return False, "Invalid username"
                elif 'incorrect password' in response_text or 'password you entered' in response_text:
                    return False, "Incorrect password"
                elif 'cookies are blocked' in response_text or 'cookies' in response_text:
                    return False, "Cookie error - site may have security restrictions"
                else:
                    return False, "Invalid username or password"
            
            # No explicit error but still on login page
            if 'wp-login.php' in response.url or 'user-login' in response_text:
                return False, "Login failed - check credentials"
        
        # Step 8: Try to access wp-admin to verify
        admin_response = session.get(admin_url, timeout=15, allow_redirects=True)
        if 'wp-admin' in admin_response.url and 'login' not in admin_response.url.lower():
            return True, "Credentials verified successfully!"
        
        return False, "Could not verify credentials - site may have additional security"
        
    except requests.exceptions.SSLError:
        return False, "SSL certificate error. Check if the site has valid HTTPS."
    except requests.exceptions.ConnectionError:
        return False, f"Could not connect to {domain}. Check if the domain is accessible."
    except requests.exceptions.Timeout:
        return False, "Connection timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"


def verify_proxy(
    proxy_type: str,
    host: str,
    port: int,
    username: str = None,
    password: str = None
) -> Tuple[bool, str, dict]:
    """
    Verify proxy connectivity and authentication.
    
    Returns:
        Tuple of (success: bool, message: str, info: dict)
    """
    # Build proxy URL
    if username and password:
        proxy_url = f"{proxy_type}://{username}:{password}@{host}:{port}"
    else:
        proxy_url = f"{proxy_type}://{host}:{port}"
    
    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }
    
    # Test URLs - we'll try multiple to ensure proxy works
    test_urls = [
        ('https://httpbin.org/ip', 'origin'),
        ('https://api.ipify.org?format=json', 'ip'),
    ]
    
    try:
        session = requests.Session()
        session.proxies = proxies
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
        })
        
        for url, ip_key in test_urls:
            try:
                response = session.get(url, timeout=15, verify=True)
                
                if response.status_code == 200:
                    data = response.json()
                    proxy_ip = data.get(ip_key, 'Unknown')
                    
                    return True, f"Proxy working! IP: {proxy_ip}", {
                        'proxy_ip': proxy_ip,
                        'test_url': url
                    }
                    
            except requests.exceptions.JSONDecodeError:
                continue
            except requests.exceptions.RequestException:
                continue
        
        return False, "Proxy connection failed - could not verify IP", {}
        
    except requests.exceptions.ProxyError as e:
        error_str = str(e).lower()
        if 'authentication' in error_str or '407' in error_str:
            return False, "Proxy authentication failed - check username/password", {}
        elif 'connection refused' in error_str:
            return False, f"Proxy connection refused at {host}:{port}", {}
        else:
            return False, f"Proxy error: {str(e)}", {}
            
    except requests.exceptions.ConnectTimeout:
        return False, f"Proxy connection timed out - check host and port", {}
        
    except requests.exceptions.ConnectionError as e:
        error_str = str(e).lower()
        if 'socks' in error_str and proxy_type == 'socks5':
            return False, "SOCKS5 connection failed. Install PySocks: pip install pysocks", {}
        return False, f"Could not connect to proxy: {host}:{port}", {}
        
    except Exception as e:
        return False, f"Error: {str(e)}", {}


def create_cloudflare_dns_record(
    api_token: str,
    zone_id: str,
    domain: str,
    server_ip: str,
    record_type: str = 'A',
    proxied: bool = True
) -> Tuple[bool, str]:
    """
    Create a DNS record in Cloudflare.
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }
    
    # Extract subdomain if present
    # e.g., "blog.example.com" -> name="blog", but "example.com" -> name="@"
    parts = domain.split('.')
    if len(parts) > 2:
        name = '.'.join(parts[:-2])  # subdomain
    else:
        name = '@'  # root domain
    
    data = {
        'type': record_type,
        'name': name if name != '@' else domain,
        'content': server_ip,
        'ttl': 1,  # Auto TTL
        'proxied': proxied
    }
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=10)
        result = response.json()
        
        if result.get('success'):
            return True, f"DNS record created for {domain}"
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
            
            # Check if record already exists
            if 'already exists' in error_msg.lower():
                return True, f"DNS record already exists for {domain}"
            
            return False, f"Cloudflare error: {error_msg}"
            
    except requests.exceptions.RequestException as e:
        return False, f"Network error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"


def get_cloudflare_zones(api_token: str) -> Tuple[bool, list]:
    """
    Get list of zones from Cloudflare account.
    
    Returns:
        Tuple of (success: bool, zones: list of dicts with 'id' and 'name')
    """
    url = "https://api.cloudflare.com/client/v4/zones"
    
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }
    
    all_zones = []
    page = 1
    per_page = 50  # Max allowed by Cloudflare
    
    try:
        while True:
            params = {'page': page, 'per_page': per_page}
            response = requests.get(url, headers=headers, params=params, timeout=15)
            result = response.json()
            
            if not result.get('success'):
                if all_zones:  # Return what we have if some pages succeeded
                    return True, all_zones
                return False, []
            
            zones = [{'id': z['id'], 'name': z['name']} for z in result.get('result', [])]
            all_zones.extend(zones)
            
            # Check if there are more pages
            result_info = result.get('result_info', {})
            total_pages = result_info.get('total_pages', 1)
            
            if page >= total_pages:
                break
            page += 1
        
        return True, all_zones
            
    except Exception:
        if all_zones:  # Return what we have on error
            return True, all_zones
        return False, []




def search_youtube(query: str, max_results: int = 2) -> list:
    """
    Search YouTube for videos related to the query.
    Uses youtube-search library.
    
    Returns: List of dicts with 'video_id', 'title', 'embed_html'
    """
    try:
        from youtube_search import YoutubeSearch
        
        # Add "guide" to query for better results
        results = YoutubeSearch(query + " guide", max_results=max_results).to_dict()
        
        videos = []
        for result in results:
            # youtube-search returns url_suffix like '/watch?v=VIDEO_ID'
            url_suffix = result.get('url_suffix', '')
            
            # Extract video ID from url_suffix
            video_id = None
            if 'v=' in url_suffix:
                video_id = url_suffix.split('v=')[-1].split('&')[0]
            
            if not video_id or len(video_id) < 8:
                video_id = result.get('id', '')
            
            if not video_id or len(video_id) < 8:
                continue
            
            video_id = video_id.strip()
            title = result.get('title', 'Watch Video')
            
            # Use clickable thumbnail instead of iframe (avoids embedding restrictions)
            # YouTube thumbnails are always available at predictable URLs
            thumbnail_url = f"https://img.youtube.com/vi/{video_id}/hqdefault.jpg"
            video_url = f"https://www.youtube.com/watch?v={video_id}"
            
            embed_html = f'''<div class="video-embed" style="margin: 30px 0; text-align: center;">
<a href="{video_url}" target="_blank" rel="noopener" style="display: inline-block; position: relative; text-decoration: none;">
<img src="{thumbnail_url}" alt="{title}" style="max-width: 100%; width: 560px; height: auto; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.3);">
<div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 68px; height: 48px; background: rgba(255,0,0,0.9); border-radius: 12px; display: flex; align-items: center; justify-content: center;">
<div style="width: 0; height: 0; border-left: 18px solid white; border-top: 10px solid transparent; border-bottom: 10px solid transparent; margin-left: 4px;"></div>
</div>
</a>
<p style="margin-top: 10px; font-size: 14px; color: #666;"><a href="{video_url}" target="_blank" rel="noopener" style="color: #1a73e8; text-decoration: none;">▶ {title[:60]}...</a></p>
</div>'''
            videos.append({
                'video_id': video_id,
                'title': title,
                'embed_html': embed_html
            })
        
        return videos
        
    except ImportError as ie:
        print(f"youtube-search import failed: {ie}. Install with: pip install youtube-search")
        return []
    except Exception as e:
        print(f"YouTube search error: {e}")
        return []


# ============================================
# Groq LLM Integration (Optimized & Rate-Limited)
# ============================================

import json
import time

from .groq_quota import (
    ARTICLE_MAX_TOKENS,
    DAILY_SAFETY_RATIO,
    MIN_COMPLETION_TOKENS,
    GroqPermanentError,
    GroqRetryLater,
    acquire_lease,
    completion_budget,
    cooldown_remaining,
    estimate_prompt_tokens,
    get_daily_usage_map,
    jittered,
    learned_tpm,
    lease_remaining,
    model_limits,
    models_for_key,
    parse_payload_limit,
    quota_pool_id,
    record_attempt,
    release_lease,
    remember_tpm,
    retry_after_from_response,
    rotate_configs,
    seconds_until_utc_tomorrow,
    set_cooldown,
)

def _clean_llm_content(content: str) -> str:
    content = content.strip()
    prefixes = ["Here is", "Here's", "Sure,", "Certainly,", "Of course,", "Here are", "Below is", "The following"]
    for p in prefixes:
        if content.lower().startswith(p.lower()):
            idx = content.find('\n')
            if idx != -1 and idx < 100:
                content = content[idx:].strip()
    return content

def call_groq_with_fallback(
    api_keys: list,
    prompt: str,
    max_tokens: int = ARTICLE_MAX_TOKENS,
    proxy: Optional[dict] = None,
) -> tuple[str, dict]:
    """Call Groq once per available quota pool without blocking a worker."""
    configs = [
        config for config in api_keys
        if config.get('is_active') and config.get('provider') == 'groq'
    ]
    if not configs:
        raise GroqPermanentError("No active Groq API keys provided")

    configs = rotate_configs(configs)
    usage_map = get_daily_usage_map([
        config.get('id') for config in configs if config.get('id')
    ])
    waits = []
    permanent_errors = []
    transient_errors = []
    prompt_estimate = estimate_prompt_tokens(prompt)

    for config in configs:
        api_key = config['api_key']
        api_key_id = config.get('id')
        pool_id = quota_pool_id(config)

        for model in models_for_key(config):
            limits = model_limits(model)
            current_tpm = int(learned_tpm(pool_id, model) or limits['tpm'])
            used_today = int(usage_map.get((api_key_id, model), 0))
            safe_daily_limit = int(limits['tpd'] * DAILY_SAFETY_RATIO)

            if used_today >= safe_daily_limit:
                waits.append(seconds_until_utc_tomorrow())
                continue

            cooling = cooldown_remaining(pool_id, model)
            if cooling > 0:
                waits.append(cooling)
                continue

            leased_for = lease_remaining(pool_id, model)
            if leased_for > 0:
                waits.append(leased_for)
                continue

            output_budget = completion_budget(prompt, max_tokens, model, current_tpm)
            if output_budget < MIN_COMPLETION_TOKENS:
                permanent_errors.append(
                    f"{model} cannot fit this prompt inside its {current_tpm} TPM limit"
                )
                continue

            estimated_request_tokens = prompt_estimate + output_budget
            if used_today + estimated_request_tokens > safe_daily_limit:
                waits.append(seconds_until_utc_tomorrow())
                continue

            acquired, lease_seconds = acquire_lease(
                pool_id,
                model,
                estimated_request_tokens,
                current_tpm,
            )
            if not acquired:
                waits.append(max(5, lease_remaining(pool_id, model)))
                continue

            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'Accept-Encoding': 'gzip, deflate',
            }
            system_prompt = (
                "You are a professional content writer. Write plain, natural "
                "prose. Output valid JSON if requested."
            )

            # A 413 gets at most one retry, and only with a smaller payload.
            for payload_attempt in range(2):
                data = {
                    'model': model,
                    'messages': [
                        {'role': 'system', 'content': system_prompt},
                        {'role': 'user', 'content': prompt},
                    ],
                    'max_tokens': output_budget,
                    'temperature': 0.7,
                    'response_format': {'type': 'json_object'},
                }
                if model.startswith('openai/gpt-oss'):
                    data['reasoning_effort'] = 'low'
                try:
                    proxy_info = (
                        f"via {list(proxy.values())[0][:30]}..."
                        if proxy else "DIRECT"
                    )
                    print(
                        f"[LLM REQUEST] Groq/{model} [Key ending in {api_key[-4:]}] "
                        f"budget={output_budget} lease={lease_seconds}s - {proxy_info}"
                    )
                    response = requests.post(
                        url,
                        json=data,
                        headers=headers,
                        timeout=160,
                        proxies=proxy,
                    )
                except requests.RequestException as exc:
                    message = f"Network error for {model}: {exc}"
                    print(message)
                    record_attempt(
                        api_key_id,
                        model,
                        status_code=0,
                        error=True,
                        error_message=message,
                        tpm_limit=current_tpm,
                    )
                    transient_errors.append(message)
                    waits.append(30)
                    break

                header_tpm = response.headers.get('x-ratelimit-limit-tokens')
                if header_tpm:
                    remember_tpm(pool_id, model, header_tpm)
                    try:
                        current_tpm = int(header_tpm)
                    except (TypeError, ValueError):
                        pass

                if response.status_code == 200:
                    try:
                        resp_json = response.json()
                        content = _clean_llm_content(
                            resp_json['choices'][0]['message']['content']
                        )
                    except (ValueError, KeyError, IndexError, TypeError) as exc:
                        usage = {}
                        message = f"Invalid Groq JSON response from {model}: {exc}"
                        record_attempt(
                            api_key_id,
                            model,
                            status_code=200,
                            prompt_tokens=usage.get('prompt_tokens', 0),
                            completion_tokens=usage.get('completion_tokens', 0),
                            error=True,
                            error_message=message,
                            tpm_limit=current_tpm,
                        )
                        transient_errors.append(message)
                        break

                    usage = resp_json.get('usage', {})
                    prompt_tokens = int(usage.get('prompt_tokens', 0) or 0)
                    completion_tokens = int(usage.get('completion_tokens', 0) or 0)
                    record_attempt(
                        api_key_id,
                        model,
                        status_code=200,
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                        tpm_limit=current_tpm,
                    )
                    return content, {
                        'provider': 'groq',
                        'model': model,
                        'timestamp': time.time(),
                        'bytes_received': len(response.content),
                        'prompt_tokens': prompt_tokens,
                        'completion_tokens': completion_tokens,
                        'max_tokens': output_budget,
                        'quota_pool': pool_id,
                    }

                error_text = response.text[:500]
                if response.status_code == 413:
                    limit, requested = parse_payload_limit(response.text)
                    record_attempt(
                        api_key_id,
                        model,
                        status_code=413,
                        payload_too_large=True,
                        error=True,
                        error_message=error_text,
                        tpm_limit=limit or current_tpm,
                    )
                    if limit:
                        remember_tpm(pool_id, model, limit)
                        current_tpm = limit
                    if (
                        payload_attempt == 0
                        and limit
                        and requested
                        and requested > limit
                    ):
                        reduced_budget = output_budget - (requested - limit) - 256
                        if reduced_budget >= MIN_COMPLETION_TOKENS:
                            output_budget = reduced_budget
                            print(
                                f"[GROQ 413] Reducing {model} output budget to "
                                f"{output_budget}; retrying once."
                            )
                            continue
                    permanent_errors.append(
                        f"{model} payload is too large even after adaptive sizing"
                    )
                    release_lease(pool_id, model)
                    break

                if response.status_code == 429:
                    wait_time = jittered(retry_after_from_response(response, 60))
                    set_cooldown(pool_id, model, wait_time)
                    record_attempt(
                        api_key_id,
                        model,
                        status_code=429,
                        rate_limited=True,
                        error_message=error_text,
                        tpm_limit=current_tpm,
                    )
                    print(
                        f"[GROQ 429] {model} key {api_key[-4:]} cooling for "
                        f"{wait_time:.1f}s."
                    )
                    waits.append(wait_time)
                    break

                if response.status_code in (498, 503):
                    wait_time = jittered(
                        retry_after_from_response(
                            response,
                            20 if response.status_code == 498 else 45,
                        )
                    )
                    set_cooldown(pool_id, model, wait_time)
                    record_attempt(
                        api_key_id,
                        model,
                        status_code=response.status_code,
                        error=True,
                        error_message=error_text,
                        tpm_limit=current_tpm,
                    )
                    transient_errors.append(error_text)
                    waits.append(wait_time)
                    break

                record_attempt(
                    api_key_id,
                    model,
                    status_code=response.status_code,
                    error=True,
                    error_message=error_text,
                    tpm_limit=current_tpm,
                )
                permanent_errors.append(
                    f"{model} returned HTTP {response.status_code}: {error_text[:160]}"
                )
                break

    if waits:
        raise GroqRetryLater(
            jittered(min(waits)),
            reason='No Groq key/model quota pool is currently available',
        )
    if transient_errors:
        raise GroqRetryLater(30, reason=transient_errors[-1])
    if permanent_errors:
        raise GroqPermanentError('; '.join(permanent_errors[-3:]))
    raise GroqPermanentError("No usable Groq key/model combinations")
# Keep fallback signature for compatibility, but route exclusively to Groq
def call_llm_with_fallback(api_keys: list, prompt: str, max_tokens: int = 4096, proxy: Optional[dict] = None) -> tuple[str, dict]:
    return call_groq_with_fallback(api_keys, prompt, max_tokens, proxy)

def generate_article_content(h2s: list, api_keys: list, proxy: Optional[dict] = None) -> dict:
    """
    Generate a full article from H2 headings using a single mega-prompt to minimize proxy bandwidth.
    """
    h2_list = '\n'.join([f'- {h2}' for h2 in h2s])
    generation_stats = []
    
    # Dynamically scale the length requirement based on the number of headings
    # so the JSON closes inside the quota-aware completion budget.
    num_h2s = len(h2s)
    if num_h2s >= 12:
        para_req = "1-2 concise paragraphs"
        faq_req = "1 short paragraph"
    elif num_h2s >= 9:
        para_req = "2 comprehensive paragraphs"
        faq_req = "1 comprehensive paragraph"
    elif num_h2s >= 6:
        para_req = "3 comprehensive paragraphs"
        faq_req = "1-2 paragraphs"
    else:
        para_req = "3-4 comprehensive paragraphs with deep analysis"
        faq_req = "2 paragraphs"
    
    mega_prompt = f"""You are an elite, highly-paid technical content writer and SEO specialist. Write a comprehensive, highly-detailed, and deeply informative blog post covering the following core topics and user questions:

{h2_list}

STRICT INSTRUCTIONS TO AVOID REPETITION & FLUFF:
You will be heavily penalized for repeating the same concepts, repeating phrases from paragraph to paragraph, or repeating intro/outro fluff across sections. Every section must introduce NEW information, NEW examples, and NEW analysis.

TONE & STYLE GUIDELINES (CRITICAL):
- Do NOT sound like an AI. Avoid robotic, overly formal transitions like "In conclusion," "Furthermore," or "It is important to note that."
- Write in a natural, conversational, yet authoritative human voice. Use active voice.
- Vary your sentence structure. Mix short, punchy sentences with longer, explanatory ones.
- Use concrete examples, relatable analogies, or hypothetical scenarios to explain complex topics. Do not just state abstract facts.

REQUIREMENTS:
1. Title: Write a highly engaging, SEO-optimized title formatted as a comprehensive guide. It must be catchy and directly address the search intent.
2. Introduction: Write an engaging hook (2-3 paragraphs). Outline exactly what the user will learn.
3. Key Takeaways: Provide exactly 5-7 actionable, distinct bullet points.
4. Main Body Sections: Convert the provided topics into a logical, flowing blog post. 
   - DO NOT copy/paste the exact input questions as your headings. Synthesize them into professional, engaging blog headers.
   - Each section should contain {para_req}.
   - Dive deep into the subject matter. Provide step-by-step instructions, technical breakdowns, analogies, or concrete examples.
   - DO NOT repeat introductory fluff at the start of every section. Get straight to the point.
5. FAQ Section: Create a dedicated "Frequently Asked Questions" section at the very end. 
   - Generate 4-6 highly specific questions that a reader might still have after reading the main text.
   - Answer them concisely ({faq_req}). 
   - CRITICAL: These questions MUST NOT be the same topics you already covered in the main body. They must touch on edge-cases, common troubleshooting, or related tangential concepts. DO NOT REPEAT YOURSELF.

GOAL: The total final article should exceed 1500-2000 words in length. Extensively expand on every point to provide maximum, unique conversational value.

FORMATTING:
You MUST return your response as a valid JSON object matching this structural schema. Do NOT return anything else:
{{
    "title": "Article Title",
    "introduction": "Paragraph 1\n\nParagraph 2...",
    "key_takeaways": [
        "Takeaway 1",
        "Takeaway 2"
    ],
    "body_sections": {{
        "Section 1 Heading": "Paragraph 1\n\nParagraph 2...",
        "Section 2 Heading": "Paragraph 1\n\nParagraph 2..."
    }},
    "faq": {{
        "Question 1": "Answer 1\n\nAnswer 2...",
        "Question 2": "Answer 1..."
    }}
}}

CRITICAL INSTRUCTIONS:
- ONLY output a valid JSON object. No markdown wrapping (like ```json). No extra text before or after the JSON.
- DO NOT use markdown formatting (**, ##) within the text values. Just plain strings with \n\n for paragraph breaks.
- Ensure the JSON is completely valid and properly closed at the end. Do not exceed typical output length limits before closing the object."""
    
    try:
        content_json_str, meta = call_llm_with_fallback(api_keys, mega_prompt, max_tokens=ARTICLE_MAX_TOKENS, proxy=proxy)
        meta['step'] = 'mega_prompt'
        generation_stats.append(meta)
        
        # Clean JSON markdown wrapping if model ignored instructions
        content_json_str = content_json_str.strip()
        if content_json_str.startswith('```json'):
            content_json_str = content_json_str[7:-3]
        elif content_json_str.startswith('```'):
            content_json_str = content_json_str[3:-3]
            
        data = json.loads(content_json_str)
        
        title = data.get('title', h2s[0] if h2s else "Article")
        introduction = data.get('introduction', '')
        key_takeaways = data.get('key_takeaways', [])
        body_sections = data.get('body_sections', {})
        faq = data.get('faq', {})
        
        # Build HTML
        html_parts = []
        
        # Introduction
        intro_paragraphs = [p.strip() for p in introduction.split('\n') if p.strip()]
        html_parts.append('<div class="article-intro">')
        for p in intro_paragraphs:
            html_parts.append(f'<p>{p}</p>')
        html_parts.append('</div>')
        
        # Key Takeaways
        if key_takeaways:
            html_parts.append('<div class="key-takeaways">')
            html_parts.append('<h2 class="takeaways-title">🔑 Key Takeaways</h2>')
            html_parts.append('<ul class="takeaways-list">')
            for takeaway in key_takeaways:
                html_parts.append(f'<li>{takeaway}</li>')
            html_parts.append('</ul>')
            html_parts.append('</div>')
            
        # Search YouTube
        youtube_videos = search_youtube(title, max_results=2)
        video_1 = youtube_videos[0]['embed_html'] if len(youtube_videos) > 0 else ''
        video_2 = youtube_videos[1]['embed_html'] if len(youtube_videos) > 1 else ''
        
        # Body Sections
        section_idx = 0
        for heading, content in body_sections.items():
            html_parts.append(f'<h2 class="section-heading">{str(heading)}</h2>')
            html_parts.append('<div class="section-content">')
            paragraphs = [p.strip() for p in str(content).split('\n') if p.strip()]
            for p in paragraphs:
                html_parts.append(f'<p>{p}</p>')
            html_parts.append('</div>')
            
            if section_idx == 0 and video_1:
                html_parts.append(video_1)
            section_idx += 1
            
        # FAQs
        if faq:
            html_parts.append('<div class="faq-section">')
            html_parts.append('<h2 class="faq-title">❓ Frequently Asked Questions</h2>')
            faq_idx = 0
            for heading, content in faq.items():
                html_parts.append('<div class="faq-item">')
                html_parts.append(f'<h2 class="faq-question">{str(heading)}</h2>')
                html_parts.append('<div class="faq-answer">')
                paragraphs = [p.strip() for p in str(content).split('\n') if p.strip()]
                for p in paragraphs:
                    html_parts.append(f'<p>{p}</p>')
                html_parts.append('</div>')
                html_parts.append('</div>')
                
                if faq_idx == 1 and video_2:
                    html_parts.append(video_2)
                faq_idx += 1
            html_parts.append('</div>')
            
        content_html = '\n'.join(html_parts)
        
        return {
            'title': title,
            'introduction': introduction,
            'key_takeaways': key_takeaways,
            'body_sections': body_sections,
            'faq': faq,
            'html': content_html,
            'meta': {'provider_usage': generation_stats}
        }
    except Exception as e:
        print(f"Failed to generate article using mega-prompt: {e}")
        raise



# ============================================
# WordPress Publishing
# ============================================

def publish_to_wordpress(site, article) -> Tuple[bool, str, Optional[int]]:
    """
    Publish article to WordPress via REST API.
    Uses Application Password for authentication.
    
    Returns: (success, message, post_id)
    """
    from base64 import b64encode
    
    domain = site.domain
    username = site.wp_username
    app_password = site.wp_app_password  # Use Application Password, not admin password
    
    if not username or not app_password:
        return False, "WordPress Application Password not configured. Go to WP Admin → Profile → Application Passwords", None
    
    # Create auth header (username + application password)
    credentials = b64encode(f"{username}:{app_password}".encode()).decode()
    
    url = f"https://{domain}/wp-json/wp/v2/posts"
    headers = {
        'Authorization': f'Basic {credentials}',
        'Content-Type': 'application/json'
    }
    
    data = {
        'title': article.title,
        'content': article.content_html,
        'status': 'publish',  # or 'draft' for review
        'lang': 'en'  # Polylang language assignment
    }
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=30)
        
        if response.status_code == 201:
            result = response.json()
            post_id = result.get('id')
            post_url = result.get('link', '')
            return True, f"Published as post #{post_id}", post_id, post_url
        
        elif response.status_code == 401:
            return False, "Authentication failed - check credentials or enable Application Passwords", None, ''
        
        elif response.status_code == 403:
            return False, "Permission denied - user may not have publish rights", None, ''
        
        else:
            error = response.json().get('message', response.text)
            return False, f"WordPress error: {error}", None, ''
            
    except requests.exceptions.RequestException as e:
        return False, f"Network error: {str(e)}", None, ''
    except Exception as e:
        return False, f"Error: {str(e)}", None, ''

