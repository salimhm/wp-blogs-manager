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

import time
import re
import json

GROQ_MODELS = [
    'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant',
]

# Track when an API key + model will be available again
# Format: { ('api_key', 'model_name'): timestamp_when_available }
API_KEY_MODEL_COOLDOWNS = {}

def get_cooldown(api_key: str, model: str) -> float:
    return max(0, API_KEY_MODEL_COOLDOWNS.get((api_key, model), 0) - time.time())

def set_cooldown(api_key: str, model: str, wait_time: float):
    API_KEY_MODEL_COOLDOWNS[(api_key, model)] = time.time() + wait_time

def _clean_llm_content(content: str) -> str:
    content = content.strip()
    prefixes = ["Here is", "Here's", "Sure,", "Certainly,", "Of course,", "Here are", "Below is", "The following"]
    for p in prefixes:
        if content.lower().startswith(p.lower()):
            idx = content.find('\n')
            if idx != -1 and idx < 100:
                content = content[idx:].strip()
    return content

def call_groq_with_fallback(api_keys: list, prompt: str, max_tokens: int = 8000, proxy: Optional[dict] = None) -> tuple[str, dict]:
    """
    Call Groq API with robust multi-key, multi-model fallback and strict rate-limit handling.
    Creates a new connection per request to ensure rotating proxies assign a new IP.
    """
    max_retries = len(api_keys) * len(GROQ_MODELS) * 2
    
    for retry in range(max_retries):
        errors = []
        
        for config in api_keys:
            if not config.get('is_active') or config.get('provider') != 'groq':
                continue
                
            api_key = config['api_key']
            
            for model in GROQ_MODELS:
                if get_cooldown(api_key, model) > 0:
                    continue
                
                url = "https://api.groq.com/openai/v1/chat/completions"
                headers = {
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/json',
                    'Accept-Encoding': 'gzip, deflate'  # Compress bandwidth significantly
                }
                system_prompt = "You are a professional content writer. Write plain, natural prose. Output valid json if requested."
                
                data = {
                    'model': model,
                    'messages': [
                        {'role': 'system', 'content': system_prompt},
                        {'role': 'user', 'content': prompt}
                    ],
                    'max_tokens': max_tokens,
                    'temperature': 0.7,
                    'presence_penalty': 0.6,
                    'frequency_penalty': 0.1,
                    'response_format': {"type": "json_object"}
                }
                
                # We use a new session/request each time (requests.post) to ensure proxy IP rotation happens dynamically.
                try:
                    proxy_info = f"via {list(proxy.values())[0][:30]}..." if proxy else "DIRECT"
                    print(f"[LLM REQUEST] Groq/{model} [Key ending in {api_key[-4:]}] - {proxy_info}")
                    
                    response = requests.post(url, json=data, headers=headers, timeout=160, proxies=proxy)
                    
                    if response.status_code == 200:
                        try:
                            resp_json = response.json()
                        except ValueError:
                            print(f"Proxy returned 200 but invalid JSON: {response.text[:100]}...")
                            errors.append(f"Proxy/JSON Error")
                            continue
                            
                        content = _clean_llm_content(resp_json['choices'][0]['message']['content'])
                        bytes_received = len(response.content)
                        usage = resp_json.get('usage', {})
                        meta = {
                            'provider': 'groq',
                            'model': model,
                            'timestamp': time.time(),
                            'bytes_received': bytes_received,
                            'prompt_tokens': usage.get('prompt_tokens', 0),
                            'completion_tokens': usage.get('completion_tokens', 0)
                        }
                        return content, meta
                        
                    if response.status_code in (429, 503):
                        # Handle strict rate limits based on Groq headers
                        wait_time = 60
                        if 'retry-after' in response.headers:
                            try: wait_time = float(response.headers['retry-after'])
                            except: pass
                        elif 'x-ratelimit-reset-tokens' in response.headers:
                            try:
                                val = response.headers['x-ratelimit-reset-tokens']
                                match = re.search(r'(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?', val)
                                if match:
                                    m = int(match.group(1)) if match.group(1) else 0
                                    s = float(match.group(2)) if match.group(2) else 0
                                    wait_time = max(wait_time, m * 60 + s)
                            except: pass
                        elif 'x-ratelimit-reset-requests' in response.headers:
                            try:
                                val = response.headers['x-ratelimit-reset-requests']
                                match = re.search(r'(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?', val)
                                if match:
                                    m = int(match.group(1)) if match.group(1) else 0
                                    s = float(match.group(2)) if match.group(2) else 0
                                    wait_time = max(wait_time, m * 60 + s)
                            except: pass
                        
                        set_cooldown(api_key, model, wait_time + 1)
                        print(f"Groq API Key {api_key[-4:]} with {model} rate limited. Cooldown: {wait_time:.1f}s")
                        continue
                        
                    # If we get here, it's a non-200 and non-rate-limit error
                    print(f"Groq returned {response.status_code}: {response.text}")
                    response.raise_for_status()
                    
                except Exception as e:
                    print(f"Request failed for {model}: {e}. The rotating proxy might have failed. Will retry.")
                    errors.append(f"Proxy/Network Error: {str(e)}")
                    continue
                    
        # If we exhausted all keys and models for this attempt, let's wait min cooldown and retry
        wait_times = [get_cooldown(cfg['api_key'], m) for cfg in api_keys if cfg.get('is_active') and cfg.get('provider')=='groq' for m in GROQ_MODELS]
        valid_waits = [w for w in wait_times if w > 0]
        
        if valid_waits:
            min_wait = min(valid_waits)
            print(f"All Groq keys/models rate limited. Waiting {min_wait:.1f}s before retry...")
            time.sleep(min_wait + 1)
        elif errors:
            print("Network/proxy errors encountered. Waiting 5s before next attempt...")
            time.sleep(5)
            
    raise Exception("Failed to generate content after trying multiple keys and proxy rotations.")

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
    # to avoid hitting Groq's maximum output token limit (8K) before closing the JSON.
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
    
    mega_prompt = f"""You are a professional article writer. Write a comprehensive, highly-detailed, SEO-optimized article based exactly on these topics/questions:

{h2_list}

REQUIREMENTS:
1. Write an engaging title (50-70 characters).
2. Write an introduction (2-3 paragraphs) that hooks the reader.
3. Provide exactly 5-7 key takeaways (brief, actionable sentences).
4. Write extensive body sections based on the topics. Each section should be {para_req}.
5. Provide a FAQ section answering any questions from the list above. Each answer should be {faq_req}.

GOAL: The total final article should exceed 1500-2000 words in length. Extensively expand on every point.

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
        content_json_str, meta = call_llm_with_fallback(api_keys, mega_prompt, max_tokens=8000, proxy=proxy)
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

