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
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        result = response.json()
        
        if result.get('success'):
            zones = [{'id': z['id'], 'name': z['name']} for z in result.get('result', [])]
            return True, zones
        else:
            return False, []
            
    except Exception:
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
# SambaNova LLM Integration
# ============================================

import time
import re

# SambaNova text generation models
# Removed deprecated models (Llama 3.1-405B/70B, Qwen 72B)
SAMBANOVA_MODELS = [
    'Meta-Llama-3.3-70B-Instruct',
    'Meta-Llama-3.1-8B-Instruct', 
    # 'Qwen2.5-Coder-32B-Instruct',
    # 'QwQ-32B-Preview',
    'Llama-3.2-90B-Vision-Instruct',
    'Llama-3.2-11B-Vision-Instruct',
]

# Track when a model will be available again
SAMBANOVA_COOLDOWNS = {}
_sambanova_model_index = 0


def get_next_sambanova_model() -> Optional[str]:
    """Get next available SambaNova model in rotation."""
    global _sambanova_model_index
    now = time.time()
    
    attempts = 0
    while attempts < len(SAMBANOVA_MODELS):
        model = SAMBANOVA_MODELS[_sambanova_model_index % len(SAMBANOVA_MODELS)]
        cooldown_expiry = SAMBANOVA_COOLDOWNS.get(model, 0)
        
        if now >= cooldown_expiry:
            _sambanova_model_index += 1
            return model
            
        _sambanova_model_index += 1
        attempts += 1
    
    return None


def call_sambanova(api_key: str, prompt: str, max_tokens: int = 4096, proxy: Optional[dict] = None) -> str:
    """
    Call SambaNova API with smart model rotation and rate limit handling.
    Uses OpenAI-compatible endpoint.
    """
    max_attempts = len(SAMBANOVA_MODELS) * 2
    attempts = 0
    
    while attempts < max_attempts:
        attempts += 1
        model = get_next_sambanova_model()
        
        if not model:
            wait_times = [t - time.time() for t in SAMBANOVA_COOLDOWNS.values() if t > time.time()]
            min_wait = min(wait_times) if wait_times else 5
            raise Exception(f"All SambaNova models rate limited. Please wait {int(min_wait)} seconds.")

        url = "https://api.sambanova.ai/v1/chat/completions"
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        system_prompt = """You are a professional content writer. Follow these rules STRICTLY:
1. Write ONLY the requested content - no introductions like "Here is..." or "Sure, I can..."
2. Do NOT include any meta-commentary or instructions
3. Do NOT use markdown formatting (no **, ##, etc.)
4. Write in plain, natural prose
5. Be informative, engaging, and professional
6. Never mention that you are an AI or that this is generated content"""
        
        data = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': max_tokens,
            'temperature': 0.7,
        }
        
        proxies = proxy if proxy else None
        
        try:
            response = requests.post(url, json=data, headers=headers, timeout=180, proxies=proxies)
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                # Cleanup
                content = content.strip()
                prefixes_to_remove = [
                    "Here is", "Here's", "Sure,", "Certainly,", "Of course,",
                    "Here are", "Below is", "The following"
                ]
                for prefix in prefixes_to_remove:
                    if content.lower().startswith(prefix.lower()):
                        idx = content.find('\n')
                        if idx != -1 and idx < 100:
                            content = content[idx:].strip()
                return content
                
            # Handle rate limits
            if response.status_code == 429 or response.status_code == 503:
                error_body = response.json() if response.text else {}
                error_msg = error_body.get('error', {}).get('message', str(response.text))
                
                wait_time = 60  # Default 1 minute
                
                if 'Retry-After' in response.headers:
                    try:
                        wait_time = int(response.headers['Retry-After'])
                    except:
                        pass
                
                SAMBANOVA_COOLDOWNS[model] = time.time() + wait_time
                print(f"SambaNova model {model} rate limited. Cooldown: {wait_time:.1f}s")
                continue
            
            response.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            print(f"SambaNova request failed for {model}: {e}")
            continue

    raise Exception("Failed to generate content after trying multiple SambaNova models.")


# ============================================
# Groq LLM Integration
# ============================================

# Models for rotation (to avoid rate limits)
import time
import re

# Models for rotation (to avoid rate limits)
GROQ_MODELS = [
    'llama-3.3-70b-versatile',
    'moonshotai/kimi-k2-instruct',
    'moonshotai/kimi-k2-instruct-0905',
    'llama-3.1-8b-instant',
    'openai/gpt-oss-120b',
    'openai/gpt-oss-20b',
]

# Track when a model will be available again
# Format: {'model_name': timestamp_when_available}
MODEL_COOLDOWNS = {}

_model_index = 0

def get_next_model() -> Optional[str]:
    """
    Get next available model in rotation.
    Returns None if all models are on cooldown.
    """
    global _model_index
    now = time.time()
    
    # Try finding an available model
    start_index = _model_index
    attempts = 0
    
    while attempts < len(GROQ_MODELS):
        model = GROQ_MODELS[_model_index % len(GROQ_MODELS)]
        cooldown_expiry = MODEL_COOLDOWNS.get(model, 0)
        
        if now >= cooldown_expiry:
            _model_index += 1
            return model
            
        _model_index += 1
        attempts += 1
    
    return None


def call_groq(api_key: str, prompt: str, max_tokens: int = 4096, proxy: Optional[dict] = None) -> str:
    """
    Call Groq API with smart model rotation and rate limit handling.
    """
    # Max retries effectively becomes traversing the model list
    max_attempts = len(GROQ_MODELS) * 2  # Allow for some second chances
    attempts = 0
    
    while attempts < max_attempts:
        attempts += 1
        model = get_next_model()
        
        if not model:
            # All models on cooldown
            wait_times = [t - time.time() for t in MODEL_COOLDOWNS.values() if t > time.time()]
            min_wait = min(wait_times) if wait_times else 5
            raise Exception(f"All models rate limited. Please wait {int(min_wait)} seconds.")

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        system_prompt = """You are a professional content writer. Follow these rules STRICTLY:
1. Write ONLY the requested content - no introductions like "Here is..." or "Sure, I can..."
2. Do NOT include any meta-commentary or instructions
3. Do NOT use markdown formatting (no **, ##, etc.)
4. Write in plain, natural prose
5. Be informative, engaging, and professional
6. Never mention that you are an AI or that this is generated content"""
        
        data = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': max_tokens,
            'temperature': 0.7,
            'presence_penalty': 0.6,
            'frequency_penalty': 0.1
        }
        
        proxies = proxy if proxy else None
        
        try:
            response = requests.post(url, json=data, headers=headers, timeout=160, proxies=proxies)
            
            # Handle success
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                
                # Cleanup
                content = content.strip()
                prefixes_to_remove = [
                    "Here is", "Here's", "Sure,", "Certainly,", "Of course,",
                    "Here are", "Below is", "The following"
                ]
                for prefix in prefixes_to_remove:
                    if content.lower().startswith(prefix.lower()):
                        idx = content.find('\n')
                        if idx != -1 and idx < 100:
                            content = content[idx:].strip()
                return content
                
            # Handle rate limits
            if response.status_code == 429 or response.status_code == 503:
                error_body = response.json() if response.text else {}
                error_msg = error_body.get('error', {}).get('message', str(response.text))
                
                # Calculate wait time
                wait_time = 60  # Default 1 minute
                
                # Check Retry-After header
                if 'Retry-After' in response.headers:
                    try:
                        wait_time = int(response.headers['Retry-After'])
                    except:
                        pass
                
                # Parse message for time (e.g., "try again in 3m21s")
                match = re.search(r'try again in (\d+m)?(\d+(\.\d+)?)s', error_msg)
                if match:
                    minutes = int(match.group(1).replace('m', '')) if match.group(1) else 0
                    seconds = float(match.group(2))
                    wait_time = (minutes * 60) + seconds + 1 # Add buffer
                
                # Mark this specific model as rate limited
                MODEL_COOLDOWNS[model] = time.time() + wait_time
                print(f"Model {model} rate limited. Cooldown: {wait_time:.1f}s")
                continue # Try next model
            
            response.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            # For network-level errors, we might want to retry differently, 
            # but for now, let's treat it as a model failure and try another if available
            print(f"Request failed for {model}: {e}")
            continue

    raise Exception("Failed to generate content after trying multiple models.")

# ============================================
# Cerebras LLM Integration
# ============================================

# Cerebras models
CEREBRAS_MODELS = [
    'llama-3.3-70b',
    'llama3.1-8b',
	'gpt-oss-120b',
]

CEREBRAS_COOLDOWNS = {}
_cerebras_model_index = 0

def get_next_cerebras_model() -> Optional[str]:
    """Get next available Cerebras model in rotation."""
    global _cerebras_model_index
    now = time.time()
    
    attempts = 0
    while attempts < len(CEREBRAS_MODELS):
        model = CEREBRAS_MODELS[_cerebras_model_index % len(CEREBRAS_MODELS)]
        cooldown_expiry = CEREBRAS_COOLDOWNS.get(model, 0)
        
        if now >= cooldown_expiry:
            _cerebras_model_index += 1
            return model
            
        _cerebras_model_index += 1
        attempts += 1
    
    return None

def call_cerebras(api_key: str, prompt: str, max_tokens: int = 4096, proxy: Optional[dict] = None) -> str:
    """
    Call Cerebras API.
    """
    max_attempts = len(CEREBRAS_MODELS) * 2
    attempts = 0
    
    while attempts < max_attempts:
        attempts += 1
        model = get_next_cerebras_model()
        
        if not model:
            wait_times = [t - time.time() for t in CEREBRAS_COOLDOWNS.values() if t > time.time()]
            min_wait = min(wait_times) if wait_times else 5
            raise Exception(f"All Cerebras models rate limited. Please wait {int(min_wait)} seconds.")

        url = "https://api.cerebras.ai/v1/chat/completions"
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        system_prompt = """You are a professional content writer. Follow these rules STRICTLY:
1. Write ONLY the requested content - no introductions like "Here is..." or "Sure, I can..."
2. No meta-commentary
3. No markdown formatting
4. Plain, natural prose
5. Informative and professional"""
        
        data = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': max_tokens,
            'temperature': 0.7,
        }
        
        proxies = proxy if proxy else None
        
        try:
            response = requests.post(url, json=data, headers=headers, timeout=120, proxies=proxies)
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                return content.strip()
                
            if response.status_code == 429 or response.status_code == 503:
                wait_time = 60
                if 'Retry-After' in response.headers:
                    try:
                        wait_time = int(response.headers['Retry-After'])
                    except:
                        pass
                
                CEREBRAS_COOLDOWNS[model] = time.time() + wait_time
                print(f"Cerebras model {model} rate limited. Cooldown: {wait_time:.1f}s")
                continue
            
            response.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            print(f"Cerebras request failed for {model}: {e}")
            continue

    raise Exception("Failed to generate content after trying multiple Cerebras models.")


# ============================================
# Unified LLM Interface with Cross-Provider Fallback
# ============================================

def call_llm(api_key: str, prompt: str, max_tokens: int = 4096, proxy: Optional[dict] = None, provider: str = 'sambanova') -> str:
    """
    Call a single provider's LLM. Routes to provider-specific implementations.
    """
    if provider == 'sambanova':
        return call_sambanova(api_key, prompt, max_tokens, proxy)
    elif provider == 'groq':
        return call_groq(api_key, prompt, max_tokens, proxy)
    elif provider == 'cerebras':
        return call_cerebras(api_key, prompt, max_tokens, proxy)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")


def call_llm_with_fallback(api_keys: list, prompt: str, max_tokens: int = 4096, proxy: Optional[dict] = None) -> tuple[str, dict]:
    """
    Call LLM with automatic cross-provider fallback.
    Tries all available providers until one succeeds.
    
    Args:
        api_keys: List of dicts [{'provider': 'sambanova', 'api_key': '...', 'is_active': True}, ...]
        prompt: The prompt to send
        max_tokens: Maximum tokens to generate
        proxy: Optional proxy dict
        
    Returns: Tuple (content, metadata_dict) where metadata contains 'provider' and 'model'
    """
    
    max_retries = 3
    for retry in range(max_retries):
        errors = []
        
        # Sort keys by priority if needed, for now use order provided
        for config in api_keys:
            if not config.get('is_active'):
                continue
                
            provider = config['provider']
            api_key = config['api_key']
            
            try:
                content = call_llm(api_key, prompt, max_tokens, proxy, provider)
                
                meta = {
                    'provider': provider,
                    'model': 'auto-rotated',
                    'timestamp': time.time()
                }
                return content, meta
                
            except Exception as e:
                print(f"Provider {provider} failed: {e}")
                errors.append(f"{provider}: {str(e)}")
                continue
        
        # All providers failed this round - check if we should retry
        if retry < max_retries - 1:
            # Check if errors indicate rate limiting (temporary)
            is_rate_limited = any('rate limit' in err.lower() or 'wait' in err.lower() for err in errors)
            if is_rate_limited:
                # Try to extract wait time from error messages
                import re
                wait_times = []
                for err in errors:
                    match = re.search(r'wait (\d+)', err.lower())
                    if match:
                        wait_times.append(int(match.group(1)))
                
                # Use smallest wait time from errors, or default
                if wait_times:
                    wait_time = min(wait_times) + 5  # Add 5s buffer
                else:
                    wait_time = 30 + (retry * 15)  # Fallback: 30s, 45s, 60s
                
                # Cap at 2 minutes max per retry
                wait_time = min(wait_time, 120)
                
                print(f"All providers rate-limited. Waiting {wait_time}s before retry {retry + 2}/{max_retries}...")
                time.sleep(wait_time)
                continue
        
        # Not rate-limited or final retry - fail
        break
            
    raise Exception(f"All providers failed: {'; '.join(errors)}")


def ensure_complete(text: str, api_key: str, proxy: Optional[dict] = None, provider: str = 'sambanova') -> str:
    """
    Ensure text ends with proper punctuation. If not, continue generating.
    """
    if not text:
        return text

    # Check if text ends with terminal punctuation
    if text.strip()[-1] in '.!?':
        return text

    # Text is cut off - try to continue
    print(f"Text appears cut off: {text[-50:]}...")
    
    # Take the last 200 chars as context
    context = text[-200:]
    
    continue_prompt = f"""The following text was cut off. Complete the last sentence and add a concluding sentence if needed.
    
    Context: "...{context}"
    
    RULES:
    - Output ONLY the completion
    - Do not repeat the context
    - Ensure it flows naturally
    - Finish with a period."""
    
    try:
        completion = call_llm(api_key, continue_prompt, 200, proxy, provider).strip() 
        # Clean up if model repeated context
        if completion.startswith(context):
            completion = completion[len(context):]
        elif completion.startswith("..."):
            completion = completion[3:]
            
        full_text = text + " " + completion
        return full_text
    except Exception as e:
        print(f"Failed to complete text: {e}")
        return text + "."  # Fallback: just add a period


def ensure_complete_with_fallback(text: str, api_keys: list, proxy: Optional[dict] = None) -> str:
    """
    Ensure text ends with proper punctuation using multi-provider fallback.
    """
    if not text:
        return text

    # Check if text ends with terminal punctuation
    if text.strip()[-1] in '.!?':
        return text

    # Text is cut off - try to continue
    print(f"Text appears cut off: {text[-50:]}...")
    
    context = text[-200:]
    
    continue_prompt = f"""The following text was cut off. Complete the last sentence and add a concluding sentence if needed.
    
    Context: "...{context}"
    
    RULES:
    - Output ONLY the completion
    - Do not repeat the context
    - Ensure it flows naturally
    - Finish with a period."""
    
    try:
        completion, meta = call_llm_with_fallback(api_keys, continue_prompt, 200, proxy)
        completion = completion.strip() 
        if completion.startswith(context):
            completion = completion[len(context):]
        elif completion.startswith("..."):
            completion = completion[3:]
            
        full_text = text + " " + completion
        return full_text
    except Exception as e:
        print(f"Failed to complete text: {e}")
        return text + "."


def generate_article_content(h2s: list, api_keys: list, proxy: Optional[dict] = None) -> dict:
    """
    Generate a full article from H2 headings using LLM with cross-provider fallback.
    
    Structure:
    1. Title
    2. Introduction (2-3 paragraphs)
    3. Key Takeaways (styled box)
    4. Body sections (3-4 comprehensive sections)
    5. FAQ section (H2s with answers)
    
    Args:
        h2s: List of H2 headings/questions
        api_keys: List of API key configs [{'provider': '...', 'api_key': '...', 'is_active': True}, ...]
        proxy: Optional proxy dict for routing requests
    
    Returns: {title, introduction, key_takeaways, body_sections, faq, html, meta: {provider_usage: [...]}}
    """
    h2_list = '\n'.join([f'- {h2}' for h2 in h2s])
    generation_stats = []
    
    def _track(step_name, meta):
        if meta:
            meta['step'] = step_name
            generation_stats.append(meta)

    # Step 1: Determine topic and generate title
    title_prompt = f"""Create an SEO-optimized article title based on these topics:

{h2_list}

RULES:
- Output ONLY the title text
- No quotes, no punctuation at the end
- Make it compelling and click-worthy
- 50-70 characters ideal length"""
    
    title, t_meta = call_llm_with_fallback(api_keys, title_prompt, 100, proxy)
    _track('title', t_meta)
    
    title = title.strip().strip('"').strip("'").rstrip('.')
    
    # Validate title - fallback if empty or too short
    if not title or len(title) < 10:
        # Use first H2 as fallback title
        title = h2s[0] if h2s else "Article Topic"
    
    # Step 2: Write introduction
    intro_prompt = f"""Write an engaging introduction for an article titled "{title}".

REQUIREMENTS:
- Write exactly 2-3 paragraphs
- Hook the reader in the first sentence
- Preview what the article covers without listing topics
- Write in second person (you/your) where appropriate
- No headings, no bullet points
- Separate paragraphs with blank lines
- CRITICAL: Finish the last sentence completely."""
    
    introduction, i_meta = call_llm_with_fallback(api_keys, intro_prompt, 800, proxy)
    _track('introduction', i_meta)
    
    introduction = introduction.strip()
    introduction = ensure_complete_with_fallback(introduction, api_keys, proxy)
    
    # Step 3: Generate Key Takeaways
    takeaways_prompt = f"""Create exactly 6 key takeaways for an article about "{title}".

Topics covered:
{h2_list}

FORMAT RULES:
- Start each line with a dash (-)
- One takeaway per line
- Each takeaway should be 15-25 words
- Be specific and actionable
- No numbering, no introductory text
- Output ONLY the 6 takeaways, nothing else"""
    
    takeaways_raw, tk_meta = call_llm_with_fallback(api_keys, takeaways_prompt, 600, proxy)
    _track('takeaways', tk_meta)
    
    takeaways_raw = takeaways_raw.strip()
    
    # Parse takeaways - try multiple formats
    key_takeaways = []
    for line in takeaways_raw.split('\n'):
        line = line.strip()
        if not line:
            continue
        # Remove common prefixes
        line = line.lstrip('-').lstrip('•').lstrip('*').strip()
        line = line.lstrip('0123456789.').strip()
        if line and len(line) > 10:  # Must be at least 10 chars
            key_takeaways.append(line)
    
    # Ensure we have at least 4 takeaways
    if len(key_takeaways) < 4:
        print(f"Key takeaways parsing got only {len(key_takeaways)}, regenerating...")
        retry_prompt = f"""List 6 key points about "{title}". 
Write each point as a complete sentence on its own line.
Do not number them. Do not use bullet points. Just sentences."""
        
        retry_raw, r_meta = call_llm_with_fallback(api_keys, retry_prompt, 600, proxy)
        _track('takeaways_retry', r_meta)
        
        retry_raw = retry_raw.strip()
        key_takeaways = [line.strip() for line in retry_raw.split('\n') if line.strip() and len(line.strip()) > 15]
    
    key_takeaways = key_takeaways[:7]  # Cap at 7
    
    # Step 4: Generate 3-4 body sections
    sections_prompt = f"""Suggest 3-4 main section headings for an article titled "{title}".

The article should address:
{h2_list}

FORMAT:
- One heading per line
- No numbers, no dashes
- Headings should be 4-8 words each
- Make them descriptive and engaging"""
    
    sections_raw, s_meta = call_llm_with_fallback(api_keys, sections_prompt, 300, proxy)
    _track('sections_outline', s_meta)
    
    sections_raw = sections_raw.strip()
    section_headings = []
    for s in sections_raw.split('\n'):
        s = s.strip().lstrip('-').lstrip('•').strip()
        s = s.lstrip('0123456789.').strip()
        if s and len(s) > 5:
            section_headings.append(s)
    section_headings = section_headings[:4]
    
    # Fallback: If no section headings were parsed, use first 3-4 H2s as sections
    if not section_headings or len(section_headings) < 2:
        print(f"Section headings parsing failed, using H2s as fallback")
        section_headings = h2s[:4] if len(h2s) >= 4 else h2s[:3]
    
    body_sections = {}
    for heading in section_headings:
        section_prompt = f"""Write comprehensive content for this section of an article titled "{title}":

Section Topic: {heading}

REQUIREMENTS:
- Write 4-5 substantial paragraphs (at least 150 words per paragraph)
- Include practical tips, real examples, and actionable advice
- Write in a conversational but professional tone
- Separate paragraphs with blank lines
- Do NOT include the section heading in your response
- Do NOT use any markdown formatting (no **, ##, bullets, etc.)
- Write in plain prose only
- CRITICAL: Complete every sentence and paragraph fully. Do not stop mid-thought."""
        
        # Increased token limit to 2000 for more comprehensive sections
        content, c_meta = call_llm_with_fallback(api_keys, section_prompt, 2000, proxy)
        _track(f'section_{heading[:10]}', c_meta)
        
        content = content.strip()
        content = ensure_complete_with_fallback(content, api_keys, proxy)
        
        # Validate content is substantial (at least 200 chars)
        if len(content) < 200:
            print(f"Section '{heading}' content too short ({len(content)} chars), regenerating...")
            # Retry with more explicit prompt
            retry_prompt = f"""Write a detailed 4-paragraph explanation about: {heading}

Context: This is for an article titled "{title}"

Each paragraph should be 3-4 sentences. Write informative, helpful content with examples.
Do not use any formatting. Just plain paragraphs separated by blank lines."""
            
            content, cr_meta = call_llm_with_fallback(api_keys, retry_prompt, 2000, proxy)
            _track(f'section_retry_{heading[:10]}', cr_meta)
            
            content = content.strip()
            content = ensure_complete_with_fallback(content, api_keys, proxy)
        
        body_sections[heading] = content
    
    # Step 5: Answer each H2 as FAQ
    faq = {}
    for h2 in h2s:
        answer_prompt = f"""Provide a comprehensive answer to this question:

Question: {h2}

Article context: {title}

REQUIREMENTS:
- Write 2-3 paragraphs with detailed, helpful information
- Start directly with the answer (don't repeat the question)
- Include specific facts, examples, or statistics when relevant
- Write in an informative, authoritative tone
- Separate paragraphs with blank lines
- Do NOT use bullet points, lists, or any formatting
- Write in plain prose only
- CRITICAL: Complete every sentence fully."""
        
        # Increased token limit to 1000 for comprehensive answers
        answer, a_meta = call_llm_with_fallback(api_keys, answer_prompt, 1000, proxy)
        _track(f'faq_{h2[:10]}', a_meta)
        
        answer = answer.strip()
        answer = ensure_complete_with_fallback(answer, api_keys, proxy)
        faq[h2] = answer
    
    # Step 6: Build HTML with CSS classes
    html_parts = []
    
    # Introduction
    intro_paragraphs = [p.strip() for p in introduction.split('\n') if p.strip()]
    html_parts.append('<div class="article-intro">')
    for p in intro_paragraphs:
        html_parts.append(f'<p>{p}</p>')
    html_parts.append('</div>')
    
    # Key Takeaways Box
    if key_takeaways:
        html_parts.append('<div class="key-takeaways">')
        html_parts.append('<h2 class="takeaways-title">🔑 Key Takeaways</h2>')
        html_parts.append('<ul class="takeaways-list">')
        for takeaway in key_takeaways:
            html_parts.append(f'<li>{takeaway}</li>')
        html_parts.append('</ul>')
        html_parts.append('</div>')
    
    # Search for YouTube videos related to the article title
    youtube_videos = search_youtube(title, max_results=2)
    video_1 = youtube_videos[0]['embed_html'] if len(youtube_videos) > 0 else ''
    video_2 = youtube_videos[1]['embed_html'] if len(youtube_videos) > 1 else ''
    
    # Body Sections - insert first video after the first section
    section_idx = 0
    for heading, content in body_sections.items():
        html_parts.append(f'<h2 class="section-heading">{heading}</h2>')
        html_parts.append('<div class="section-content">')
        paragraphs = [p.strip() for p in content.split('\n') if p.strip()]
        for p in paragraphs:
            html_parts.append(f'<p>{p}</p>')
        html_parts.append('</div>')
        
        # Insert first YouTube video after first body section
        if section_idx == 0 and video_1:
            html_parts.append(video_1)
        section_idx += 1
    
    # FAQ Section - insert second video after 3rd FAQ
    if faq:
        html_parts.append('<div class="faq-section">')
        html_parts.append('<h2 class="faq-title">❓ Frequently Asked Questions</h2>')
        faq_idx = 0
        for h2, answer in faq.items():
            html_parts.append('<div class="faq-item">')
            html_parts.append(f'<h3 class="faq-question">{h2}</h3>')
            answer_paragraphs = [p.strip() for p in answer.split('\n') if p.strip()]
            html_parts.append('<div class="faq-answer">')
            for p in answer_paragraphs:
                html_parts.append(f'<p>{p}</p>')
            html_parts.append('</div>')
            html_parts.append('</div>')
            
            # Insert second YouTube video after 3rd FAQ
            if faq_idx == 2 and video_2:
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

