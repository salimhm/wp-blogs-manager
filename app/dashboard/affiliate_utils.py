"""
affiliate_utils.py
Amazon Affiliate product insertion utilities.
"""

import re
import time
import random
import requests
from typing import Optional

# ── User-agents rotated per Amazon request ────────────────────────────────
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

# ── Amazon search URL ─────────────────────────────────────────────────────
_AMAZON_SEARCH_URL = "https://www.amazon.com/s"

# ── Redis cache TTL for keyword and product results ───────────────────────
_KEYWORD_CACHE_TTL = 60 * 60 * 24        # 24 hours
_PRODUCTS_CACHE_TTL = 60 * 60 * 24       # 24 hours

# Amazon's <head> alone is ~100KB of inline JS/CSS; products are in the body.
# Reading 400KB reliably captures search result listings.
_AMAZON_READ_LIMIT = 400 * 1024


# =============================================================================
# Groq keyword extraction
# =============================================================================

def extract_keywords_with_groq(title: str, content_snippet: str, api_keys: list, proxy: Optional[dict] = None) -> list[str]:
    """
    Use Groq to extract 1-2 precise Amazon product search queries for the article.
    Uses the same key rotation as article generation (call_groq_with_fallback).
    Returns a list of 1-2 keyword strings. Cached in Redis by title hash (24h).
    """
    from django.core.cache import cache
    import hashlib
    import json

    cache_key = f"affiliate_kw_{hashlib.md5(title.encode()).hexdigest()}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    from .utils import call_groq_with_fallback

    prompt = f"""You are an Amazon product search expert. Your job is to identify what physical products someone reading this article would most likely buy on Amazon.

Article title: {title}
Article preview: {content_snippet[:400]}

Rules:
- Output ONLY the JSON object below, nothing else
- The "keywords" array must contain 1 or 2 short Amazon search queries (2-5 words each)
- Queries must be SPECIFIC product names/types a person would search on Amazon to buy
- NEVER output question fragments, topic descriptions, or article titles as keywords
- Think: if someone reads this article, what would they open Amazon and search for?

Examples:
- "How to cook pork tenderloin?" → {{"keywords": ["pork tenderloin roast", "meat thermometer"]}}
- "Do hornets have natural predators?" → {{"keywords": ["hornet nest removal spray", "wasp trap outdoor"]}}
- "Best air fryer recipes" → {{"keywords": ["air fryer basket", "air fryer cookbook"]}}

Output:
{{"keywords": [...]}}"""

    try:
        result, _ = call_groq_with_fallback(
            api_keys=api_keys,
            prompt=prompt,
            max_tokens=80,
            proxy=proxy,
        )
        parsed = json.loads(result.strip())
        # response_format=json_object returns a dict — extract "keywords" key
        keywords = parsed.get('keywords', parsed)
        if isinstance(keywords, list):
            keywords = [k.strip() for k in keywords if isinstance(k, str) and k.strip()][:2]
            if keywords:
                cache.set(cache_key, keywords, timeout=_KEYWORD_CACHE_TTL)
                return keywords
    except Exception as e:
        print(f"[affiliate] Keyword extraction failed for '{title[:50]}': {e}")

    # Fallback: strip filler words from title and use remaining topic words
    filler = {'what', 'is', 'are', 'how', 'to', 'do', 'does', 'a', 'an', 'the',
              'can', 'will', 'should', 'would', 'could', 'have', 'has', 'any', 'some',
              'why', 'when', 'where', 'which', 'who', 'i', 'you', 'we', 'they', 'best'}
    words = [w for w in re.sub(r'[^a-zA-Z0-9 ]', '', title).lower().split()
             if w not in filler]
    fallback = [" ".join(words[:4])] if words else [title[:40]]
    cache.set(cache_key, fallback, timeout=_KEYWORD_CACHE_TTL)
    return fallback


# =============================================================================
# Amazon scraper
# =============================================================================

def scrape_amazon_products(keyword: str, affiliate_tag: str, proxy: Optional[dict] = None, max_products: int = 3) -> list[dict]:
    """
    Scrape the Amazon search results page for `keyword`.
    Returns a list of product dicts: {title, price, asin, image_url, affiliate_url}.
    Results are Redis-cached for 24h to avoid duplicate proxy requests.

    Bandwidth optimizations:
    - gzip compression via Accept-Encoding header
    - streams response and reads only first 80KB (search results are in the top of the page)
    - no JS engine — pure requests + BeautifulSoup
    - per-keyword Redis cache (24h TTL)
    """
    from django.core.cache import cache
    import hashlib

    cache_key = f"affiliate_products_{hashlib.md5(f'{keyword}:{max_products}:{affiliate_tag}'.encode()).hexdigest()}"
    cached = cache.get(cache_key)
    if cached is not None:
        print(f"[affiliate] Cache hit for '{keyword}'")
        return cached

    headers = {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",  # key bandwidth optimization
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }

    params = {
        "k": keyword,
        "ref": "nb_sb_noss",
    }

    products = []
    try:
        response = requests.get(
            _AMAZON_SEARCH_URL,
            params=params,
            headers=headers,
            proxies=proxy,
            timeout=20,
            stream=True,
        )

        # Stream response — smart early-stop:
        # Amazon's <head> is ~100KB of JS/CSS. After 150KB, start checking
        # how many real product ASINs (B0...) we've accumulated. Stop as
        # soon as we have 2x what we need (plenty to parse from).
        raw_bytes = b""
        products = []
        for chunk in response.iter_content(chunk_size=16384):
            raw_bytes += chunk
            if len(raw_bytes) > 150 * 1024:
                # Quick text probe — no BS4 needed, B-prefix ASIN is reliable
                asin_hits = raw_bytes.count(b'data-asin="B')
                if asin_hits >= max_products * 2:
                    break  # Have enough — stop reading
            if len(raw_bytes) >= _AMAZON_READ_LIMIT:
                break

        html = raw_bytes.decode("utf-8", errors="replace")

        # Detect CAPTCHA / bot wall
        captcha_signals = [
            "Enter the characters you see below",
            "api-services-support@amazon.com",
            "Type the characters you see in this image",
            "robot check",
            "automated access",
        ]
        for signal in captcha_signals:
            if signal.lower() in html.lower():
                print(f"[affiliate] Amazon CAPTCHA/block hit for '{keyword}': found '{signal}'")
                return []

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")

        # Count elements for debug
        all_asin_els = soup.select("[data-asin]")
        print(f"[affiliate][DEBUG] data-asin elements found: {len(all_asin_els)}")

        for item in all_asin_els:
            asin = item.get("data-asin", "").strip()
            if not asin or len(asin) != 10:
                continue

            title_el = item.select_one("h2 span") or item.select_one(".a-text-normal")
            if not title_el:
                continue
            title = title_el.get_text(strip=True)[:100]

            price_el = item.select_one(".a-price .a-offscreen") or item.select_one(".a-price-whole")
            price = price_el.get_text(strip=True) if price_el else ""

            img_el = item.select_one("img.s-image") or item.select_one("img[data-image-latency]")
            image_url = img_el.get("src", "") if img_el else ""

            products.append({
                "title": title,
                "price": price,
                "asin": asin,
                "image_url": image_url,
                "affiliate_url": f"https://www.amazon.com/dp/{asin}?tag={affiliate_tag}",
            })

            if len(products) >= max_products:
                break

    except Exception as e:
        print(f"[affiliate] Amazon scrape failed for '{keyword}': {e}")
        return []

    if products:
        cache.set(cache_key, products, timeout=_PRODUCTS_CACHE_TTL)
        print(f"[affiliate] Scraped {len(products)} products for '{keyword}'")
    else:
        print(f"[affiliate] No products found for '{keyword}'")

    return products


# =============================================================================
# HTML builder
# =============================================================================

def build_product_block_html(products: list[dict]) -> str:
    """
    Build a self-contained, inline-styled <div class="amazon-prd"> product block.
    Inline styles ensure it renders correctly on any WP theme without extra CSS.
    """
    if not products:
        return ""

    items_html = ""
    for p in products:
        img_tag = ""
        if p.get("image_url"):
            img_tag = (
                f'<img src="{p["image_url"]}" alt="{p["title"]}" loading="lazy" '
                f'style="width:100%;height:140px;object-fit:contain;margin-bottom:8px;">'
            )

        price_tag = ""
        if p.get("price"):
            price_tag = (
                f'<span style="display:block;font-weight:700;color:#B12704;font-size:15px;">'
                f'{p["price"]}</span>'
            )

        items_html += (
            f'<a href="{p["affiliate_url"]}" target="_blank" rel="nofollow sponsored noopener" '
            f'style="display:flex;flex-direction:column;align-items:center;text-decoration:none;'
            f'color:#111;background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;'
            f'flex:1;min-width:140px;max-width:200px;transition:box-shadow .2s;" '
            f'onmouseover="this.style.boxShadow=\'0 4px 12px rgba(0,0,0,.15)\'" '
            f'onmouseout="this.style.boxShadow=\'none\'">'
            f'{img_tag}'
            f'<span style="font-size:13px;text-align:center;margin-bottom:6px;line-height:1.3;">{p["title"][:80]}</span>'
            f'{price_tag}'
            f'<span style="margin-top:8px;font-size:12px;background:#FF9900;color:#111;'
            f'padding:5px 10px;border-radius:4px;font-weight:600;">View on Amazon</span>'
            f'</a>'
        )

    return (
        f'<div class="amazon-prd" style="margin:24px 0;padding:16px;background:#f9f9f9;'
        f'border:1px solid #e0e0e0;border-radius:10px;">'
        f'<p style="margin:0 0 12px;font-weight:700;font-size:15px;color:#333;">🛒 Recommended Products</p>'
        f'<div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">'
        f'{items_html}'
        f'</div>'
        f'<p style="margin:10px 0 0;font-size:10px;color:#999;text-align:right;">'
        f'As an Amazon Associate I earn from qualifying purchases.</p>'
        f'</div>'
    )


def strip_amazon_blocks(html: str) -> str:
    """
    Remove all <div class="amazon-prd"> product blocks from post content.
    Used when the affiliate tag has changed and blocks need to be replaced.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    for div in soup.find_all('div', class_='amazon-prd'):
        div.decompose()
    body = soup.find('body')
    return body.decode_contents() if body else soup.decode_contents()


def inject_into_content(original_html: str, product_block_html: str, insert_after_paragraph: int = 1) -> str:
    """
    Insert product_block_html at 3 positions:
      1. After paragraph N  (insert_after_paragraph, default = 1st)
      2. After the middle paragraph
      3. Appended at the very end of the content

    All positions are calculated on the original HTML so offsets are stable.
    Inserts highest-offset first to preserve lower positions.
    """
    if not product_block_html:
        return original_html

    pattern = re.compile(r'</p>', re.IGNORECASE)
    matches = list(pattern.finditer(original_html))

    if not matches:
        # No <p> tags — prepend + append
        return product_block_html + "\n" + original_html + "\n" + product_block_html

    total_paras = len(matches)

    # Position 1: after configured paragraph (1-based, clamped)
    idx1 = min(insert_after_paragraph, total_paras) - 1

    # Position 2: after middle paragraph (at least 2 paragraphs after idx1)
    idx2 = min(max(total_paras // 2, idx1 + 2), total_paras - 1)

    # Collect unique raw character positions from the ORIGINAL string (descending)
    raw_positions = sorted(
        {matches[i].end() for i in {idx1, idx2}},
        reverse=True,
    )

    # Insert blocks from the end of the string toward the beginning
    result = original_html
    for pos in raw_positions:
        result = result[:pos] + "\n" + product_block_html + "\n" + result[pos:]

    # Position 3: bottom of article
    result += "\n" + product_block_html

    return result


# =============================================================================
# WordPress helpers
# =============================================================================

def _wp_auth_headers(site, extra: dict = None) -> dict:
    """Build auth + compression headers for WP REST API calls."""
    from base64 import b64encode
    credentials = b64encode(f"{site.wp_username}:{site.wp_app_password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {credentials}",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers


def fetch_wp_posts_by_slugs(site, slugs: list[str]) -> list[dict]:
    """
    Fetch WP posts by slug, one at a time.
    Direct connection — no proxy needed since this is the user's own server.
    """
    headers = _wp_auth_headers(site)
    base_url = f"https://{site.domain}/wp-json/wp/v2/posts"
    posts = []

    for raw_slug in slugs:
        slug = raw_slug.strip().lstrip("/")
        if not slug:
            continue
        try:
            resp = requests.get(
                base_url,
                params={"slug": slug, "_fields": "id,slug,title,content", "status": "publish"},
                headers=headers,
                timeout=20,  # direct — no proxy
            )
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    posts.append(data[0])
                else:
                    print(f"[affiliate] Slug not found on WP: {slug}")
            else:
                print(f"[affiliate] WP returned {resp.status_code} for slug '{slug}'")
        except Exception as e:
            print(f"[affiliate] WP fetch error for slug '{slug}': {e}")

        time.sleep(0.2)

    return posts


def fetch_wp_post_by_slug(site, slug: str) -> Optional[dict]:
    """
    Fetch a single WP post by slug. Returns the post dict or None.
    Direct connection — no proxy needed since this is the user's own server.
    """
    headers = _wp_auth_headers(site)
    base_url = f"https://{site.domain}/wp-json/wp/v2/posts"
    try:
        resp = requests.get(
            base_url,
            params={"slug": slug, "_fields": "id,slug,title,content", "status": "publish"},
            headers=headers,
            timeout=20,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data[0] if data else None
    except Exception as e:
        print(f"[affiliate] WP fetch error for slug '{slug}': {e}")
    return None


def patch_wp_post_content(site, post_id: int, new_content: str) -> bool:
    """
    Update a WP post's content via REST API PATCH.
    Direct connection — no proxy needed since this is the user's own server.
    """
    headers = _wp_auth_headers(site)
    url = f"https://{site.domain}/wp-json/wp/v2/posts/{post_id}"
    try:
        resp = requests.patch(
            url,
            json={"content": new_content},
            headers=headers,
            timeout=30,  # direct — no proxy
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"[affiliate] WP patch failed for post {post_id}: {e}")
        return False
