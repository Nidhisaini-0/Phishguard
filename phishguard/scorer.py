import os
import re
import datetime
import ipaddress
from functools import lru_cache
from urllib.parse import urlparse

import requests
import tldextract

# Offline-safe: uses the suffix list bundled with the package
extractor = tldextract.TLDExtract(suffix_list_urls=())

USE_WHOIS = os.environ.get("PHISHGUARD_WHOIS", "1") == "1"

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "suspend", "wallet", "invoice",
    "ledger", "metamask", "airdrop", "claim", "recover", "unlock", "helpdesk",
]
RISKY_TLDS = {
    "xyz", "top", "click", "zip", "work", "support", "country", "gq", "tk", "ml", "cf", "ga",
    "icu", "buzz", "cyou", "cfd", "sbs", "rest", "bond", "quest", "monster", "beer", "vip",
    "biz.id", "my.id", "lol", "properties", "fun", "pw",
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
              "tiny.cc", "goo.su", "u.to", "py.md", "v.gd", "ow.ly", "buff.ly", "shorturl.at"}

# Free platforms where anyone can publish a page
FREE_HOSTS = {
    "pages.dev", "vercel.app", "netlify.app", "wasmer.app", "workers.dev", "github.io",
    "gitlab.io", "web.app", "firebaseapp.com", "weebly.com", "wixsite.com", "glitch.me",
    "repl.co", "onrender.com", "herokuapp.com", "blogspot.com", "000webhostapp.com",
    "godaddysites.com", "webflow.io", "carrd.co", "eu.cc", "flazio.com", "gitbook.io",
    "craftum.io", "azurefd.net", "r2.dev", "appspot.com", "webcindario.com", "edgeone.dev",
    "web.core.windows.net", "blob.core.windows.net",
}
# Trusted platforms where anyone can still publish a page
USER_CONTENT_HOSTS = {"sites.google.com", "docs.google.com", "drive.google.com"}

# Brand -> its real domains. Extend with brands your audience uses.
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "amazon": {"amazon.com", "amazon.in", "ssl-images-amazon.com", "media-amazon.com", "quip-amazon.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com"},
    "paytm": {"paytm.com"},
    "icicibank": {"icicibank.com"},
    "hdfcbank": {"hdfcbank.com"},
    "roblox": {"roblox.com"},
    "ledger": {"ledger.com"},
    "metamask": {"metamask.io"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "trezor": {"trezor.io"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
}
TRUSTED_DOMAINS = set().union(*BRANDS.values()) | {"wikipedia.org", "microsoftonline.com"}

# Look-alike character swaps: paypa1 -> paypal, g00gle -> google
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _levenshtein(a: str, b: str) -> int:
    """Number of single-letter edits needed to turn a into b."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def free_host_match(host: str):
    """Return the free-hosting platform this host belongs to, or None."""
    for h in FREE_HOSTS:
        if host.endswith("." + h):
            return h
    return None


def looks_random(label: str) -> bool:
    """Throwaway scam domains are often digits or consonant soup."""
    if label.isdigit() and len(label) >= 5:
        return True
    letters = re.sub(r"[^a-z]", "", label)
    if len(letters) >= 7:
        vowels = sum(c in "aeiou" for c in letters)
        return vowels / len(letters) < 0.2
    return False


def check_brand_impersonation(ext, skip_domain=False):
    """Return (points, reason) if the address imitates a known brand, else None.
    skip_domain=True is used for free-hosting platforms, whose own domain
    (e.g. github.io) is not an impersonation."""
    domain = ext.domain
    norm = domain.translate(LEET)
    sub_tokens = [t for t in re.split(r"[^a-z0-9]+", ext.subdomain.translate(LEET)) if t]

    for brand in BRANDS:
        if not skip_domain:
            max_edit = 2 if len(brand) >= 8 else 1
            if norm == brand and domain != brand:
                return 40, f"The name imitates '{brand}' by swapping letters for numbers."
            if domain == brand:
                # Brands own many country sites (google.de, amazon.in); skip unless the ending is risky
                if not (len(ext.suffix) == 2 and ext.suffix not in RISKY_TLDS):
                    return 25, f"It uses the '{brand}' name but is not the official {brand} website."
            elif len(brand) >= 5 and 0 < _levenshtein(norm, brand) <= max_edit:
                return 40, f"The name looks like a misspelling of '{brand}'."
            elif len(brand) >= 5 and brand in norm:
                return 30, f"The domain contains '{brand}' but is not the real {brand} website."
        for tok in sub_tokens:
            if tok == brand or (len(brand) >= 5 and (brand in tok or (len(tok) >= 5 and _levenshtein(tok, brand) <= 1))):
                return 35, f"The name '{brand}' appears at the front of an address that belongs to someone else."
    return None


@lru_cache(maxsize=512)
def get_domain_age_days(domain: str):
    """Days since registration via RDAP (works over HTTPS), or None if unavailable."""
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=5,
                         headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=datetime.timezone.utc)
                return (datetime.datetime.now(datetime.timezone.utc) - created).days
    except Exception:
        return None
    return None


def analyze_url(url: str) -> dict:
    score = 0
    reasons = []

    raw = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw  # assume http if no scheme given

    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
    except ValueError:
        host = ""

    if not host:
        return {"url": url, "score": 50, "verdict": "yellow",
                "reasons": ["This doesn't look like a valid web address."]}

    ext = extractor(host)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # Trusted platforms that host user-created pages
    if host in USER_CONTENT_HOSTS:
        return {"url": url, "score": 40, "verdict": "yellow",
                "reasons": ["This page is user-created content on a trusted platform. Anyone can publish here, "
                            "so the platform's reputation doesn't guarantee this page is safe."]}

    # Known official sites get a clean pass
    if registered in TRUSTED_DOMAINS:
        return {"url": url, "score": 0, "verdict": "green",
                "reasons": ["This is a recognized official website."]}

    def flag(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    is_ip = _is_ip(host)
    free = free_host_match(host)

    # 1. No HTTPS
    if parsed.scheme != "https":
        flag(15, "The site does not use a secure (HTTPS) connection.")

    # 2. IP address instead of a domain name
    if is_ip:
        flag(30, "The link uses a raw IP address instead of a normal website name.")

    # 3. '@' symbol
    if "@" in parsed.netloc:
        flag(25, "The link contains an '@' symbol, a trick used to hide the real destination.")

    # 4. Very long URL
    if len(raw) > 75:
        flag(10, "The link is unusually long, which can be used to hide suspicious parts.")

    # 5. Too many subdomains
    sub_count = len([s for s in ext.subdomain.split(".") if s]) if ext.subdomain else 0
    if sub_count >= 3:
        flag(15, "The address has many sub-sections (subdomains), a common disguise technique.")

    # 6. Hyphens or digits in the main domain
    if not is_ip and not free:
        if ext.domain.count("-") >= 2:
            flag(10, "The domain name contains several hyphens, which is common in fake sites.")
        if re.search(r"\d", ext.domain) and re.search(r"[a-z]", ext.domain):
            flag(10, "The domain mixes letters and numbers, like a look-alike spelling (e.g. paypa1).")

    # 7. Punycode (look-alike foreign characters)
    if "xn--" in host:
        flag(25, "The address uses special look-alike characters that can imitate a real brand.")

    # 8. Risky ending (top-level domain)
    if not is_ip and (ext.suffix in RISKY_TLDS or ext.suffix.split(".")[-1] in RISKY_TLDS):
        flag(15, f"The address ends in '.{ext.suffix}', which is often used in scam sites.")

    # 8b. Free hosting platform
    if free:
        flag(30, f"This page is hosted on a free public platform ({free}), where anyone can publish a fake page.")
        page_label = host[: -(len(free) + 1)]
        if page_label.count("-") >= 3:
            flag(10, "The page name is a long chain of hyphenated words, typical of mass-produced scam pages.")

    # 8c. Random-looking name
    if not is_ip and not free and looks_random(ext.domain):
        flag(15, "The website name looks randomly generated, like throwaway scam domains.")

    # 9. URL shortener
    if registered in SHORTENERS:
        flag(15, "This is a shortened link, so the real destination is hidden.")

    # 10. Suspicious keywords
    text = (host + parsed.path).lower()
    hits = [w for w in SUSPICIOUS_WORDS if w in text]
    if hits:
        flag(min(10 * len(hits), 25), f"The link contains pressure/credential words: {', '.join(hits[:3])}.")

    # 11. Brand impersonation
    if not is_ip:
        hit = check_brand_impersonation(ext, skip_domain=bool(free))
        if hit:
            flag(*hit)

    # 11b. Brand name inside the path (e.g. /microsoftonline/login on an unrelated site)
    path_text = (parsed.path + "?" + (parsed.query or "")).lower()
    for brand in BRANDS:
        if len(brand) >= 5 and brand in path_text and ext.domain != brand:
            flag(15, f"The link mentions '{brand}' in its path, but the website is not {brand}.")
            break

    # 11c. Long number strings in the path
    if re.search(r"\d{9,}", parsed.path):
        flag(10, "The link contains a long random number, common in generated scam pages.")

    # 12. Domain age (needs internet; skipped quietly if unavailable)
    if USE_WHOIS and not is_ip and not free and ext.suffix:
        age = get_domain_age_days(registered)
        if age is not None:
            if age < 30:
                flag(35, f"This website was created only {age} days ago. Scam sites are usually brand new.")
            elif age < 180:
                flag(15, "This website is less than 6 months old.")

    score = min(score, 100)
    verdict = "green" if score < 30 else "yellow" if score < 60 else "red"
    if not reasons:
        reasons.append("No suspicious patterns found in the link itself.")

    return {"url": url, "score": score, "verdict": verdict, "reasons": reasons}