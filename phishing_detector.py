"""
phishing_detector.py
=====================

A hybrid, rule-based phishing detection engine for emails.

This module exposes a single public entry point, :func:`detect_phishing`,
which analyzes an email's sender, subject, body, and embedded URLs and
returns a structured risk assessment.

Design goals
------------
* Standard-library only (``re``, ``urllib.parse``, ``ipaddress``, ``string``).
* Modular: each analysis category (sender / subject / body / url) is its
  own set of small, single-purpose helper functions.
* Configurable: every rule's score contribution is a named constant in
  the ``*_WEIGHTS`` dictionaries near the top of the file, so tuning or
  adding rules does not require touching the detection logic.
* Defensive: malformed / missing / non-string input never raises an
  exception -- it degrades gracefully and is simply treated as "no
  signal" for that field.

Example
-------
>>> result = detect_phishing(
...     sender="PayPal Security <security@paypa1-verify.com>",
...     subject="URGENT: Your account has been suspended!!!",
...     body="Please verify your account by clicking the link below.",
...     urls=["http://192.168.1.5/login?verify=1"],
... )
>>> result["risk_level"]
'Critical'
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse, parse_qs

__all__ = ["detect_phishing"]


# ======================================================================
# Configuration: keyword lists, weights, and thresholds
# ======================================================================
# Every rule below contributes a fixed number of points to the overall
# 0-100 score. Adjusting detection sensitivity should only ever require
# editing the constants in this section.

# ---- Sender analysis --------------------------------------------------

#: Free / consumer webmail providers. Legitimate businesses rarely send
#: official account or security notices from these domains.
FREE_EMAIL_PROVIDERS: frozenset[str] = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "mail.com", "gmx.com", "zoho.com", "yandex.com",
    "protonmail.com", "live.com", "msn.com",
})

#: Well-known brand names that are frequently impersonated, mapped to
#: their legitimate root domain(s). Used to flag lookalike domains and
#: free-mail impersonation.
PROTECTED_BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com"}),
    "amazon": frozenset({"amazon.com"}),
    "apple": frozenset({"apple.com"}),
    "microsoft": frozenset({"microsoft.com", "office.com", "live.com"}),
    "google": frozenset({"google.com", "gmail.com"}),
    "netflix": frozenset({"netflix.com"}),
    "bankofamerica": frozenset({"bankofamerica.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "chase": frozenset({"chase.com"}),
    "irs": frozenset({"irs.gov"}),
    "linkedin": frozenset({"linkedin.com"}),
    "facebook": frozenset({"facebook.com"}),
    "dhl": frozenset({"dhl.com"}),
    "usps": frozenset({"usps.com"}),
}

#: Character substitutions commonly used to build lookalike domains
#: (e.g. "paypa1.com" instead of "paypal.com").
LOOKALIKE_SUBSTITUTIONS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "$": "s", "8": "b",
}

SENDER_WEIGHTS: dict[str, int] = {
    "lookalike_domain": 30,
    "free_email_brand_impersonation": 22,
    "display_name_email_mismatch": 18,
    "reply_to_mismatch": 20,
    "malformed_sender": 8,
}

# ---- Subject analysis --------------------------------------------------

URGENCY_WORDS: frozenset[str] = frozenset({
    "urgent", "immediately", "action required", "expire", "expires",
    "expiring", "deadline", "final notice", "act now", "asap",
    "time sensitive", "response required",
})

FEAR_WORDS: frozenset[str] = frozenset({
    "suspended", "locked", "unauthorized", "compromised", "breach",
    "terminate", "terminated", "penalty", "restricted", "disabled",
    "unusual activity", "security alert",
})

CREDENTIAL_WORDS: frozenset[str] = frozenset({
    "password", "login", "log in", "sign in", "credentials",
    "verify your account", "confirm your identity", "username",
})

FINANCIAL_SCAM_WORDS: frozenset[str] = frozenset({
    "invoice", "payment", "wire transfer", "refund", "tax refund",
    "prize", "lottery", "winner", "congratulations you", "claim your",
})

PASSWORD_RESET_WORDS: frozenset[str] = frozenset({
    "reset your password", "password will expire", "password expired",
    "reset password", "update your password",
})

SUBJECT_WEIGHTS: dict[str, int] = {
    "urgency": 10,
    "fear": 12,
    "credential_request": 14,
    "financial_scam": 12,
    "password_reset_scam": 14,
    "excessive_caps": 8,
    "multiple_exclamations": 6,
}

# Ratio of uppercase-to-alphabetic characters above which a subject is
# considered "shouting". Only evaluated for subjects of a minimum length
# to avoid false positives on short strings (e.g. "FYI").
CAPS_RATIO_THRESHOLD: float = 0.6
CAPS_MIN_LENGTH: int = 8

# ---- Body analysis -------------------------------------------------------

SOCIAL_ENGINEERING_PHRASES: frozenset[str] = frozenset({
    "verify your identity", "confirm your details", "unusual activity",
    "click below", "click the link below", "act now",
    "failure to comply", "avoid suspension", "limited time offer",
})

CREDENTIAL_HARVESTING_PHRASES: frozenset[str] = frozenset({
    "enter your password", "login here", "update your billing information",
    "confirm your password", "re-enter your credentials",
    "enter your ssn", "enter your social security",
})

FAKE_VERIFICATION_PHRASES: frozenset[str] = frozenset({
    "verify your account", "confirm your email", "validate your account",
    "confirm your account", "verify now",
})

BANKING_WORDS: frozenset[str] = frozenset({
    "account number", "routing number", "swift code", "iban",
    "wire transfer", "bank account", "sort code",
})

CRYPTO_SCAM_WORDS: frozenset[str] = frozenset({
    "bitcoin", "crypto", "wallet address", "investment opportunity",
    "guaranteed returns", "double your money", "ethereum", "usdt",
})

INVOICE_SCAM_WORDS: frozenset[str] = frozenset({
    "invoice attached", "overdue invoice", "payment due",
    "outstanding balance", "invoice #", "past due",
})

GIFT_CARD_SCAM_WORDS: frozenset[str] = frozenset({
    "gift card", "itunes card", "google play card", "amazon gift card",
    "steam card", "gift cards as payment",
})

BODY_WEIGHTS: dict[str, int] = {
    "social_engineering": 10,
    "credential_harvesting": 20,
    "fake_verification": 14,
    "banking_keywords": 10,
    "crypto_scam": 14,
    "invoice_scam": 8,
    "gift_card_scam": 16,
    "spam_indicators": 8,
    "suspicious_html": 16,
}

# Regex for a "Reply-To:" style header that may be embedded in the body
# (some mail clients / test harnesses surface raw headers in the body).
REPLY_TO_HEADER_RE = re.compile(r"reply-to\s*:\s*.*?([\w.+-]+@[\w.-]+)", re.IGNORECASE)

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
DISPLAY_NAME_SENDER_RE = re.compile(r"^\s*(?P<name>.*?)\s*<\s*(?P<email>[^<>@\s]+@[^<>\s]+)\s*>\s*$")

# ---- URL analysis ---------------------------------------------------------

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
})

SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "club", "work", "support", "click", "link", "gq",
    "tk", "ml", "cf", "ga", "info", "loan", "download", "zip", "review",
})

REDIRECT_QUERY_KEYS: frozenset[str] = frozenset({
    "url", "redirect", "redirect_uri", "next", "continue", "returnurl",
    "return_to", "dest", "destination", "target",
})

SUSPICIOUS_QUERY_KEYS: frozenset[str] = frozenset({
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "password", "token", "session",
})

URL_LONG_LENGTH_THRESHOLD: int = 75
URL_MAX_SUBDOMAIN_LABELS: int = 3   # e.g. a.b.c.example.com -> 3 labels before "example"
URL_MAX_HYPHENS: int = 3

URL_WEIGHTS: dict[str, int] = {
    "insecure_scheme": 6,
    "ip_address_host": 18,
    "url_shortener": 12,
    "excessively_long": 8,
    "too_many_subdomains": 10,
    "suspicious_tld": 12,
    "redirect_parameter": 14,
    "at_symbol": 20,
    "excessive_hyphens": 8,
    "hex_or_encoded_host": 14,
    "suspicious_query_params": 8,
}

# ---- Overall scoring / classification -------------------------------------

#: Category weight multipliers applied when combining the four raw
#: category scores into the final 0-100 score. Values sum to 1.0 so the
#: blended result stays in the same 0-100 range as each category.
CATEGORY_BLEND_WEIGHTS: dict[str, float] = {
    "sender": 0.25,
    "subject": 0.20,
    "body": 0.30,
    "url": 0.25,
}

#: Score (inclusive lower bound) -> risk level, evaluated highest-first.
RISK_THRESHOLDS: list[tuple[int, str]] = [
    (80, "Critical"),
    (55, "High"),
    (30, "Medium"),
    (10, "Low"),
    (0, "Safe"),
]

RISK_RECOMMENDATIONS: dict[str, str] = {
    "Safe": "Allow",
    "Low": "Allow (Monitor)",
    "Medium": "Flag for Review",
    "High": "Block",
    "Critical": "Block and Report",
}


# ======================================================================
# Generic helpers
# ======================================================================

def _safe_str(value: Any) -> str:
    """Coerce arbitrary input into a safe, stripped string.

    Never raises: non-string / ``None`` input becomes an empty string.
    """
    if not isinstance(value, str):
        return ""
    return value.strip()


def _safe_url_list(urls: Any) -> list[str]:
    """Coerce arbitrary input into a list of non-empty URL strings."""
    if not isinstance(urls, (list, tuple, set)):
        return []
    return [u.strip() for u in urls if isinstance(u, str) and u.strip()]


def _contains_any(text: str, phrases: frozenset[str]) -> list[str]:
    """Return the subset of ``phrases`` found as substrings of ``text``.

    ``text`` is expected to already be lower-cased by the caller.
    """
    return [phrase for phrase in phrases if phrase in text]


def _cap(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp ``value`` into the inclusive range [lo, hi]."""
    return max(lo, min(hi, value))


class _Findings:
    """Accumulates weighted score contributions and human-readable reasons
    for a single analysis category (sender, subject, body, or url).

    Keeping this bookkeeping in one small class avoids duplicating the
    "add points + record reason + record feature flag" pattern across
    every rule in every category.
    """

    def __init__(self) -> None:
        self.score: int = 0
        self.reasons: list[str] = []
        self.features: dict[str, Any] = {}

    def add(self, feature_name: str, weight: int, reason: str, detail: Any = True) -> None:
        """Record a triggered rule: bump the score, log the reason, and
        store a feature flag/detail for the detected_features report.
        """
        self.score += weight
        self.reasons.append(reason)
        self.features[feature_name] = detail

    def set_feature(self, feature_name: str, detail: Any) -> None:
        """Record a feature value without contributing to the score
        (used for informational, non-scored data points).
        """
        self.features[feature_name] = detail


# ======================================================================
# Sender analysis
# ======================================================================

def _extract_domain(email_address: str) -> str:
    """Return the lower-cased domain portion of an email address, or ''
    if it cannot be parsed.
    """
    match = EMAIL_RE.search(email_address)
    if not match:
        return ""
    return match.group(0).rsplit("@", 1)[-1].lower()


def _parse_sender(sender: str) -> tuple[str, str]:
    """Split a sender header of the form ``"Display Name <addr@domain>"``
    into ``(display_name, email_address)``.

    Falls back gracefully if the sender is a bare email address or an
    unparsable string.
    """
    match = DISPLAY_NAME_SENDER_RE.match(sender)
    if match:
        return match.group("name").strip(' "\''), match.group("email").strip()

    # No angle-bracket display name; try to find a bare email address.
    bare_match = EMAIL_RE.search(sender)
    if bare_match:
        return "", bare_match.group(0)

    return sender, ""


def _is_lookalike_of(domain: str, brand: str, official_domains: frozenset[str]) -> bool:
    """Heuristically determine whether ``domain`` is a lookalike / typosquat
    of ``brand`` (e.g. "paypa1-secure.com" for brand "paypal").
    """
    if domain in official_domains:
        return False

    root_label = domain.split(".")[0]
    normalized = root_label
    for digit, letter in LOOKALIKE_SUBSTITUTIONS.items():
        normalized = normalized.replace(digit, letter)

    # Brand name embedded in a domain that is NOT the official domain is
    # itself suspicious (e.g. "paypal-security-check.com").
    if brand in root_label or brand in normalized:
        return True

    return False


def analyze_sender(sender: str, body: str) -> _Findings:
    """Analyze the sender header for spoofing / impersonation indicators.

    Parameters
    ----------
    sender:
        Raw sender string, e.g. ``"PayPal <service@paypal.com>"``.
    body:
        Email body, scanned best-effort for an embedded ``Reply-To:``
        header to detect reply-to/sender domain mismatches.
    """
    findings = _Findings()
    sender = _safe_str(sender)

    if not sender:
        findings.add("malformed_sender", SENDER_WEIGHTS["malformed_sender"],
                     "Sender field is empty or missing.")
        return findings

    display_name, email_address = _parse_sender(sender)
    domain = _extract_domain(email_address) if email_address else ""

    if not domain:
        findings.add("malformed_sender", SENDER_WEIGHTS["malformed_sender"],
                     "Sender does not contain a parsable email address.")
        return findings

    findings.set_feature("sender_domain", domain)
    findings.set_feature("display_name", display_name)

    display_lower = display_name.lower()

    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_mentioned_in_name = brand in display_lower
        brand_mentioned_in_domain = brand in domain

        # Lookalike domain: brand referenced (in name or domain) but the
        # actual sending domain is a typosquat / near-miss of the brand.
        if (brand_mentioned_in_name or brand_mentioned_in_domain) and \
                _is_lookalike_of(domain, brand, official_domains):
            findings.add(
                "lookalike_domain",
                SENDER_WEIGHTS["lookalike_domain"],
                f"Sender domain '{domain}' appears to impersonate '{brand}' "
                f"but does not match its official domain(s).",
                detail=domain,
            )
            break  # one lookalike match is enough signal

    # Free-mail impersonation: display name claims to be a known brand,
    # but the email is sent from a free consumer webmail provider.
    if domain in FREE_EMAIL_PROVIDERS:
        for brand in PROTECTED_BRANDS:
            if brand in display_lower:
                findings.add(
                    "free_email_brand_impersonation",
                    SENDER_WEIGHTS["free_email_brand_impersonation"],
                    f"Display name references '{brand}' but the email was "
                    f"sent from a free email provider ('{domain}').",
                    detail=domain,
                )
                break

    # Display-name / email mismatch: the display name itself contains an
    # email address that differs from the actual sending address.
    embedded_email_match = EMAIL_RE.search(display_name)
    if embedded_email_match and embedded_email_match.group(0).lower() != email_address.lower():
        findings.add(
            "display_name_email_mismatch",
            SENDER_WEIGHTS["display_name_email_mismatch"],
            "Display name contains an email address different from the "
            "actual sending address.",
            detail=embedded_email_match.group(0),
        )

    # Reply-To mismatch: best-effort extraction of a Reply-To header
    # embedded in the body, compared against the sender's domain.
    reply_to_match = REPLY_TO_HEADER_RE.search(body)
    if reply_to_match:
        reply_domain = _extract_domain(reply_to_match.group(1))
        findings.set_feature("reply_to_domain", reply_domain)
        if reply_domain and reply_domain != domain:
            findings.add(
                "reply_to_mismatch",
                SENDER_WEIGHTS["reply_to_mismatch"],
                f"Reply-To domain '{reply_domain}' differs from the sender "
                f"domain '{domain}'.",
                detail=reply_domain,
            )

    return findings


# ======================================================================
# Subject analysis
# ======================================================================

def analyze_subject(subject: str) -> _Findings:
    """Analyze the email subject line for social-engineering indicators."""
    findings = _Findings()
    subject = _safe_str(subject)

    if not subject:
        return findings

    subject_lower = subject.lower()

    rule_table: list[tuple[str, frozenset[str], str]] = [
        ("urgency", URGENCY_WORDS, "Subject contains urgency language"),
        ("fear", FEAR_WORDS, "Subject contains fear-based / threatening language"),
        ("credential_request", CREDENTIAL_WORDS, "Subject requests credentials or login action"),
        ("financial_scam", FINANCIAL_SCAM_WORDS, "Subject contains financial-scam language"),
        ("password_reset_scam", PASSWORD_RESET_WORDS, "Subject mimics a password-reset notice"),
    ]

    for feature_name, wordlist, reason_prefix in rule_table:
        hits = _contains_any(subject_lower, wordlist)
        if hits:
            findings.add(
                feature_name,
                SUBJECT_WEIGHTS[feature_name],
                f"{reason_prefix}: {', '.join(sorted(hits))}.",
                detail=hits,
            )

    # Excessive capitalization ("shouting").
    letters = [c for c in subject if c.isalpha()]
    if len(subject) >= CAPS_MIN_LENGTH and letters:
        caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if caps_ratio >= CAPS_RATIO_THRESHOLD:
            findings.add(
                "excessive_caps",
                SUBJECT_WEIGHTS["excessive_caps"],
                f"Subject is written mostly in capital letters "
                f"({caps_ratio:.0%} of letters).",
                detail=round(caps_ratio, 2),
            )

    # Multiple exclamation marks.
    exclamation_count = subject.count("!")
    if exclamation_count >= 2:
        findings.add(
            "multiple_exclamations",
            SUBJECT_WEIGHTS["multiple_exclamations"],
            f"Subject contains {exclamation_count} exclamation marks.",
            detail=exclamation_count,
        )

    return findings


# ======================================================================
# Body analysis
# ======================================================================

#: Simple HTML patterns associated with phishing (hidden content, mismatched
#: link text/href, inline event handlers, obfuscated styling).
HTML_ANCHOR_RE = re.compile(r'<a\b[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
HTML_HIDDEN_RE = re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0', re.IGNORECASE)
HTML_ONEVENT_RE = re.compile(r'\son\w+\s*=\s*["\']', re.IGNORECASE)
TAG_TEXT_RE = re.compile(r'<[^>]+>')


def _detect_suspicious_html(body: str) -> list[str]:
    """Detect suspicious HTML patterns embedded in an email body.

    Looks for: anchor text/href domain mismatches, hidden elements used
    to conceal content from the reader, and inline JavaScript event
    handlers (onclick, onload, etc.).
    """
    issues: list[str] = []

    for href, link_text in HTML_ANCHOR_RE.findall(body):
        visible_text = TAG_TEXT_RE.sub("", link_text).strip()
        href_domain = _extract_domain(href) or urlparse(href).netloc.lower()
        # If the visible text itself looks like a URL/domain but doesn't
        # match where the link actually points, that's a classic
        # "text says one thing, link goes elsewhere" phishing trick.
        text_domain_match = re.search(r'([\w-]+\.[\w.-]+)', visible_text)
        if text_domain_match and href_domain and text_domain_match.group(1).lower() not in href_domain \
                and href_domain not in text_domain_match.group(1).lower():
            issues.append(f"link text '{visible_text}' does not match its target '{href}'")

    if HTML_HIDDEN_RE.search(body):
        issues.append("hidden or zero-size HTML elements detected")

    if HTML_ONEVENT_RE.search(body):
        issues.append("inline JavaScript event handler detected")

    return issues


def analyze_body(body: str) -> _Findings:
    """Analyze the email body for social-engineering, scam, and spam
    indicators, including basic suspicious-HTML detection.
    """
    findings = _Findings()
    body = _safe_str(body)

    if not body:
        return findings

    body_lower = body.lower()

    rule_table: list[tuple[str, frozenset[str], str]] = [
        ("social_engineering", SOCIAL_ENGINEERING_PHRASES, "Body contains social-engineering phrasing"),
        ("credential_harvesting", CREDENTIAL_HARVESTING_PHRASES, "Body attempts to harvest credentials"),
        ("fake_verification", FAKE_VERIFICATION_PHRASES, "Body contains a fake verification request"),
        ("banking_keywords", BANKING_WORDS, "Body references sensitive banking details"),
        ("crypto_scam", CRYPTO_SCAM_WORDS, "Body contains cryptocurrency-scam language"),
        ("invoice_scam", INVOICE_SCAM_WORDS, "Body mimics an invoice/payment-due scam"),
        ("gift_card_scam", GIFT_CARD_SCAM_WORDS, "Body requests payment via gift cards"),
    ]

    for feature_name, wordlist, reason_prefix in rule_table:
        hits = _contains_any(body_lower, wordlist)
        if hits:
            findings.add(
                feature_name,
                BODY_WEIGHTS[feature_name],
                f"{reason_prefix}: {', '.join(sorted(hits))}.",
                detail=hits,
            )

    # Grammar / spam indicators: runs of repeated punctuation, excessive
    # non-alphanumeric character density, or long stretches of capitals.
    spam_signals: list[str] = []
    if re.search(r'[!?]{3,}', body):
        spam_signals.append("repeated punctuation (e.g. '!!!' or '???')")
    if re.search(r'\b[A-Z]{6,}\b', body):
        spam_signals.append("long all-capitals words")
    non_alnum_ratio = sum(1 for c in body if not (c.isalnum() or c.isspace())) / len(body)
    if non_alnum_ratio > 0.15:
        spam_signals.append(f"high symbol density ({non_alnum_ratio:.0%})")

    if spam_signals:
        findings.add(
            "spam_indicators",
            BODY_WEIGHTS["spam_indicators"],
            f"Body shows spam/grammar red flags: {', '.join(spam_signals)}.",
            detail=spam_signals,
        )

    html_issues = _detect_suspicious_html(body)
    if html_issues:
        findings.add(
            "suspicious_html",
            BODY_WEIGHTS["suspicious_html"],
            f"Body contains suspicious HTML: {', '.join(html_issues)}.",
            detail=html_issues,
        )

    return findings


# ======================================================================
# URL analysis
# ======================================================================

def _is_ip_host(host: str) -> bool:
    """Return True if ``host`` is a literal IPv4/IPv6 address."""
    host = host.strip("[]")  # strip IPv6 brackets, if present
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_hex_or_encoded_host(host: str) -> bool:
    """Detect hosts written as decimal/hex-encoded IPs (e.g.
    ``0x7f000001`` or a pure-digit "dotless" IP like ``2130706433``),
    a common obfuscation trick to hide the true destination.
    """
    stripped = host.replace(".", "")
    if re.fullmatch(r'0x[0-9a-fA-F]+', host):
        return True
    if stripped.isdigit() and len(stripped) >= 8:
        return True
    return False


def _analyze_single_url(url: str) -> tuple[int, list[str], dict[str, Any]]:
    """Run all URL-level rules against a single URL.

    Returns
    -------
    (score_contribution, reasons, feature_detail)
    """
    score = 0
    reasons: list[str] = []
    detail: dict[str, Any] = {"url": url}

    try:
        parsed = urlparse(url)
    except ValueError:
        reasons.append(f"URL could not be parsed: '{url}'.")
        return URL_WEIGHTS["hex_or_encoded_host"], reasons, detail

    scheme = parsed.scheme.lower()
    # netloc may contain userinfo (user:pass@host) and port; split it apart.
    netloc = parsed.netloc
    host = parsed.hostname or ""
    host = host.lower()

    # --- '@' symbol trick: "https://trusted.com@evil.com/..." -------------
    if "@" in netloc:
        score += URL_WEIGHTS["at_symbol"]
        reasons.append(f"URL uses '@' to disguise its real destination: '{url}'.")
        detail["at_symbol"] = True

    # --- Insecure scheme -----------------------------------------------
    if scheme == "http":
        score += URL_WEIGHTS["insecure_scheme"]
        reasons.append(f"URL uses insecure HTTP instead of HTTPS: '{url}'.")
        detail["insecure_scheme"] = True

    # --- IP-address host -------------------------------------------------
    if host and _is_ip_host(host):
        score += URL_WEIGHTS["ip_address_host"]
        reasons.append(f"URL host is a raw IP address rather than a domain name: '{host}'.")
        detail["ip_address_host"] = host

    # --- Hex/decimal-encoded host -----------------------------------------
    elif host and _is_hex_or_encoded_host(host):
        score += URL_WEIGHTS["hex_or_encoded_host"]
        reasons.append(f"URL host appears to be a hex/decimal-encoded IP address: '{host}'.")
        detail["hex_or_encoded_host"] = host

    # --- URL shortener -------------------------------------------------
    root_domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    if root_domain in URL_SHORTENERS:
        score += URL_WEIGHTS["url_shortener"]
        reasons.append(f"URL uses a link-shortening service that hides the real destination: '{host}'.")
        detail["url_shortener"] = host

    # --- Excessive length -------------------------------------------------
    if len(url) > URL_LONG_LENGTH_THRESHOLD:
        score += URL_WEIGHTS["excessively_long"]
        reasons.append(f"URL is unusually long ({len(url)} characters).")
        detail["excessively_long"] = len(url)

    # --- Too many subdomains -----------------------------------------------
    if host and not _is_ip_host(host):
        labels = host.split(".")
        subdomain_label_count = max(0, len(labels) - 2)
        if subdomain_label_count > URL_MAX_SUBDOMAIN_LABELS:
            score += URL_WEIGHTS["too_many_subdomains"]
            reasons.append(f"URL host has an excessive number of subdomains: '{host}'.")
            detail["too_many_subdomains"] = subdomain_label_count

    # --- Suspicious TLD -----------------------------------------------
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += URL_WEIGHTS["suspicious_tld"]
        reasons.append(f"URL uses a top-level domain commonly abused for phishing: '.{tld}'.")
        detail["suspicious_tld"] = tld

    # --- Excessive hyphens ---------------------------------------------
    if host.count("-") > URL_MAX_HYPHENS:
        score += URL_WEIGHTS["excessive_hyphens"]
        reasons.append(f"URL host contains an unusually high number of hyphens: '{host}'.")
        detail["excessive_hyphens"] = host.count("-")

    # --- Query parameter analysis (redirects + suspicious keys) -----------
    query_params = parse_qs(parsed.query)
    query_keys_lower = {k.lower() for k in query_params}

    redirect_hits = query_keys_lower & REDIRECT_QUERY_KEYS
    if redirect_hits:
        # Extra signal if the redirect target itself looks like a URL,
        # indicating a redirect chain designed to mask the final landing page.
        score += URL_WEIGHTS["redirect_parameter"]
        reasons.append(
            f"URL contains a redirect parameter that may chain to another "
            f"destination: {', '.join(sorted(redirect_hits))}."
        )
        detail["redirect_parameter"] = sorted(redirect_hits)

    suspicious_key_hits = query_keys_lower & SUSPICIOUS_QUERY_KEYS
    if suspicious_key_hits:
        score += URL_WEIGHTS["suspicious_query_params"]
        reasons.append(
            f"URL query string contains credential/verification-themed "
            f"parameters: {', '.join(sorted(suspicious_key_hits))}."
        )
        detail["suspicious_query_params"] = sorted(suspicious_key_hits)

    return score, reasons, detail


def analyze_urls(urls: list[str]) -> _Findings:
    """Analyze every URL in ``urls`` and aggregate the results.

    Each URL is scored independently; the category score is the average
    per-URL score (capped at 100) so that a single bad link among many
    benign ones does not automatically saturate the URL category, while
    a batch of consistently bad links pushes the score up quickly.
    """
    findings = _Findings()
    urls = _safe_url_list(urls)

    if not urls:
        findings.set_feature("url_count", 0)
        return findings

    findings.set_feature("url_count", len(urls))

    per_url_scores: list[int] = []
    per_url_details: list[dict[str, Any]] = []

    for url in urls:
        url_score, url_reasons, url_detail = _analyze_single_url(url)
        per_url_scores.append(url_score)
        per_url_details.append(url_detail)
        findings.reasons.extend(url_reasons)

    findings.set_feature("per_url_findings", per_url_details)

    # Blend average severity with the single worst offender so that one
    # highly malicious URL among several clean ones is not diluted away.
    average_score = sum(per_url_scores) / len(per_url_scores)
    worst_score = max(per_url_scores)
    findings.score = round(_cap(0.5 * average_score + 0.5 * worst_score))

    return findings


# ======================================================================
# Scoring, classification, and top-level orchestration
# ======================================================================

def _classify_risk(score: int) -> str:
    """Map a 0-100 score onto a discrete risk level."""
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return "Safe"  # pragma: no cover - RISK_THRESHOLDS always covers 0


def _estimate_confidence(category_findings: dict[str, _Findings], final_score: int) -> int:
    """Estimate a 0-100 confidence value for the classification.

    Confidence grows with (a) the number of independent categories that
    agree there is a problem (sender + subject + body + url signals
    corroborating each other is stronger evidence than a single noisy
    category) and (b) the total number of individual rules triggered.
    A message with zero signals at all is also reported with a solidly
    high confidence, since "quiet" evidence is itself meaningful.
    """
    categories_triggered = sum(1 for f in category_findings.values() if f.score > 0)
    total_signals = sum(len(f.reasons) for f in category_findings.values())

    if categories_triggered == 0:
        return 85  # confidently "quiet" -- no rules fired at all

    base = 40
    base += categories_triggered * 12          # cross-category corroboration
    base += min(total_signals, 10) * 3          # depth of evidence, capped
    base += 10 if final_score >= 80 else 0      # very high scores are unambiguous

    return round(_cap(base))


def detect_phishing(
    sender: str,
    subject: str,
    body: str,
    urls: list[str],
) -> dict[str, Any]:
    """Analyze an email and produce a structured phishing risk assessment.

    This is the single public entry point for the module. It runs the
    sender, subject, body, and URL analyzers, blends their category
    scores into an overall 0-100 score, classifies the result into a
    risk level, and returns everything needed for downstream handling.

    Parameters
    ----------
    sender:
        Raw "From" header value, e.g. ``'"IT Support" <it@company.com>'``.
    subject:
        Email subject line.
    body:
        Plain-text or HTML email body.
    urls:
        List of URLs extracted from the email (links, images, etc.).

    Returns
    -------
    dict
        A dictionary with the following keys:

        - ``score`` (int): overall risk score, 0-100.
        - ``risk_level`` (str): one of "Safe", "Low", "Medium", "High",
          "Critical".
        - ``confidence`` (int): 0-100 confidence in the classification.
        - ``reasons`` (list[str]): human-readable explanations for every
          rule that fired.
        - ``detected_features`` (dict): structured, per-category detail
          of exactly which signals were detected, for auditing/logging.
        - ``recommendation`` (str): suggested handling action.

    Notes
    -----
    This function never raises on malformed input: missing or
    incorrectly-typed fields are treated as absent signals rather than
    errors, so the function can safely be used directly on untrusted /
    partially-parsed email data.
    """
    sender = _safe_str(sender)
    subject = _safe_str(subject)
    body = _safe_str(body)
    urls = _safe_url_list(urls)

    category_findings: dict[str, _Findings] = {
        "sender": analyze_sender(sender, body),
        "subject": analyze_subject(subject),
        "body": analyze_body(body),
        "url": analyze_urls(urls),
    }

    # Blend the four category scores (each independently capped at 100)
    # using the configured category weights into a single 0-100 score.
    blended_score = sum(
        _cap(category_findings[category].score) * weight
        for category, weight in CATEGORY_BLEND_WEIGHTS.items()
    )
    final_score = round(_cap(blended_score))

    risk_level = _classify_risk(final_score)
    confidence = _estimate_confidence(category_findings, final_score)
    recommendation = RISK_RECOMMENDATIONS[risk_level]

    all_reasons: list[str] = []
    detected_features: dict[str, Any] = {}
    for category, findings in category_findings.items():
        all_reasons.extend(findings.reasons)
        detected_features[category] = {
            "score": round(_cap(findings.score)),
            "features": findings.features,
        }

    return {
        "score": final_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "reasons": all_reasons,
        "detected_features": detected_features,
        "recommendation": recommendation,
    }


# ======================================================================
# Manual smoke test (only runs when executed directly, not on import)
# ======================================================================
if __name__ == "__main__":
    example = detect_phishing(
        sender="PayPal Security <security@paypa1-verify-account.com>",
        subject="URGENT: Your account has been suspended!!!",
        body=(
            "Dear Customer, we noticed unusual activity on your account. "
            "Please verify your account immediately by clicking the link "
            "below and entering your password to avoid suspension."
        ),
        urls=["http://192.168.1.5/login?verify=1&redirect=http://evil.example"],
    )

    import json
    print(json.dumps(example, indent=2))
