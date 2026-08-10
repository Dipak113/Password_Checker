"""Core logic for the Password Security Checker.

Kept independent of Streamlit so it can be reused from a script,
a notebook, tested with plain unit tests, or a UI.
"""

import math
import re
import secrets
import string

MIN_LENGTH = 8          # minimum acceptable length
STRONG_LENGTH = 12      # length that earns a bonus point toward "strong"
SPECIAL_CHARS = string.punctuation  # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~


# ---------------------------------------------------------------------------
# Individual rule checks
# ---------------------------------------------------------------------------

def check_length(password, min_length=MIN_LENGTH):
    # True if the password meets the minimum length requirement
    return len(password) >= min_length


def has_uppercase(password):
    # True if at least one A-Z character is present
    return any(ch.isupper() for ch in password)


def has_lowercase(password):
    # True if at least one a-z character is present
    return any(ch.islower() for ch in password)


def has_digit(password):
    # True if at least one 0-9 character is present
    return any(ch.isdigit() for ch in password)


def has_special_char(password):
    # True if at least one punctuation/symbol character is present
    return any(ch in SPECIAL_CHARS for ch in password)


def has_whitespace(password):
    # True if the password contains a space or other whitespace (usually undesirable)
    return any(ch.isspace() for ch in password)


# ---------------------------------------------------------------------------
# Aggregate analysis
# ---------------------------------------------------------------------------

def analyze_password(password, min_length=MIN_LENGTH):
    """Run every rule check and return a dict of individual results.

    This is the single source of truth the UI reads from, so the app
    never has to re-implement or duplicate any rule.
    """
    return {
        "length_ok": check_length(password, min_length),
        "length": len(password),
        "has_upper": has_uppercase(password),
        "has_lower": has_lowercase(password),
        "has_digit": has_digit(password),
        "has_special": has_special_char(password),
        "has_whitespace": has_whitespace(password),
    }


def score_password(password, min_length=MIN_LENGTH):
    """Score a password from 0-6 based on how many criteria it satisfies.

    Base criteria (1 point each): length, uppercase, lowercase, digit, special char.
    Bonus (1 point): length >= STRONG_LENGTH, since longer passwords resist
    brute-force attacks far better than merely "long enough" ones.
    """
    results = analyze_password(password, min_length)
    score = sum([
        results["length_ok"],
        results["has_upper"],
        results["has_lower"],
        results["has_digit"],
        results["has_special"],
    ])
    if len(password) >= STRONG_LENGTH:
        score += 1
    return score


def classify_strength(password, min_length=MIN_LENGTH):
    """Classify a password as 'Weak', 'Medium', or 'Strong'.

    An empty password is always Weak regardless of score.
    """
    if not password:
        return "Weak"

    score = score_password(password, min_length)

    if score <= 2:
        return "Weak"
    if score <= 4:
        return "Medium"
    return "Strong"


def get_suggestions(password, min_length=MIN_LENGTH):
    """Return a list of concrete, actionable suggestions for a weak/medium password.

    Empty list means the password already satisfies every rule checked here.
    """
    if not password:
        return ["Enter a password to get started."]

    results = analyze_password(password, min_length)
    suggestions = []

    if not results["length_ok"]:
        suggestions.append(f"Use at least {min_length} characters.")
    elif len(password) < STRONG_LENGTH:
        suggestions.append(
            f"Consider {STRONG_LENGTH}+ characters for extra strength."
        )
    if not results["has_upper"]:
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not results["has_lower"]:
        suggestions.append("Add at least one lowercase letter (a-z).")
    if not results["has_digit"]:
        suggestions.append("Add at least one number (0-9).")
    if not results["has_special"]:
        suggestions.append("Add at least one special character (e.g. ! @ # $ %).")
    if results["has_whitespace"]:
        suggestions.append("Remove spaces — they're often rejected and weaken predictability.")
    if is_common_password(password):
        suggestions.append("Avoid common/well-known passwords — this one appears on breach lists.")

    return suggestions


# ---------------------------------------------------------------------------
# Extra: common-password check (bonus hardening beyond the base assignment)
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
    "123456789", "football", "dragon",
}


def is_common_password(password):
    # Case-insensitive check against a small list of frequently breached passwords
    return password.lower() in COMMON_PASSWORDS


def check_password(password, min_length=MIN_LENGTH):
    """Convenience wrapper: run the full pipeline and return everything the UI needs."""
    crack_seconds, crack_display = estimate_crack_time(password)
    return {
        "analysis": analyze_password(password, min_length),
        "score": score_password(password, min_length),
        "strength": classify_strength(password, min_length),
        "suggestions": get_suggestions(password, min_length),
        "is_common": is_common_password(password),
        "entropy_bits": estimate_entropy_bits(password),
        "crack_time_seconds": crack_seconds,
        "crack_time_display": crack_display,
    }


# ---------------------------------------------------------------------------
# Entropy and crack-time estimation
# ---------------------------------------------------------------------------

# Illustrative offline-attack throughput (guesses/sec) used only to turn raw
# entropy into a relatable duration -- not a precise security guarantee.
GUESSES_PER_SECOND = 10_000_000_000


def estimate_entropy_bits(password):
    """Estimate the password's entropy in bits from the character pool it draws from."""
    if not password:
        return 0.0

    pool = 0
    if has_lowercase(password):
        pool += 26
    if has_uppercase(password):
        pool += 26
    if has_digit(password):
        pool += 10
    if has_special_char(password):
        pool += len(SPECIAL_CHARS)
    if has_whitespace(password):
        pool += 1

    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


# Beyond this, the exact figure is meaningless to a reader -- collapse it to
# a single readable phrase instead of an oversized number.
UNCRACKABLE_THRESHOLD_YEARS = 1_000_000


def humanize_seconds(seconds):
    """Convert a duration in seconds into a short, human-readable string."""
    if seconds < 1:
        return "instantly"

    years = seconds / (60 * 60 * 24 * 365)
    if years >= UNCRACKABLE_THRESHOLD_YEARS:
        return "practically uncrackable"

    units = (
        ("century", "centuries", 60 * 60 * 24 * 365 * 100),
        ("year", "years", 60 * 60 * 24 * 365),
        ("day", "days", 60 * 60 * 24),
        ("hour", "hours", 60 * 60),
        ("minute", "minutes", 60),
        ("second", "seconds", 1),
    )
    for singular, plural, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            display = f"{value:,.0f}" if value > 1000 else f"{value:,.1f}"
            name = singular if value == 1 else plural
            return f"{display} {name}"
    return "instantly"


def estimate_crack_time(password, guesses_per_second=GUESSES_PER_SECOND):
    """Return (seconds, human_readable) rough average-case crack-time estimate."""
    if not password:
        return 0.0, "instantly"
    bits = estimate_entropy_bits(password)
    seconds = (2 ** bits) / 2 / guesses_per_second  # average case: half the keyspace
    return seconds, humanize_seconds(seconds)


# ---------------------------------------------------------------------------
# Secure password generation
# ---------------------------------------------------------------------------

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    """Generate a cryptographically secure random password from the chosen character classes.

    Guarantees at least one character from each selected class so the
    result always satisfies the rule checklist, then fills the rest
    randomly from the combined pool and shuffles.
    """
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_special:
        pools.append(SPECIAL_CHARS)
    if not pools:
        pools = [string.ascii_letters + string.digits]

    length = max(length, len(pools))
    alphabet = "".join(pools)

    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [secrets.choice(alphabet) for _ in range(length - len(password_chars))]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
