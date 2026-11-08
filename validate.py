import re
import base64
from flask import jsonify

# Layer 1: Maximum input length
MAX_LENGTH = 500

# Layer 2: Regex injection blocklist
INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"you are now",
    r"pretend you are",
    r"act as if you have no",
    r"\bDAN\b",                    # word boundary to avoid false positives on "Daniel"
    r"jailbreak",
    r"system prompt",
    r"no restrictions",
    r"bypass authentication",
]

def validate_input(user_msg):
    """
    Layer 1 + Layer 2: Input validation
    Returns (is_valid: bool, error_message: str or None)
    """
    # Layer 1: Maximum input length
    if len(user_msg) > MAX_LENGTH:
        return False, "Input exceeds maximum length of 500 characters."
    
    # Layer 2: Regex injection blocklist
    lowered = user_msg.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            return False, f"Blocked: input matches injection pattern '{pattern}'."
    
    # Check for base64-encoded strings of 40+ characters
    potential_b64 = re.findall(r'[A-Za-z0-9+/=]{40,}', user_msg)
    for b64_str in potential_b64:
        try:
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            if any(re.search(p, decoded.lower()) for p in INJECTION_PATTERNS):
                return False, "Blocked: base64-encoded injection detected."
        except Exception:
            pass
    
    return True, None

def scan_output(response_text):
    """
    Layer 3: Output scanner
    Returns (is_safe: bool, error_message: str or None)
    """
    # Block verbatim system prompt text
    if "You are a helpful assistant" in response_text:
        return False, "Blocked: response contains system prompt text."
    
    # Block credential patterns
    credential_patterns = [
        r"password\s*=",
        r"api[_-]?key",
        r"token\s*=",
        r"secret\s*=",
        r"sk-[a-zA-Z0-9]{10,}",
        r"Bearer\s+[a-zA-Z0-9]"
    ]
    for pattern in credential_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return False, "Blocked: response contains credential pattern."
    
    # Block unsolicited external URLs (allow localhost for testing)
    url_pattern = r'https?://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9.-]+\.[a-z]{2,}'
    if re.search(url_pattern, response_text):
        return False, "Blocked: response contains external URL."
    
    return True, None
