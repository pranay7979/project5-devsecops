import os
import re
import sys

# Build patterns in fragments to avoid detecting this scanner itself.
PATTERNS = [
    (r"SYSTEM_" + r"PROMPT\s*=", "Hardcoded system prompt"),
    (r"system_message\s*=", "Hardcoded system message"),
    (r'"role"\s*:\s*"system"', "System role declaration"),
    (r"ignore previous" + r" instructions", "Prompt injection phrase"),
    (r"you are now", "Prompt injection phrase"),
    (r"pretend you are", "Prompt injection phrase"),
    (r"act as if you have no restrictions", "Prompt injection phrase"),
]

def scan_file(filepath):
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()

        for pattern, description in PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[:match.start()].count("\n") + 1
                findings.append(
                    f"{filepath}:{line_number}: {description}"
                )

    except OSError as error:
        print(f"[ERROR] Cannot read {filepath}: {error}")

    return findings


def main():
    findings = []

    for root, dirs, files in os.walk("."):
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "__pycache__", ".venv", "venv"}
        ]

        for filename in files:
            if filename.endswith(".py") and filename not in {"inject_scanner.py", "validate.py"}:
                filepath = os.path.join(root, filename)
                findings.extend(scan_file(filepath))

    if findings:
        print("[FAIL] Prompt injection scanner detected issues:")
        for finding in findings:
            print(f"  - {finding}")
        sys.exit(1)

    print("[PASS] No configured prompt injection patterns detected.")
    sys.exit(0)


if __name__ == "__main__":
    main()
