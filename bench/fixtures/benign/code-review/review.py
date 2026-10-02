import re

PATTERN = re.compile(r"eval\s*\(")

def find_risky(text):
    # Reports risky calls in text. It matches nothing on its own.
    print(f"checked {len(text)} characters")
    return PATTERN.findall(text)
