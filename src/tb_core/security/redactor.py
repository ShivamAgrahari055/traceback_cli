import re

class SecretRedactor:
    def __init__(self):
        # Patterns for common secrets
        self.patterns = {
            "API_KEY": r"(?i)(api[_-]?key|secret|token)=[\w\d\-]{10,}",
            "JWT": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_=]*",
            "PASSWORD": r"(?i)(password|passwd|pwd)=[\w\d\-]+",
            "EMAIL": r"[\w\.-]+@[\w\.-]+\.\w+",
        }

    def redact(self, text: str) -> str:
        if not text: return text
        redacted_text = text
        for label, pattern in self.patterns.items():
            redacted_text = re.sub(pattern, f"<{label}_REDACTED>", redacted_text)
        return redacted_text
