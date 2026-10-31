"""Deterministic rule-based analysis engine.

Implements patterns such as null reference, database connection timeout,
permission denied, missing environment variable, repeated retries, etc.

Each pattern maps an event keyword to:
  - pattern name
  - description
  - preceding events context
  - cascading errors
  - recommended debugging steps

All conclusions use explainable heuristics. Confidence labels (HIGH/MEDIUM/LOW)
are derived from evidence strength, not random values.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tb_core.core.models import Event, Evidence

# Pattern definitions: keyword -> metadata
PATTERNS: Dict[str, Dict[str, Any]] = {
    "null_reference": {
        "keywords": ["null pointer", "null reference", "cannot read", "property of null"],
        "title": "Null Reference Exception",
        "description": "Code attempted to access a property or method on a null object.",
        "confidence": "HIGH",
        "recommended_steps": [
            "Add null guards before dereferencing objects",
            "Validate input data before use",
            "Check service dependencies return expected data",
            "Add unit tests covering null input scenarios",
        ],
    },
    "database_connection_timeout": {
        "keywords": ["connection timeout", "database timeout", "timeout", "not responding"],
        "title": "Database Connection Timeout",
        "description": "The application could not establish a connection to the database within the timeout window.",
        "confidence": "HIGH",
        "recommended_steps": [
            "Verify database connectivity and network latency",
            "Check database server resource usage",
            "Increase connection pool timeout",
            "Review database query performance",
        ],
    },
    "connection_refused": {
        "keywords": ["connection refused", "refused", "unavailable"],
        "title": "Connection Refused",
        "description": "The target service actively refused the connection.",
        "confidence": "MEDIUM",
        "recommended_steps": [
            "Verify the target service is running",
            "Check firewall rules and network policies",
            "Confirm service health endpoints",
            "Review load balancer health checks",
        ],
    },
    "permission_denied": {
        "keywords": ["permission denied", "denied", "forbidden"],
        "title": "Permission Denied",
        "description": "Access to a file, resource, or operation was denied.",
        "confidence": "MEDIUM",
        "recommended_steps": [
            "Verify file permissions and ownership",
            "Check user/service account privileges",
            "Review IAM policies and role assignments",
            "Confirm required secrets and keys are present",
        ],
    },
    "missing_environment_variable": {
        "keywords": ["environment variable", "missing", "not set", "required"],
        "title": "Missing Environment Variable",
        "description": "A required configuration value was not set in the environment.",
        "confidence": "HIGH",
        "recommended_steps": [
            "Verify environment configuration for all deployed instances",
            "Add missing variable to the deployment manifest",
            "Use a secrets manager for sensitive values",
            "Add validation for required configuration",
        ],
    },
    "file_not_found": {
        "keywords": ["file not found", "missing file", "not found", "permission"],
        "title": "File Not Found",
        "description": "A required file could not be loaded.",
        "confidence": "MEDIUM",
        "recommended_steps": [
            "Check that the file path is correct",
            "Verify the file exists in the expected location",
            "Confirm the service has read permissions",
            "Check container or volume mounts",
        ],
    },
    "memory_allocation_failure": {
        "keywords": ["out of memory", "memory allocation", "oom", "killed"],
        "title": "Memory Allocation Failure",
        "description": "The application exhausted available memory.",
        "confidence": "MEDIUM",
        "recommended_steps": [
            "Increase container or system memory limits",
            "Profile memory usage for memory leaks",
            "Load test to find memory growth patterns",
            "Add memory usage monitoring",
        ],
    },
    "repeated_api_retries": {
        "keywords": ["retry", "retrying", "rate limit", "backoff"],
        "title": "Repeated API Retries",
        "description": "The client repeatedly attempted and failed to reach an upstream dependency.",
        "confidence": "MEDIUM",
        "recommended_steps": [
            "Check upstream service availability",
            "Verify circuit breaker configuration",
            "Review retry and backoff strategy",
            "Increase timeout for slow dependencies",
        ],
    },
    "authentication_failure": {
        "keywords": ["authentication failed", "unauthorized", "invalid credentials", "not authorized"],
        "title": "Authentication Failure",
        "description": "The request could not be authenticated successfully.",
        "confidence": "HIGH",
        "recommended_steps": [
            "Verify authentication credentials and tokens",
            "Check token expiration policies",
            "Review identity provider configuration",
            "Ensure required scopes and claims are present",
        ],
    },
    "dependency_unavailable": {
        "keywords": ["unavailable", "service down", "fatal error", "terminated"],
        "title": "Dependency Unavailable",
        "description": "An upstream dependency became unavailable or crashed.",
        "confidence": "MEDIUM",
        "recommended_steps": [
            "Check the upstream service health and logs",
            "Verify deployment and restart status",
            "Review infrastructure alerts for the dependency",
            "Confirm connection pool and timeout configuration",
        ],
    },
    "database_query_failed": {
        "keywords": ["query failed", "sql", "database error", "query error"],
        "title": "Database Query Failure",
        "description": "A database query failed to execute.",
        "confidence": "HIGH",
        "recommended_steps": [
            "Validate the query syntax and parameters",
            "Check database constraints and indexes",
            "Review connection pool exhaustion",
            "Inspect database error logs",
        ],
    },
}


class RulesEngine:
    """Enumerates and manages analysis patterns."""

    def __init__(self):
        self.patterns = PATTERNS

    def list_patterns(self) -> List[str]:
        return list(self.patterns.keys())

    def get_pattern(self, name: str) -> Optional[Dict[str, Any]]:
        return self.patterns.get(name)

    def detect(self, message: str, exception_type: Optional[str]) -> Optional[str]:
        """Return the pattern name that best matches a log message."""
        text = f"{message} {exception_type or ''}".lower()
        matches = []
        for name, meta in self.patterns.items():
            for kw in meta["keywords"]:
                if kw in text:
                    matches.append(name)
        if not matches:
            return None
        # Return the most specific match (longer keyword = more specific)
        return max(matches, key=lambda n: len(self.patterns[n]["keywords"][0]))