"""OpenAI-compatible LLM provider.

Works with any provider that exposes an OpenAI-compatible chat
completions endpoint (OpenAI, Groq, Gemini via OpenAI-compatible
proxy, local models via llama.cpp, etc.).

Uses only the Python standard library (urllib) to avoid adding
new dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from tb_core.ai.config import AIConfig
from tb_core.ai.models import (
    LLMAnswer,
    LLMRootCauseAnalysis,
    ProviderError,
)
from tb_core.ai.provider import BaseLLMProvider
from tb_core.core.models import Event, Evidence


class OpenAICompatibleProvider(BaseLLMProvider):
    """OpenAI-compatible chat completions provider."""

    def __init__(self, config: AIConfig):
        super().__init__(config)
        self._base_url = config.base_url or "https://api.openai.com/v1"
        self._api_key = config.api_key or ""
        self._model = config.model
        self._timeout = config.timeout
        self._max_tokens = config.max_tokens
        self._temperature = config.temperature

    # ------------------------------------------------------------------
    # Incident analysis
    # ------------------------------------------------------------------

    def analyze_incident(
        self,
        *,
        incident_id: str,
        title: str,
        severity: str,
        events: List[Event],
        deterministic_analysis: Dict[str, Any],
        redacted_events: List[Event],
    ) -> LLMRootCauseAnalysis:
        """Generate an LLM-enhanced root-cause analysis."""
        if not self._api_key:
            raise ProviderError("No API key configured", retryable=False)

        event_ids = {ev.event_id for ev in redacted_events}
        context = self._build_evidence_context(redacted_events, deterministic_analysis)

        system_prompt = (
            "You are an expert incident investigation assistant. "
            "Analyze the provided log evidence and produce a structured "
            "root-cause analysis. "
            "CRITICAL RULES: "
            "1) Never invent events, services, or timestamps that are not "
            "in the evidence. "
            "2) Only reference event IDs that appear in the evidence. "
            "3) Distinguish clearly between OBSERVED EVIDENCE (facts from "
            "logs) and INFERRED HYPOTHESES (your conclusions). "
            "4) Do not claim a hypothesis is confirmed unless the evidence "
            "strongly supports it. "
            "5) Calibrate confidence honestly: LOW if evidence is thin, "
            "MEDIUM if there is correlation but ambiguity, HIGH only if "
            "there is strong causal evidence. "
            "6) If information is missing, say so explicitly."
        )

        user_prompt = (
            f"{context}\n\n"
            f"Incident title: {title}\n"
            f"Severity: {severity}\n\n"
            "Please produce a structured root-cause analysis with the "
            "following sections (return valid JSON matching the schema):\n"
            "- summary: A brief plain-language summary of what happened.\n"
            "- root_cause_hypothesis: The most likely root cause, clearly "
            "labelled as a hypothesis.\n"
            "- confidence: HIGH / MEDIUM / LOW.\n"
            "- confidence_explanation: Why you assigned this confidence.\n"
            "- affected_services: List of service names involved.\n"
            "- causal_chain: List of events with category (root_cause, "
            "supporting_evidence, application_exception, downstream_failure, "
            "user_facing_impact) and description.\n"
            "- downstream_failures: Events that are consequences, with "
            "event_id and finding.\n"
            "- user_facing_impact: User-visible errors, with event_id and "
            "finding.\n"
            "- debugging_recommendations: Up to 10 specific, prioritized "
            "steps.\n"
            "- missing_evidence: Up to 5 pieces of information that would "
            "help.\n"
            "- limitations: Up to 5 limitations of this analysis.\n"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            raw = self._chat_completion(messages)
            content = raw["choices"][0]["message"]["content"]
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"Provider call failed: {exc}", retryable=True)

        # Try to parse JSON from the response
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code fences
            data = self._extract_json(content)
            if data is None:
                raise ProviderError("Malformed model output: not valid JSON", retryable=True)

        # Validate via Pydantic
        try:
            result = LLMRootCauseAnalysis(**data)
        except Exception as exc:
            # Retry once with a correction prompt
            try:
                correction = (
                    f"The previous response failed validation: {exc}\n"
                    f"Please fix and return valid JSON only, no markdown."
                )
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": correction})
                raw2 = self._chat_completion(messages)
                content2 = raw2["choices"][0]["message"]["content"]
                data2 = json.loads(content2)
                result = LLMRootCauseAnalysis(**data2)
            except Exception:
                raise ProviderError(
                    f"Model output validation failed: {exc}", retryable=False
                )

        # Filter event references to only those that exist
        result.causal_chain = [
            c for c in result.causal_chain if c.event_id in event_ids
        ]
        result.downstream_failures = self._validate_event_references(
            result.downstream_failures, event_ids
        )
        result.user_facing_impact = self._validate_event_references(
            result.user_facing_impact, event_ids
        )
        result.is_llm_generated = True

        return result

    # ------------------------------------------------------------------
    # Question answering
    # ------------------------------------------------------------------

    def answer_question(
        self,
        *,
        incident_id: str,
        question: str,
        events: List[Event],
        deterministic_analysis: Dict[str, Any],
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> LLMAnswer:
        """Answer a question about an incident."""
        if not self._api_key:
            raise ProviderError("No API key configured", retryable=False)

        event_ids = {ev.event_id for ev in events}
        context = self._build_evidence_context(events, deterministic_analysis)

        system_prompt = (
            "You are an incident investigation assistant. Answer the user's "
            "question based ONLY on the provided log evidence. "
            "CRITICAL RULES: "
            "1) Never invent events or facts not in the evidence. "
            "2) Cite event IDs when making evidence-based claims. "
            "3) If information is unavailable, say so explicitly. "
            "4) Do not mix data from different incidents. "
            "5) Keep answers concise and actionable."
        )

        # Build conversation history
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt},
        ]
        if conversation_history:
            for turn in conversation_history[-6:]:  # Limit history
                messages.append({"role": "user", "content": turn.get("question", "")})
                messages.append({"role": "assistant", "content": turn.get("answer", "")})

        messages.append(
            {
                "role": "user",
                "content": (
                    f"Incident ID: {incident_id}\n"
                    f"Evidence:\n{context}\n\n"
                    f"Question: {question}"
                ),
            }
        )

        try:
            raw = self._chat_completion(messages)
            content = raw["choices"][0]["message"]["content"]
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"Provider call failed: {exc}", retryable=True)

        # Parse the answer (may not be strict JSON for Q&A)
        try:
            data = json.loads(content)
            answer_text = data.get("answer", content)
            conf = data.get("confidence", "LOW")
        except (json.JSONDecodeError, AttributeError):
            answer_text = content.strip()
            conf = "LOW"

        try:
            result = LLMAnswer(
                answer=answer_text,
                confidence=conf,
                is_llm_generated=True,
            )
        except Exception:
            result = LLMAnswer(
                answer=answer_text,
                confidence="LOW",
                is_llm_generated=True,
            )

        # Filter event references
        result.event_references = self._validate_event_references(
            result.event_references, event_ids
        )

        return result

    # ------------------------------------------------------------------
    # HTTP transport
    # ------------------------------------------------------------------

    def _chat_completion(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Call the OpenAI-compatible chat completions API."""
        url = self._base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 401:
                raise ProviderError("Invalid API credentials", retryable=False)
            if exc.code == 429:
                raise ProviderError("Rate limited by provider", retryable=True)
            if exc.code >= 500:
                raise ProviderError(f"Provider server error ({exc.code})", retryable=True)
            raise ProviderError(f"Provider error ({exc.code}): {body[:200]}", retryable=False)
        except urllib.error.URLError as exc:
            raise ProviderError(f"Network error: {exc}", retryable=True)
        except json.JSONDecodeError as exc:
            raise ProviderError(f"Malformed provider response: {exc}", retryable=True)
        except Exception as exc:
            raise ProviderError(f"Unexpected error: {exc}", retryable=True)

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict[str, Any]]:
        """Try to extract a JSON object from markdown-wrapped text."""
        import re

        # Look for ```json ... ``` or ``` ... ```
        match = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass
        # Try to find a raw JSON object
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        return None
