"""
JIT Rule Synthesizer for Novel / Unseen Log Grammars.
Supports:
1. Statistical / Heuristic synthesis (100% offline, deterministic, zero-cost, air-gap safe)
2. Local SLM via Ollama (Qwen 2.5-Coder 7B / Llama 3.2 3B)
3. Cloud LLM via Google Gemini API (optional)
"""

import re
import json
import requests
from typing import List, Dict, Any, Optional, Tuple
from inference.sandbox import RuleSandbox
from inference.rule_store import LearnedRuleStore, DynamicRegexParser
import config


class RuleSynthesizer:
    """
    Generates compiled regex and OCSF field mappings for novel log templates.
    """

    def __init__(self, rule_store: LearnedRuleStore, backend: str = config.INFERENCE_BACKEND):
        self.rule_store = rule_store
        self.backend = backend.lower()

    def synthesize_rule(
        self,
        signature_id: str,
        template_str: str,
        sample_logs: List[str]
    ) -> Tuple[Optional[DynamicRegexParser], str, float]:
        """
        Attempts to synthesize a validated rule.
        Returns (dynamic_parser, report, confidence_score).
        """
        regex_pattern = None
        field_mappings = {}

        if self.backend == "ollama":
            regex_pattern, field_mappings = self._synthesize_via_ollama(template_str, sample_logs)

        elif self.backend == "gemini":
            regex_pattern, field_mappings = self._synthesize_via_gemini(template_str, sample_logs)

        # Fallback to offline heuristic if backend was "heuristic" or API failed
        if not regex_pattern:
            regex_pattern, field_mappings = self._synthesize_via_heuristic(template_str, sample_logs)

        # Validate in sandbox
        is_valid, report, score = RuleSandbox.validate_candidate_rule(
            regex_pattern, field_mappings, sample_logs
        )

        if is_valid:
            # Save rule in SQLite
            self.rule_store.save_rule(
                signature_id=signature_id,
                template_str=template_str,
                regex_pattern=regex_pattern,
                field_mappings=field_mappings,
                sample_logs=sample_logs,
                confidence_score=score,
                is_verified=False
            )
            # Instantiate dynamic parser
            parser = DynamicRegexParser(
                signature_id=signature_id,
                regex_pattern=regex_pattern,
                field_mappings=field_mappings,
                confidence_score=score
            )
            return parser, f"Successfully synthesized and validated rule: {report}", score

        return None, f"Synthesis validation failed: {report}", score

    def _synthesize_via_heuristic(
        self,
        template_str: str,
        sample_logs: List[str]
    ) -> Tuple[str, Dict[str, str]]:
        """
        Air-gapped deterministic template induction.
        Turns template wildcards into typed named regex capture groups based on token samples.
        """
        if not sample_logs:
            return "", {}

        sample = sample_logs[0]

        # Escape special characters in template except <*>
        # Split template by <*>
        parts = template_str.split("<*>")
        regex_parts = []
        field_mappings = {}
        var_index = 0

        # Heuristic entity detection patterns
        ipv4_regex = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        port_regex = r"\d{1,5}"
        timestamp_regex = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"

        for i, part in enumerate(parts):
            escaped_part = re.escape(part)
            # Re-enable masked tokens if present
            escaped_part = escaped_part.replace(r"\<IP\>", rf"(?P<ip_{i}>{ipv4_regex})")
            escaped_part = escaped_part.replace(r"\<NUM\>", rf"(?P<num_{i}>\d+)")
            escaped_part = escaped_part.replace(r"\<HEX\>", rf"(?P<hex_{i}>0x[0-9a-fA-F]+)")
            escaped_part = escaped_part.replace(r"\<UUID\>", rf"(?P<uuid_{i}>[0-9a-fA-F\-]{{36}})")
            regex_parts.append(escaped_part)

            if i < len(parts) - 1:
                var_index += 1
                group_name = f"var_{var_index}"

                # Infer group semantics from preceding part
                preceding = part.lower()
                if any(w in preceding for w in ("from", "src", "source", "client")):
                    group_name = f"src_ip"
                    field_mappings[group_name] = "src_endpoint.ip"
                    regex_parts.append(rf"(?P<{group_name}>{ipv4_regex}|\S+)")
                elif any(w in preceding for w in ("to", "dst", "dest", "server", "target")):
                    group_name = f"dst_ip"
                    field_mappings[group_name] = "dst_endpoint.ip"
                    regex_parts.append(rf"(?P<{group_name}>{ipv4_regex}|\S+)")
                elif any(w in preceding for w in ("port", "pt", "dport")):
                    group_name = f"dst_port"
                    field_mappings[group_name] = "dst_endpoint.port"
                    regex_parts.append(rf"(?P<{group_name}>{port_regex})")
                elif any(w in preceding for w in ("time", "date", "[")):
                    group_name = f"timestamp"
                    field_mappings[group_name] = "timestamp.raw"
                    regex_parts.append(rf"(?P<{group_name}>{timestamp_regex}|\S+)")
                elif any(w in preceding for w in ("user", "usr", "account")):
                    group_name = f"user_name"
                    field_mappings[group_name] = "actor.user_name"
                    regex_parts.append(rf"(?P<{group_name}>[a-zA-Z0-9_\-\.\@]+)")
                elif any(w in preceding for w in ("status", "action", "event")):
                    group_name = f"action"
                    field_mappings[group_name] = "event.action"
                    regex_parts.append(rf"(?P<{group_name}>\w+)")
                else:
                    field_mappings[group_name] = f"unmapped.{group_name}"
                    regex_parts.append(rf"(?P<{group_name}>\S+)")

        pattern = "^" + "".join(regex_parts) + "$"
        return pattern, field_mappings

    def _synthesize_via_ollama(
        self,
        template_str: str,
        sample_logs: List[str]
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """
        Queries local Ollama instance for structured JSON parser spec.
        """
        prompt = f"""
You are a cybersecurity log engineer. Convert this raw log template into a Python regex with named capture groups and OCSF schema field mappings.
Log Template: {template_str}
Sample Logs:
{json.dumps(sample_logs[:3], indent=2)}

Respond with ONLY valid JSON adhering strictly to this format:
{{
  "regex_pattern": "^...$",
  "field_mappings": {{
     "group_name": "ocsf_target_path"
  }}
}}
Allowed OCSF target paths: "src_endpoint.ip", "src_endpoint.port", "dst_endpoint.ip", "dst_endpoint.port", "timestamp.raw", "event.action", "event.status", "actor.user_name", "process.name".
"""
        try:
            resp = requests.post(
                f"{config.OLLAMA_HOST}/api/generate",
                json={
                    "model": config.OLLAMA_MODEL,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.1}
                },
                timeout=5.0
            )
            if resp.status_code == 200:
                data = resp.json()
                raw_response = data.get("response", "{}")
                parsed_json = json.loads(raw_response)
                return parsed_json.get("regex_pattern"), parsed_json.get("field_mappings", {})
        except Exception:
            pass

        return None, {}

    def _synthesize_via_gemini(
        self,
        template_str: str,
        sample_logs: List[str]
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """
        Queries Google Gemini API for structured JSON parser spec.
        """
        if not config.GEMINI_API_KEY:
            return None, {}

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.GEMINI_MODEL}:generateContent?key={config.GEMINI_API_KEY}"
        prompt = f"""
Convert this log template into a Python regex with named capture groups and OCSF schema mappings.
Template: {template_str}
Samples: {sample_logs[:3]}
Return ONLY JSON: {{"regex_pattern": "^...$", "field_mappings": {{"group": "ocsf_path"}}}}
"""
        try:
            resp = requests.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=6.0
            )
            if resp.status_code == 200:
                body = resp.json()
                text = body["candidates"][0]["content"]["parts"][0]["text"]
                # Clean possible markdown fences
                text_clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
                parsed = json.loads(text_clean)
                return parsed.get("regex_pattern"), parsed.get("field_mappings", {})
        except Exception:
            pass

        return None, {}

