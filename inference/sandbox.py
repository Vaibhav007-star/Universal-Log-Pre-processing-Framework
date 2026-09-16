"""
Rule Validation Sandbox.
Executes candidate regex and schema mappings against sample logs in isolation before promoting to hot path.
"""

import re
from typing import List, Dict, Any, Tuple


class RuleSandbox:
    """
    Validates candidate regex patterns against actual log samples.
    """

    @staticmethod
    def validate_candidate_rule(
        regex_pattern: str,
        field_mappings: Dict[str, str],
        sample_logs: List[str]
    ) -> Tuple[bool, str, float]:
        """
        Tests regex against samples.
        Returns (is_valid: bool, report: str, score: float [0.0 - 1.0]).
        """
        if not regex_pattern or not sample_logs:
            return False, "Empty regex or sample list", 0.0

        try:
            compiled_regex = re.compile(regex_pattern)
        except re.error as e:
            return False, f"Regex compilation error: {e}", 0.0

        matches_count = 0
        total_extracted_fields = 0

        for sample in sample_logs:
            m = compiled_regex.search(sample)
            if m:
                matches_count += 1
                group_dict = m.groupdict()
                # Count how many named groups matched non-empty values
                matched_groups = {k: v for k, v in group_dict.items() if v is not None and str(v).strip()}
                total_extracted_fields += len(matched_groups)

        if matches_count == 0:
            return False, "Candidate regex matched 0 of the test samples", 0.0

        match_ratio = matches_count / len(sample_logs)
        avg_fields = total_extracted_fields / matches_count if matches_count > 0 else 0

        # Score calculation
        score = (0.6 * match_ratio) + min(0.4, (avg_fields / 5.0) * 0.4)

        if match_ratio >= 0.60:
            return True, f"Passed sandbox verification: {matches_count}/{len(sample_logs)} matched (avg fields: {avg_fields:.1f})", round(score, 3)
        else:
            return False, f"Low sample coverage: {matches_count}/{len(sample_logs)} matched", round(score, 3)

