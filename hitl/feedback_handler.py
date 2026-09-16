"""
Applies Cybersecurity Analyst Feedback to Improve Future Parsing Accuracy.
"""

from typing import Dict, Any, List
from inference.rule_store import LearnedRuleStore, DynamicRegexParser
from parsers.registry import ParserRegistry
from hitl.review_queue import ReviewQueue


class FeedbackHandler:
    """
    Closes the human-in-the-loop active learning loop.
    """

    def __init__(
        self,
        rule_store: LearnedRuleStore,
        registry: ParserRegistry,
        review_queue: ReviewQueue
    ):
        self.rule_store = rule_store
        self.registry = registry
        self.review_queue = review_queue

    def apply_analyst_correction(
        self,
        event_id: str,
        signature_id: str,
        template_str: str,
        regex_pattern: str,
        corrected_mappings: Dict[str, str],
        sample_log: str
    ) -> bool:
        """
        Commits verified rule to SQLite store and hot-reloads into live parser registry.
        """
        # Save verified rule
        self.rule_store.save_rule(
            signature_id=signature_id,
            template_str=template_str,
            regex_pattern=regex_pattern,
            field_mappings=corrected_mappings,
            sample_logs=[sample_log],
            confidence_score=1.0,  # 100% confidence because human-verified
            is_verified=True
        )

        # Hot-load into live registry
        dynamic_parser = DynamicRegexParser(
            signature_id=signature_id,
            regex_pattern=regex_pattern,
            field_mappings=corrected_mappings,
            confidence_score=1.0
        )
        dynamic_parser.priority = 72  # Prioritize human-verified rules
        self.registry.register(dynamic_parser)

        # Mark queue item approved
        self.review_queue.mark_status(event_id, "APPROVED")
        return True

