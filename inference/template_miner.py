"""
Online Log Template Mining via Drain3.
Extracts structural templates and identifies novel clusters without manual regex.
"""

import hashlib
from typing import Dict, Any, Optional, Tuple
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import MaskingInstruction


class LogTemplateMiner:
    """
    Stateful online clustering engine that abstracts variable parameters into wildcards.
    """

    def __init__(self, depth: int = 4, sim_th: float = 0.5):
        config = TemplateMinerConfig()
        config.drain_depth = depth
        config.drain_sim_th = sim_th
        config.drain_max_children = 100
        config.drain_max_clusters = 2000

        # Custom masking instructions to accelerate clustering
        config.masking_instructions = [
            MaskingInstruction(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", "<IP>"),
            MaskingInstruction(r"0x[0-9a-fA-F]+", "<HEX>"),
            MaskingInstruction(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>"),
            MaskingInstruction(r"\b\d+\b", "<NUM>"),
        ]

        self.miner = TemplateMiner(config=config)

    def process_log(self, raw_log: str) -> Dict[str, Any]:
        """
        Processes a log line and returns cluster metadata:
        {
            "cluster_id": int,
            "template": str,
            "signature_hash": str,
            "is_novel": bool,
            "cluster_size": int
        }
        """
        line_clean = raw_log.strip()
        result = self.miner.add_log_message(line_clean)

        template_str = result["template_mined"]
        cluster_id = result["cluster_id"]
        change_type = result["change_type"]  # "cluster_created", "cluster_template_changed", "none"

        sig_hash = hashlib.md5(template_str.encode("utf-8")).hexdigest()[:12]

        cluster = self.miner.drain.id_to_cluster.get(cluster_id)
        cluster_size = cluster.size if cluster else 1

        return {
            "cluster_id": cluster_id,
            "template": template_str,
            "signature_hash": f"sig_{sig_hash}",
            "is_novel": (change_type == "cluster_created"),
            "cluster_size": cluster_size
        }

