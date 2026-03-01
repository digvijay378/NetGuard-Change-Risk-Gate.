"""Structured audit logger for NetGuard assessments."""
import logging
import json
from datetime import datetime, timezone

logger = logging.getLogger("netguard.audit")


def log_assessment(assessment_id: str, decision: str, risk_level: str,
                   score: int, source: str, block_merge: bool):
    entry = {
        "event": "assessment_completed",
        "assessment_id": assessment_id,
        "decision": decision,
        "risk_level": risk_level,
        "adjusted_risk_score": score,
        "change_source": source,
        "block_merge": block_merge,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(json.dumps(entry))


def log_error(assessment_id: str, error: str):
    entry = {
        "event": "assessment_error",
        "assessment_id": assessment_id,
        "error": error,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    logger.error(json.dumps(entry))
