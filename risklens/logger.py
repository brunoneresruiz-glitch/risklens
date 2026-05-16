import json 
import os
from datetime import datetime, timezone 

LOGS_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "results.json")


def log_result(findings: dict, evaluation: dict) -> None:
    """
    Appends one analysis record to results.json.
    Timestamp reflects the local time of whoever is running the tool.
    """
    record = {
        "analysed_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "url": findings["url"],
        "domain": findings["domain"],
        "verdict": evaluation["verdict"],
        "signals": [s["id"] for s in evaluation["signals"]],
        "signal_details": evaluation["signals"],
        "is_https": findings["is_https"],
    }

    os.makedirs(os.path.dirname(LOGS_FILE), exist_ok=True)

    existing = []
    if os.path.exists(LOGS_FILE):
        with open(LOGS_FILE, "r", encoding="utf-8") as f:
            existing = json.load(f)

    existing.append(record)

    with open(LOGS_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

