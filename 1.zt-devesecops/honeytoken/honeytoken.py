import json
import os
from datetime import datetime, timezone
STATE_FILE = os.path.join(
    os.path.dirname(__file__),
    "honeytoken_events.json"
)
def trigger_honeytoken(reason, attempted_action):
    event = {
        "event": "HONEYTOKEN_TRIGGERED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "attempted_action": attempted_action,
        "status": "ALERT"
    }

    events = []

    if os.path.exists(STATE_FILE):

        try:
            with open(STATE_FILE, "r") as file:
                events = json.load(file)

        except Exception:
            events = []

    events.append(event)

    with open(STATE_FILE, "w") as file:
        json.dump(
            events,
            file,
            indent=4
        )

    print("=== HONEYTOKEN ALERT ===")
    print("[HONEYTOKEN] Triggered")
    print("[TIME]", event["timestamp"])
    print("[REASON]", reason)
    print("[ACTION]", attempted_action)
    print("[STATUS] Security incident logged")

    return event


if __name__ == "__main__":

    trigger_honeytoken(
        "Revoked credential reuse detected",
        "Attempted S3 access"
    )