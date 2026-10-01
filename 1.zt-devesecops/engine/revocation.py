import json
import os
import boto3
from datetime import datetime, timezone

from config import ROLE_ARN, REVOCATION_POLICY_ARN


STATE_FILE = os.path.join(
    os.path.dirname(__file__),
    "access_state.json"
)


def create_access_state():
    state = {
        "status": "ACTIVE",
        "granted_at": datetime.now(timezone.utc).isoformat(),
        "revoked_at": None,
        "reason": None
    }

    save_state(state)

    print("[ACCESS] Temporary access marked ACTIVE")

    return state


def revoke_access(reason="Task completed"):

    state = load_state()

    if state is None:
        print("[REVOCATION] No access session found")
        return False

    if state["status"] == "REVOKED":
        print("[REVOCATION] Access is already revoked")
        return True

    iam = boto3.client("iam")

    print("[REVOCATION] Attaching AWS explicit-deny policy...")

    iam.attach_role_policy(
        RoleName="ZT-DevSecOps-Deploy-Role",
        PolicyArn=REVOCATION_POLICY_ARN
    )

    state["status"] = "REVOKED"
    state["revoked_at"] = datetime.now(timezone.utc).isoformat()
    state["reason"] = reason

    save_state(state)

    print("[REVOCATION] AWS deny policy attached")
    print("[REVOCATION] Access marked REVOKED")
    print("[REVOCATION] Reason:", reason)

    return True


def load_state():

    if not os.path.exists(STATE_FILE):
        return None

    with open(STATE_FILE, "r") as file:
        return json.load(file)


def save_state(state):

    with open(STATE_FILE, "w") as file:
        json.dump(
            state,
            file,
            indent=4
        )


def is_access_active():

    state = load_state()

    if state is None:
        return False

    return state["status"] == "ACTIVE"


if __name__ == "__main__":

    print("=== Zero Trust AWS Revocation Controller ===")

    create_access_state()

    print(
        "[STATUS] Access active:",
        is_access_active()
    )

    revoke_access(
        "Deployment task completed"
    )

    print(
        "[STATUS] Access active:",
        is_access_active()
    )