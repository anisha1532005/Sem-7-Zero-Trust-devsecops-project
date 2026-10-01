import yaml
import json
import boto3
import sys
import os

from config import ROLE_ARN
from revocation import create_access_state, revoke_access


# Allow Python to find the VAPT module
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

VAPT_PATH = os.path.join(PROJECT_ROOT, "vapt")

if VAPT_PATH not in sys.path:
    sys.path.append(VAPT_PATH)

from vapt_scanner import run_vapt_scan


MANIFEST_PATH = os.path.join(
    PROJECT_ROOT,
    "manifests",
    "intent.yaml"
)


def load_manifest():
    with open(MANIFEST_PATH, "r") as file:
        return yaml.safe_load(file)


def check_vapt():
    print("[VAPT] Starting security scan...")

    result = run_vapt_scan()

    if result:
        print("[VAPT] Security scan PASSED")
        return True

    print("[VAPT] Security scan FAILED")
    return False


def request_temporary_access(manifest):

    sts = boto3.client("sts")

    # Read permissions from intent manifest
    resource = manifest["access"]["resource"]
    actions = manifest["access"]["actions"]

    # Convert S3 URL to ARN
    bucket_arn = resource.replace(
        "s3://",
        "arn:aws:s3:::"
    )

    # Create session policy from manifest
    session_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": bucket_arn + "/*"
            }
        ]
    }

    print("[POLICY] Session policy created from manifest")
    print("[POLICY] Allowed actions:", actions)

    # Request temporary AWS credentials
    response = sts.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="ZeroTrustDeployment",
        Policy=json.dumps(session_policy)
    )

    print("[STS] Temporary credentials issued")
    print(
        "[STS] Access expires at:",
        response["Credentials"]["Expiration"]
    )

    return response["Credentials"]


def main():

    print("=== Zero Trust Access Engine ===")

    # ------------------------------------------------
    # 1. Load Intent Manifest
    # ------------------------------------------------

    manifest = load_manifest()

    print("[1] Intent manifest loaded")
    print(
        "Pipeline:",
        manifest["pipeline"]["name"]
    )

    print(
        "Stage:",
        manifest["stage"]["name"]
    )

    print(
        "Resource:",
        manifest["access"]["resource"]
    )

    print(
        "Actions:",
        manifest["access"]["actions"]
    )

    # ------------------------------------------------
    # 2. Run VAPT Before Access
    # ------------------------------------------------

    if not check_vapt():

        print("[ACCESS DENIED]")
        print("Reason: VAPT security check failed")

        return

    # ------------------------------------------------
    # 3. Request Temporary Access
    # ------------------------------------------------

    credentials = request_temporary_access(
        manifest
    )

    # ------------------------------------------------
    # 4. Access Granted
    # ------------------------------------------------

    print("[ACCESS GRANTED]")
    print("Temporary access successfully created.")

    # ------------------------------------------------
    # 5. Record Access Lifecycle
    # ------------------------------------------------

    create_access_state()

    print("[LIFECYCLE] Access state recorded as ACTIVE")

    # ------------------------------------------------
    # 6. Task Completed
    # ------------------------------------------------

    print("[TASK] Deployment task completed")

    # ------------------------------------------------
    # 7. Revoke AWS Access
    # ------------------------------------------------

    revoke_access(
        "Deployment task completed"
    )

    print("[LIFECYCLE] Access revoked")


if __name__ == "__main__":
    main()