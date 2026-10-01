import os
import re


def run_vapt_scan():
    print("=== VAPT Security Scan ===")

    findings = []

    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )

    # -------------------------------------------------
    # 1. Scan project files for possible exposed secrets
    # -------------------------------------------------

    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"aws_secret_access_key\s*=",
        r"password\s*=\s*['\"]",
        r"secret_key\s*=\s*['\"]"
    ]

    for root, dirs, files in os.walk(project_root):

        dirs[:] = [
            d for d in dirs
            if d not in [".venv", ".git", "__pycache__"]
        ]

        for filename in files:

            if filename.endswith((".py", ".yaml", ".yml", ".json", ".tf")):

                filepath = os.path.join(root, filename)

                try:
                    with open(filepath, "r", encoding="utf-8") as file:
                        content = file.read()

                    for pattern in secret_patterns:

                        if re.search(pattern, content, re.IGNORECASE):

                            findings.append(
                                f"Possible secret found: {filepath}"
                            )

                except Exception:
                    pass

    # -------------------------------------------------
    # 2. Check Terraform S3 public-access protection
    # -------------------------------------------------

    terraform_dir = os.path.join(project_root, "terraform")

    terraform_content = ""

    if os.path.exists(terraform_dir):

        for filename in os.listdir(terraform_dir):

            if filename.endswith(".tf"):

                filepath = os.path.join(terraform_dir, filename)

                try:
                    with open(filepath, "r", encoding="utf-8") as file:
                        terraform_content += file.read() + "\n"

                except Exception:
                    pass

    required_security_settings = [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets"
    ]

    for setting in required_security_settings:

        if setting not in terraform_content:

            findings.append(
                f"S3 public-access protection missing: {setting}"
            )

    # -------------------------------------------------
    # 3. Final VAPT result
    # -------------------------------------------------

    if findings:

        print("[VAPT] Security findings detected")

        for finding in findings:
            print("[FINDING]", finding)

        print("[VAPT] FAILED")

        return False

    print("[VAPT] No critical findings detected")
    print("[VAPT] PASSED")

    return True


if __name__ == "__main__":
    run_vapt_scan()