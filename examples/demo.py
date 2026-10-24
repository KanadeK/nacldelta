"""Run after installation; all inputs are synthetic and removed on exit."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    allow = {
        "RuleNumber": 100,
        "Protocol": "6",
        "RuleAction": "allow",
        "Egress": False,
        "CidrBlock": "192.0.2.0/24",
        "PortRange": {"From": 443, "To": 443},
    }
    deny = {**allow, "RuleNumber": 50, "RuleAction": "deny", "CidrBlock": "192.0.2.64/26"}
    with tempfile.TemporaryDirectory(prefix="nacldelta-demo-") as temp:
        before, after = Path(temp) / "before.json", Path(temp) / "after.json"
        for path, entries in ((before, [allow]), (after, [allow, deny])):
            path.write_text(
                json.dumps({"NetworkAcls": [{"NetworkAclId": "acl-example", "Entries": entries}]}),
                encoding="utf-8",
            )
        args = [
            sys.executable,
            "-m",
            "nacldelta",
            str(before),
            str(after),
            "--protocol",
            "tcp",
            "--port",
            "443",
        ]
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=30)
        if result.returncode != 1:
            raise RuntimeError(
                f"Expected effective change, got {result.returncode}: {result.stderr}"
            )
        detail = json.loads(result.stdout)["families"]["ipv4"]
        if (
            detail["newly_denied"]["cidrs"] != ["192.0.2.64/26"]
            or detail["newly_denied"]["address_count"] != "64"
        ):
            raise RuntimeError("Demo decision differs from the expected 64-address deny range")
        args[4] = str(before)
        unchanged = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", timeout=30
        )
        if unchanged.returncode != 0 or json.loads(unchanged.stdout)["changed"]:
            raise RuntimeError("Identical snapshot should be unchanged")
        print(
            "Demo passed: ingress TCP/443 newly denies 192.0.2.64/26 (64 addresses); identical snapshots stay unchanged."
        )


if __name__ == "__main__":
    main()
