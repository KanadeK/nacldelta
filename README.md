# Nacldelta

[![CI](https://github.com/KanadeK/nacldelta/actions/workflows/ci.yml/badge.svg)](https://github.com/KanadeK/nacldelta/actions/workflows/ci.yml)

**Which address ranges actually gain or lose permission when an AWS network ACL changes?** Nacldelta compares two local JSON exports for one TCP/UDP port and direction, applying ordered, first-match decisions. It reports exact IPv4/IPv6 CIDRs newly allowed or denied, even when a textual rule diff is misleading.

[中文说明](README.zh-CN.md) · [Design and support boundary](docs/design.md) · [Validation](docs/validation.md)

## Install

Python 3.11+; no runtime dependencies, AWS SDK, AWS credentials or network access during analysis. Source installation downloads the open-source build backend. No package has been uploaded to PyPI.

```sh
git clone https://github.com/KanadeK/nacldelta.git
cd nacldelta
python -m venv .venv
```

Activate the environment with `.venv\Scripts\Activate.ps1` in PowerShell, or `source .venv/bin/activate` on macOS/Linux, then:

```sh
python -m pip install .
python examples/demo.py
nacldelta --version
```

For an offline installation, download the wheel and `SHA256SUMS` from [Releases](https://github.com/KanadeK/nacldelta/releases), verify its checksum, and install the local file with `python -m pip install --no-index --no-deps nacldelta-0.1.0-py3-none-any.whl`. The source archive contains the examples and tests.

## Try the complete workflow

The supplied snapshots are synthetic documentation addresses. A lower-numbered deny carves 64 addresses out of an existing allow:

```sh
nacldelta examples/before.json examples/after.json --protocol tcp --port 443 --format text
```

```text
ingress tcp/443: changed
ipv4 newly_allowed: (none) (0 addresses)
ipv4 newly_denied: 192.0.2.64/26 (64 addresses)
ipv6 newly_allowed: (none) (0 addresses)
ipv6 newly_denied: (none) (0 addresses)
```

**Exit 1 means an effective permission change**; this is expected for this example. Exit 0 means equal allowed-address sets for this query. Exit 2 means invalid arguments/input, unsupported input or an I/O failure. Rule/identifier changes alone do not cause exit 1.

If you already use AWS CLI, create each snapshot yourself when the desired configuration is deployed:

```sh
aws ec2 describe-network-acls --network-acl-ids acl-YOUR-ID --output json > before.json
# Capture after.json after your separately managed change.
nacldelta before.json after.json --protocol udp --port 53 --direction egress
```

No AWS command is executed by Nacldelta. Ingress compares source addresses; egress compares destination addresses. Multiple ACLs in an export require selectors:

```sh
nacldelta before.json after.json --before-id acl-OLD --after-id acl-NEW --protocol tcp --port 443
```

Default output is JSON (`schema_version: 1`). Each family contains `before_allowed`, `after_allowed`, `newly_allowed` and `newly_denied`, with `cidrs`, `address_count` and `first_address` (null for an empty set). Counts are **decimal strings** to preserve IPv6-sized values in JSON consumers. `*_shadowed_rules` lists non-default rules that match the selected service but have no undecided addresses left. Partial shadowing is reflected in the effective sets, not listed as full shadowing.

Library API:

```python
from nacldelta.core import compare, load_snapshot

report = compare(
    load_snapshot("before.json"),
    load_snapshot("after.json"),
    protocol="tcp",
    port=443,
    direction="ingress",
)
print(report["families"]["ipv4"]["newly_denied"])
```

## Scope and limitations

- Models the ACL's first matching rule for **one** TCP or UDP destination port, in **one** direction. Missing matching rules deny. Protocol `-1` matches both services regardless of its port field. Protocol numbers 6 and 17 use inclusive port ranges.
- Accepts AWS CLI `NetworkAcls` envelopes or a single ACL object with `Entries`. Selected ACL rules are validated even if unrelated to the query. CIDRs must already be canonical, as AWS exports them; conflicting/duplicate selected rule numbers within a direction/family fail closed. Unknown AWS metadata is ignored.
- Maximum input 8 MiB, 256 ACLs per envelope, 2,000 rules in the selected ACL and JSON depth 128. Only regular files are accepted. Deterministic interval operations avoid expanding address spaces; worst-case rule fragmentation can still increase work.
- **An ACL decision is only one part of reachability.** Routing, security groups, NAT, return traffic, ephemeral ports and AWS traffic exempt from NACL filtering are not modeled. ICMP, source-port constraints and comparisons over every port are outside this release. No live AWS access or infrastructure changes.
- Reports contain supplied ACL identifiers and network ranges. Keep sensitive reports local. This tool sends no telemetry and writes no input/report files itself; shell redirection is your choice. Replacing a file concurrently is unsupported; size/mtime changes during reading are rejected.

AWS documents [ordered matching](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-rules.html) and [NACL limitations](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html). Use [Batfish](https://github.com/batfish/batfish) or AWS's broader analysis services when you need a network model. Nacldelta provides a small offline change gate for exported ACLs.

## Development and cleanup

```sh
python -m pip install -r requirements-dev.txt
python -m pip install --no-build-isolation --no-deps -e .
python -m ruff check .
python -m ruff format --check .
python -m coverage run -m unittest discover -s tests -v
python -m coverage report --fail-under=85
python -m build --no-isolation
python examples/demo.py
```

CI runs these checks on Linux, macOS and Windows with Python 3.11/3.13. The tests include an independent per-address first-match oracle, IPv6 `/0`, shadowing, malformed inputs and CLI workflows. See [validation](docs/validation.md) for the release evidence and its limits.

Uninstall with `python -m pip uninstall nacldelta`. The demo's temporary directory is automatically removed. Deactivate and remove your dedicated virtual environment/checkout when no longer needed; there are no services, caches or account integrations to clean up. Retain or delete your own snapshot/report files according to your data policy.

MIT · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [Third-party notices](THIRD_PARTY.md)
