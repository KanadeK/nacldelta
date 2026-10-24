from __future__ import annotations

import contextlib
import copy
import io
import ipaddress
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nacldelta.cli import main
from nacldelta.core import MAX_BYTES, InputError, compare, load_snapshot, parse_snapshot


def rule(
    number=100, cidr="192.0.2.0/24", action="allow", protocol="6", ports=(443, 443), egress=False
):
    value = {
        "RuleNumber": number,
        "CidrBlock" if ":" not in cidr else "Ipv6CidrBlock": cidr,
        "RuleAction": action,
        "Protocol": protocol,
        "Egress": egress,
    }
    if ports is not None:
        value["PortRange"] = {"From": ports[0], "To": ports[1]}
    return value


def snapshot(*rules):
    return parse_snapshot({"NetworkAclId": "acl-example", "Entries": list(rules)})


def delta(before, after, **kwargs):
    return compare(
        before,
        after,
        protocol=kwargs.get("protocol", "tcp"),
        port=kwargs.get("port", 443),
        direction=kwargs.get("direction", "ingress"),
    )


class DecisionTests(unittest.TestCase):
    def test_empty_snapshots_deny_everything(self):
        result = delta(snapshot(), snapshot())
        self.assertFalse(result["changed"])
        self.assertEqual(result["families"]["ipv6"]["before_allowed"]["address_count"], "0")

    def test_whole_ipv4_universe(self):
        result = delta(snapshot(), snapshot(rule(cidr="0.0.0.0/0")))
        self.assertEqual(result["families"]["ipv4"]["newly_allowed"]["cidrs"], ["0.0.0.0/0"])
        self.assertEqual(result["families"]["ipv4"]["newly_allowed"]["address_count"], "4294967296")

    def test_whole_ipv6_universe_without_enumeration(self):
        result = delta(snapshot(), snapshot(rule(cidr="::/0")))
        detail = result["families"]["ipv6"]["newly_allowed"]
        self.assertEqual(detail["cidrs"], ["::/0"])
        self.assertEqual(detail["address_count"], str(2**128))
        self.assertEqual(detail["first_address"], "::")

    def test_priority_deny_splits_later_allow(self):
        result = delta(snapshot(rule()), snapshot(rule(), rule(50, "192.0.2.64/26", "deny")))
        self.assertEqual(result["families"]["ipv4"]["newly_denied"]["cidrs"], ["192.0.2.64/26"])
        self.assertEqual(result["families"]["ipv4"]["after_allowed"]["address_count"], "192")

    def test_later_deny_is_shadowed(self):
        result = delta(snapshot(rule()), snapshot(rule(), rule(200, "192.0.2.0/25", "deny")))
        self.assertFalse(result["changed"])
        self.assertEqual(result["families"]["ipv4"]["after_shadowed_rules"], [200])

    def test_reordering_rules_changes_policy(self):
        result = delta(
            snapshot(rule(), rule(50, "192.0.2.0/25", "deny")),
            snapshot(rule(), rule(150, "192.0.2.0/25", "deny")),
        )
        self.assertEqual(result["families"]["ipv4"]["newly_allowed"]["cidrs"], ["192.0.2.0/25"])

    def test_adjacent_allow_ranges_coalesce(self):
        result = delta(snapshot(), snapshot(rule(100, "192.0.2.0/25"), rule(101, "192.0.2.128/25")))
        self.assertEqual(result["families"]["ipv4"]["after_allowed"]["cidrs"], ["192.0.2.0/24"])

    def test_all_protocol_ignores_its_port_range(self):
        result = delta(snapshot(), snapshot(rule(protocol="-1", ports=(1, 2))), protocol="udp")
        self.assertTrue(result["changed"])

    def test_wrong_protocol_or_port_does_not_match(self):
        after = snapshot(
            rule(100, protocol="1", ports=None), rule(101, protocol="17"), rule(102, ports=(0, 442))
        )
        self.assertFalse(delta(snapshot(), after)["changed"])

    def test_port_range_edges_and_zero(self):
        after = snapshot(rule(ports=(0, 65535)))
        for port in (0, 65535):
            self.assertTrue(delta(snapshot(), after, port=port)["changed"])

    def test_direction_is_independent(self):
        after = snapshot(rule(egress=True))
        self.assertFalse(delta(snapshot(), after)["changed"])
        self.assertTrue(delta(snapshot(), after, direction="egress")["changed"])

    def test_default_rules_can_repeat_across_families_and_directions(self):
        after = snapshot(
            *(
                rule(32767, cidr, "deny", "-1", None, egress)
                for cidr in ("0.0.0.0/0", "::/0")
                for egress in (False, True)
            )
        )
        self.assertFalse(delta(snapshot(), after)["changed"])

    def test_family_extremes_and_both_deltas(self):
        old = snapshot(
            rule(cidr="255.255.255.255/32"),
            rule(200, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
        )
        new = snapshot(rule(cidr="0.0.0.0/32"), rule(200, "::/128"))
        result = delta(old, new)
        for family in ("ipv4", "ipv6"):
            self.assertEqual(result["families"][family]["newly_allowed"]["address_count"], "1")
            self.assertEqual(result["families"][family]["newly_denied"]["address_count"], "1")

    def test_equivalent_redundant_policy_is_unchanged(self):
        self.assertFalse(delta(snapshot(rule()), snapshot(rule(), rule(200)))["changed"])

    def test_randomized_independent_point_oracle(self):
        rng = random.Random(20261024)  # noqa: S311 - reproducible test data, not security
        checks = 0
        for version, base in (
            (4, int(ipaddress.ip_address("192.0.2.0"))),
            (6, int(ipaddress.ip_address("2001:db8::"))),
        ):
            address_type = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
            for _ in range(35):
                documents = []
                for _side in range(2):
                    entries = []
                    for number in range(10, 25):
                        width = 1 << rng.randrange(0, 9)
                        offset = rng.randrange(256 // width) * width
                        cidr = f"{address_type(base + offset)}/{(32 if version == 4 else 128) - (width.bit_length() - 1)}"
                        proto = rng.choice(("6", "17", "-1", "1"))
                        start = rng.randrange(0, 4)
                        entries.append(
                            rule(
                                number,
                                cidr,
                                rng.choice(("allow", "deny")),
                                proto,
                                (start, start + rng.randrange(0, 3))
                                if proto in ("6", "17")
                                else None,
                                rng.choice((False, True)),
                            )
                        )
                    rng.shuffle(entries)
                    documents.append(entries)
                port = rng.randrange(0, 6)
                egress = rng.choice((False, True))
                proto = rng.choice(("tcp", "udp"))
                result = delta(
                    snapshot(*documents[0]),
                    snapshot(*documents[1]),
                    port=port,
                    protocol=proto,
                    direction="egress" if egress else "ingress",
                )["families"][f"ipv{version}"]

                def decision(entries, address, egress=egress, proto=proto, port=port):
                    for entry in sorted(entries, key=lambda item: item["RuleNumber"]):
                        if entry["Egress"] != egress or entry["Protocol"] not in (
                            "-1",
                            "6" if proto == "tcp" else "17",
                        ):
                            continue
                        if address not in ipaddress.ip_network(
                            entry.get("CidrBlock", entry.get("Ipv6CidrBlock"))
                        ):
                            continue
                        if entry["Protocol"] != "-1":
                            ports = entry["PortRange"]
                            if not ports["From"] <= port <= ports["To"]:
                                continue
                        return entry["RuleAction"] == "allow"
                    return False

                gained = [ipaddress.ip_network(cidr) for cidr in result["newly_allowed"]["cidrs"]]
                lost = [ipaddress.ip_network(cidr) for cidr in result["newly_denied"]["cidrs"]]
                counts = [0, 0]
                for offset in range(256):
                    address = address_type(base + offset)
                    before = decision(documents[0], address)
                    after = decision(documents[1], address)
                    expected = (after and not before, before and not after)
                    actual = (
                        any(address in network for network in gained),
                        any(address in network for network in lost),
                    )
                    self.assertEqual(actual, expected)
                    counts = [counts[index] + int(expected[index]) for index in (0, 1)]
                    checks += 1
                self.assertEqual(
                    [result[key]["address_count"] for key in ("newly_allowed", "newly_denied")],
                    [str(count) for count in counts],
                )
        self.assertEqual(checks, 17920)


class ValidationTests(unittest.TestCase):
    def test_multi_acl_requires_unambiguous_selector(self):
        document = {
            "NetworkAcls": [{"NetworkAclId": name, "Entries": []} for name in ("acl-a", "acl-b")]
        }
        with self.assertRaises(InputError):
            parse_snapshot(document)
        self.assertEqual(parse_snapshot(document, "acl-b").acl_id, "acl-b")
        for selector in ("missing", "acl-a"):
            broken = copy.deepcopy(document)
            if selector == "acl-a":
                broken["NetworkAcls"].append(broken["NetworkAcls"][0])
            with self.assertRaises(InputError):
                parse_snapshot(broken, selector)

    def test_envelope_types_and_limits(self):
        for document in (
            [],
            {},
            {"NetworkAcls": []},
            {"NetworkAcls": [None]},
            {"NetworkAcls": [{}] * 257},
            {"Entries": [rule()] * 2001},
            {"Entries": [], "NetworkAclId": 42},
            {"Entries": [], "NetworkAclId": "a" * 257},
        ):
            with self.subTest(document_type=type(document).__name__), self.assertRaises(InputError):
                parse_snapshot(document)

    def test_malformed_fields_fail_even_for_nonmatching_rules(self):
        mutations = [
            ("RuleNumber", True),
            ("RuleNumber", 0),
            ("RuleNumber", 32768),
            ("Egress", 0),
            ("RuleAction", "ALLOW"),
            ("Protocol", 6),
            ("Protocol", "tcp"),
            ("Protocol", "256"),
            ("CidrBlock", "192.0.2.1/24"),
            ("CidrBlock", "::/0"),
            ("CidrBlock", "garbage"),
            ("CidrBlock", None),
            ("PortRange", []),
            ("PortRange", {"From": 2, "To": 1}),
            ("PortRange", {"From": False, "To": 9}),
            ("PortRange", {"From": 0, "To": 65536}),
        ]
        for field, value in mutations:
            entry = rule(egress=True)
            entry[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(InputError):
                snapshot(entry)

    def test_missing_and_conflicting_fields(self):
        for field in ("RuleNumber", "Egress", "Protocol", "RuleAction", "CidrBlock", "PortRange"):
            entry = rule()
            del entry[field]
            with self.subTest(field=field), self.assertRaises(InputError):
                snapshot(entry)
        with self.assertRaises(InputError):
            snapshot({**rule(), "Ipv6CidrBlock": "::/0"})
        with self.assertRaises(InputError):
            snapshot(None)

    def test_duplicate_rule_numbers(self):
        with self.assertRaises(InputError):
            snapshot(rule(), rule())

    def test_default_rule_may_not_allow(self):
        with self.assertRaises(InputError):
            snapshot(rule(32767, "0.0.0.0/0", "allow", "-1", None))

    def test_query_validation(self):
        for kwargs in (
            {"port": -1},
            {"port": 65536},
            {"port": True},
            {"protocol": "icmp"},
            {"direction": "both"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(InputError):
                delta(snapshot(), snapshot(), **kwargs)

    def test_file_loader_and_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "acl.json"
            path.write_bytes(
                b'\xef\xbb\xbf{"NetworkAcls":[{"NetworkAclId":"acl-test","Entries":[]}]}'
            )
            self.assertEqual(load_snapshot(path).acl_id, "acl-test")

    def test_invalid_json_duplicate_keys_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            for payload in (
                b'{"Entries":[],"Entries":[]}',
                b'{"Entries":[],"x":NaN}',
                b"\xff",
                b"{",
                b"[" * 1500,
            ):
                path.write_bytes(payload)
                with self.subTest(payload=payload[:30]), self.assertRaises(InputError):
                    load_snapshot(path)

    def test_depth_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "deep.json"
            path.write_text(
                '{"Entries":[],"extra":' + "[" * 130 + "0" + "]" * 130 + "}", encoding="utf-8"
            )
            with self.assertRaises(InputError):
                load_snapshot(path)

    def test_missing_directory_and_oversize_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InputError):
                load_snapshot(Path(temp) / "missing")
            with self.assertRaises(InputError):
                load_snapshot(temp)
            path = Path(temp) / "big"
            with path.open("wb") as stream:
                stream.truncate(MAX_BYTES + 1)
            with self.assertRaises(InputError):
                load_snapshot(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO safety check")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pipe"
            os.mkfifo(path)
            with self.assertRaises(InputError):
                load_snapshot(path)


class CliTests(unittest.TestCase):
    def test_in_process_report_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "acl.json"
            path.write_text(json.dumps({"Entries": [rule()]}), encoding="utf-8")
            for format_name in ("json", "text"):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    status = main(
                        [
                            str(path),
                            str(path),
                            "--protocol",
                            "tcp",
                            "--port",
                            "443",
                            "--format",
                            format_name,
                        ]
                    )
                self.assertEqual(status, 0)
                if format_name == "json":
                    self.assertFalse(json.loads(output.getvalue())["changed"])
                else:
                    self.assertIn("unchanged", output.getvalue())
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(
                    main([str(path), str(path), "--protocol", "tcp", "--port", "-1"]), 2
                )
            self.assertIn("port", errors.getvalue())
            with patch("builtins.print", side_effect=BrokenPipeError):
                self.assertEqual(
                    main([str(path), str(path), "--protocol", "tcp", "--port", "443"]), 2
                )

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "nacldelta", *map(str, args)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
        )

    def test_help_and_version(self):
        self.assertEqual(self.run_cli("--version").stdout.strip(), "0.1.0")
        self.assertEqual(self.run_cli("--help").returncode, 0)

    def test_changed_unchanged_and_text_workflows(self):
        with tempfile.TemporaryDirectory() as temp:
            before, after = Path(temp) / "before.json", Path(temp) / "after.json"
            before.write_text(json.dumps({"Entries": []}), encoding="utf-8")
            after.write_text(json.dumps({"Entries": [rule()]}), encoding="utf-8")
            result = self.run_cli(before, after, "--protocol", "tcp", "--port", 443)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["families"]["ipv4"]["newly_allowed"]["cidrs"],
                ["192.0.2.0/24"],
            )
            result = self.run_cli(
                after, after, "--protocol", "tcp", "--port", 443, "--format", "text"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("unchanged", result.stdout)
            self.assertIn("(none)", result.stdout)
            result = self.run_cli(
                before, after, "--protocol", "tcp", "--port", 443, "--format", "text"
            )
            self.assertIn("192.0.2.0/24", result.stdout)

    def test_invalid_input_and_argument_exit_two(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text(
                '{"Entries":[],"bad\\u001b[31m":1,"bad\\u001b[31m":2}', encoding="utf-8"
            )
            result = self.run_cli(path, path, "--protocol", "tcp", "--port", 443)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("\x1b", result.stderr)
        self.assertEqual(self.run_cli().returncode, 2)


if __name__ == "__main__":
    unittest.main()
