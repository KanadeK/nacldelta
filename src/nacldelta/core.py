"""Exact, first-match address decisions for one exported NACL service tuple."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_BYTES = 8 * 1024 * 1024
MAX_RULES = 2000
Interval = tuple[int, int]


class InputError(ValueError):
    """An input cannot be safely interpreted within the supported contract."""


@dataclass(frozen=True)
class Rule:
    number: int
    egress: bool
    version: int
    first: int
    last: int
    protocol: int
    action: str
    ports: tuple[int, int] | None


@dataclass(frozen=True)
class Snapshot:
    acl_id: str | None
    rules: tuple[Rule, ...]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise InputError(f"Non-JSON numeric constant: {value}")


def _integer(value: Any, low: int, high: int, field: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise InputError(f"{field} must be an integer in {low}..{high}")
    return value


def parse_snapshot(document: Any, acl_id: str | None = None) -> Snapshot:
    """Parse AWS CLI JSON or a single ACL object. Do not silently select an ACL."""
    if not isinstance(document, dict):
        raise InputError("Root must be an object")
    if "NetworkAcls" in document:
        acls = document["NetworkAcls"]
        if not isinstance(acls, list) or not 1 <= len(acls) <= 256:
            raise InputError("NetworkAcls must contain 1..256 ACL objects")
    else:
        acls = [document]
    if any(not isinstance(acl, dict) for acl in acls):
        raise InputError("Every ACL must be an object")
    if acl_id is not None:
        selected = [acl for acl in acls if acl.get("NetworkAclId") == acl_id]
        if len(selected) != 1:
            raise InputError("ACL selector must match exactly one NetworkAclId")
        acl = selected[0]
    elif len(acls) == 1:
        acl = acls[0]
    else:
        raise InputError("Multiple ACLs: supply an explicit ACL selector")
    identifier = acl.get("NetworkAclId")
    if identifier is not None and (not isinstance(identifier, str) or len(identifier) > 256):
        raise InputError("NetworkAclId must be a string of at most 256 characters")
    entries = acl.get("Entries")
    if not isinstance(entries, list) or len(entries) > MAX_RULES:
        raise InputError(f"Entries must be an array of at most {MAX_RULES} rules")
    rules: list[Rule] = []
    seen: set[tuple[bool, int, int]] = set()
    for index, entry in enumerate(entries):
        prefix = f"Entries[{index}]"
        if not isinstance(entry, dict):
            raise InputError(f"{prefix} must be an object")
        number = _integer(entry.get("RuleNumber"), 1, 32767, prefix + ".RuleNumber")
        egress = entry.get("Egress")
        if type(egress) is not bool:
            raise InputError(f"{prefix}.Egress must be a boolean")
        action = entry.get("RuleAction")
        if action not in ("allow", "deny"):
            raise InputError(f"{prefix}.RuleAction must be allow or deny")
        protocol = entry.get("Protocol")
        if not isinstance(protocol, str) or not re.fullmatch(r"-1|[0-9]{1,3}", protocol):
            raise InputError(f"{prefix}.Protocol must be a numeric AWS protocol string")
        protocol_number = int(protocol)
        if protocol_number > 255:
            raise InputError(f"{prefix}.Protocol exceeds 255")
        fields = [key for key in ("CidrBlock", "Ipv6CidrBlock") if key in entry]
        if len(fields) != 1 or not isinstance(entry[fields[0]], str):
            raise InputError(f"{prefix} must have exactly one IPv4 or IPv6 CIDR")
        try:
            network = ipaddress.ip_network(entry[fields[0]], strict=True)
        except ValueError as exc:
            raise InputError(f"{prefix}: invalid or noncanonical CIDR") from exc
        version = 4 if fields[0] == "CidrBlock" else 6
        if network.version != version:
            raise InputError(f"{prefix}: CIDR family does not match its field")
        key = (egress, version, number)
        if key in seen:
            raise InputError(f"{prefix}: duplicate rule number within direction/address family")
        seen.add(key)
        ports = None
        if "PortRange" in entry:
            raw = entry["PortRange"]
            if not isinstance(raw, dict):
                raise InputError(f"{prefix}.PortRange must be an object")
            first = _integer(raw.get("From"), 0, 65535, prefix + ".PortRange.From")
            last = _integer(raw.get("To"), 0, 65535, prefix + ".PortRange.To")
            if first > last:
                raise InputError(f"{prefix}: inverted port range")
            ports = (first, last)
        if protocol_number in (6, 17) and ports is None:
            raise InputError(f"{prefix}: TCP/UDP rule requires PortRange")
        if number == 32767 and (
            action != "deny" or protocol_number != -1 or network.prefixlen != 0
        ):
            raise InputError(f"{prefix}: rule 32767 must be the default all-protocol /0 deny")
        rules.append(
            Rule(
                number,
                egress,
                version,
                int(network.network_address),
                int(network.broadcast_address),
                protocol_number,
                action,
                ports,
            )
        )
    return Snapshot(identifier, tuple(sorted(rules, key=lambda rule: rule.number)))


def load_snapshot(path: str | Path, acl_id: str | None = None) -> Snapshot:
    """Bound regular-file reads, reject duplicate keys, constants and excessive nesting."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
                raise InputError("Input must be a regular file no larger than 8 MiB")
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
            if len(raw) > MAX_BYTES or (before.st_size, before.st_mtime_ns) != (
                after.st_size,
                after.st_mtime_ns,
            ):
                raise InputError("Input exceeds 8 MiB or changed while being read")
    except OSError as exc:
        raise InputError(f"Cannot read input: {exc.strerror or 'I/O error'}") from exc
    try:
        document = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError(f"Invalid JSON: {exc}") from exc
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 128:
            raise InputError("JSON nesting exceeds 128 levels")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return parse_snapshot(document, acl_id)


def merge(intervals: list[Interval]) -> list[Interval]:
    """Canonical disjoint, ordered, closed intervals."""
    result: list[Interval] = []
    for first, last in sorted(intervals):
        if result and first <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(last, result[-1][1]))
        else:
            result.append((first, last))
    return result


def subtract(left: list[Interval], right: list[Interval]) -> list[Interval]:
    """Set difference between sorted disjoint closed-interval lists, without expansion."""
    result: list[Interval] = []
    index = 0
    for first, last in left:
        cursor = first
        while index < len(right) and right[index][1] < cursor:
            index += 1
        other = index
        while other < len(right) and right[other][0] <= last:
            cut_first, cut_last = right[other]
            if cut_first > cursor:
                result.append((cursor, cut_first - 1))
            cursor = max(cursor, cut_last + 1)
            if cursor > last:
                break
            other += 1
        if cursor <= last:
            result.append((cursor, last))
    return result


def effective(
    snapshot: Snapshot, version: int, protocol: int, port: int, egress: bool
) -> tuple[list[Interval], list[int]]:
    """Compute allowed addresses and fully shadowed rules for a validated query."""
    remaining = [(0, (1 << (32 if version == 4 else 128)) - 1)]
    allowed: list[Interval] = []
    shadowed: list[int] = []
    for rule in snapshot.rules:
        if rule.version != version or rule.egress != egress or rule.protocol not in (-1, protocol):
            continue
        if rule.protocol != -1 and rule.ports is not None:
            if not rule.ports[0] <= port <= rule.ports[1]:
                continue
        hits = [
            (max(first, rule.first), min(last, rule.last))
            for first, last in remaining
            if first <= rule.last and last >= rule.first
        ]
        if not hits and rule.number != 32767:
            shadowed.append(rule.number)
        if rule.action == "allow":
            allowed.extend(hits)
        remaining = subtract(remaining, hits)
    return merge(allowed), shadowed


def _ranges(intervals: list[Interval], version: int) -> dict[str, Any]:
    address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return {
        "cidrs": [
            str(network)
            for first, last in intervals
            for network in ipaddress.summarize_address_range(address(first), address(last))
        ],
        "address_count": str(sum(last - first + 1 for first, last in intervals)),
        "first_address": str(address(intervals[0][0])) if intervals else None,
    }


def compare(
    before: Snapshot,
    after: Snapshot,
    *,
    protocol: str,
    port: int,
    direction: str = "ingress",
) -> dict[str, Any]:
    """Return exact newly allowed/denied ranges for a single service and direction."""
    if protocol not in ("tcp", "udp") or direction not in ("ingress", "egress"):
        raise InputError("Query requires tcp/udp and ingress/egress")
    _integer(port, 0, 65535, "port")
    families: dict[str, Any] = {}
    changed = False
    for version in (4, 6):
        old, old_shadowed = effective(
            before, version, 6 if protocol == "tcp" else 17, port, direction == "egress"
        )
        new, new_shadowed = effective(
            after, version, 6 if protocol == "tcp" else 17, port, direction == "egress"
        )
        gained, lost = subtract(new, old), subtract(old, new)
        changed = changed or bool(gained or lost)
        families[f"ipv{version}"] = {
            "before_allowed": _ranges(old, version),
            "after_allowed": _ranges(new, version),
            "newly_allowed": _ranges(gained, version),
            "newly_denied": _ranges(lost, version),
            "before_shadowed_rules": old_shadowed,
            "after_shadowed_rules": new_shadowed,
        }
    return {
        "schema_version": 1,
        "scope": {"protocol": protocol, "port": port, "direction": direction},
        "before_acl_id": before.acl_id,
        "after_acl_id": after.acl_id,
        "changed": changed,
        "families": families,
    }
