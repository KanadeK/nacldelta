"""Nacldelta command line; stdout is the report, stderr is input diagnostics."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import InputError, compare, load_snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare effective AWS NACL address decisions for one service."
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("before", help="Before: AWS describe-network-acls JSON or one ACL object")
    parser.add_argument("after", help="After: AWS describe-network-acls JSON or one ACL object")
    parser.add_argument(
        "--before-id", help="Required selector when the before export contains multiple ACLs"
    )
    parser.add_argument(
        "--after-id", help="Required selector when the after export contains multiple ACLs"
    )
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--direction", choices=("ingress", "egress"), default="ingress")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        before = load_snapshot(args.before, args.before_id)
        after = load_snapshot(args.after, args.after_id)
        report = compare(
            before, after, protocol=args.protocol, port=args.port, direction=args.direction
        )
    except InputError as exc:
        print(f"nacldelta: {ascii(str(exc))[1:-1]}", file=sys.stderr)
        return 2
    try:
        if args.format == "json":
            print(json.dumps(report, indent=2, ensure_ascii=True))
        else:
            print(
                f"{args.direction} {args.protocol}/{args.port}: {'changed' if report['changed'] else 'unchanged'}"
            )
            for family, result in report["families"].items():
                for key in ("newly_allowed", "newly_denied"):
                    detail = result[key]
                    print(
                        f"{family} {key}: {', '.join(detail['cidrs']) or '(none)'} ({detail['address_count']} addresses)"
                    )
    except (BrokenPipeError, OSError):
        return 2
    return 1 if report["changed"] else 0
