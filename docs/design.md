# Contract and design

## Acceptance scenario

A reviewer has two AWS CLI JSON exports. For ingress TCP/443, an added deny at rule 50 precedes an allow at 100. The tool reports the exact carved-out range and exits 1. Moving the deny after the allow leaves the allowed set unchanged (exit 0) and lists that deny as fully shadowed. A malformed rule, ambiguous ACL selection or unsupported query must fail with exit 2 instead of reporting equal policies.

## Model

For each address family, begin with one undecided closed interval covering the family. Visit rules in ascending numeric order. Direction, protocol and inclusive destination-port range filter rules for this query. Intersect a matching rule's CIDR with undecided intervals. Add hits to the allowed set only for allow rules; remove hits from undecided intervals for either action. Remaining undecided addresses implicitly deny.

Merge adjacent allowed intervals. Subtract before from after for newly allowed, and after from before for newly denied. Convert intervals to canonical CIDRs using `ipaddress.summarize_address_range`, explicitly selecting IPv4Address/IPv6Address so low-valued IPv6 addresses retain their family. Counts use exact integers serialized as decimal strings. Address count does not affect running time. Fragmentation makes worst-case rule evaluation quadratic; the selected rule count is bounded.

`Rule` and `Snapshot` are immutable parsed records; construct them through `parse_snapshot` or `load_snapshot`. `effective` is an internal building block expecting validated records/query. `compare` validates the public query and returns a JSON-compatible schema-1 dictionary. Reports deliberately exclude unrelated tags, associations and AWS account metadata.

## Input decisions

Validate every rule in the selected ACL, including rules outside the requested direction. Unknown AWS metadata is tolerated. Duplicate JSON keys, invalid protocol strings, missing TCP/UDP ranges, conflicting families and noncanonical CIDRs are rejected. Rule 32767 is accepted only as an all-protocol `/0` deny; IPv4 and IPv6 default entries are distinct. A default deny need not be explicitly present because missing matches deny. Input editing concurrent with analysis is unsupported.

This is a comparison of exported ACL rules, not a validator of every AWS service quota or a prediction that an AWS API will accept edited JSON. CIDR family and direction determine independent matching domains. API canonicalization, traffic exemptions, security groups and routing remain external to this model.

## Privacy and licenses

Only local files are opened, never URLs or credentials. No subprocesses or network calls occur at runtime. stdout contains operational identifiers/address ranges, so it is not anonymized. The implementation and synthetic documentation fixtures are original MIT code. Python standard-library modules are used; no third-party runtime code or audio/network captures are bundled. Development/build packages remain separate from the wheel.

Sources: [AWS entry fields](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_NetworkAclEntry.html), [rule semantics](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-rules.html). Broader alternative: [Batfish](https://github.com/batfish/batfish).
