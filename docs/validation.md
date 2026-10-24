# Validation for 0.1.0

Local environment: Windows, Python 3.13.16. The release workflow separately checks the exact pushed commit on Linux, macOS and Windows, with Python 3.11 and 3.13. The Actions badge and run logs are the source for remote results.

The local suite contains 31 discovered tests: 30 pass on Windows; the POSIX FIFO test is skipped there and runs on POSIX CI. Local statement coverage is 98.74% (239 statements, 3 untraced: the subprocess entry point and concurrent-file-change rejection). CLI subprocess tests actually execute the entry point; their child execution is not included in that coverage figure.

The independent oracle sorts raw rules, tests individual IP addresses and returns the first matching decision. Seventy randomized before/after comparisons across IPv4 and IPv6 verify 17,920 address decisions, including both gained and lost permissions and exact counts. This tests a different implementation from the interval-set algorithm. Whole-family `/0`, zero and maximum addresses, priority, partial/full shadowing, adjacent merging, all-protocol matching, port edges and independent directions have explicit cases.

Negative tests cover duplicate JSON keys/rule numbers, ambiguous ACL selection, incorrect field types, missing ports, incorrect CIDR families, noncanonical CIDRs, nesting, file size, nonregular files and CLI diagnostic escaping. Source fixtures are synthetic and do not require an AWS account.

Release gates also run Ruff lint and formatting checks, build the wheel and source distribution, inspect runtime metadata for zero dependencies/MIT, scan distributable sources for credential/private-key/machine-path patterns, install the wheel into an empty environment without an index, execute its help/version and copied standalone demo, then uninstall it. After upload, the release procedure checks all six CI jobs, commit identities, exact remote history, asset digests and the sole-contributor requirement. The local full logs and receipts are retained outside the repository; source-only new-user installation is checked anonymously after publication.

These are functional regression checks, not a formal proof, AWS service integration test or independent security certification. No live cloud resources were provisioned. No runtime package dependencies are shipped. The strict parser does not claim to enforce every AWS quota or API validation rule.
