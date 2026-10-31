# Security Policy

## Scope

This repository contains security research artifacts: proof-of-concept
verifiers, lab Docker Compose setups, static-analysis tooling, detection
rules, and findings documents. It is not a supported product and receives no
security updates or service-level commitments.

## Lab-only use

Every PoC and lab in this repository targets loopback only: `localhost`,
`127.0.0.0/8`, or `::1`. The only commands permitted are the fixed benign
allowlist: `id`, `uname`, and `whoami`. The artifacts are not authorized for
use against systems you do not own or have explicit written permission to
test. Do not repackage them for remote targets.

## Reporting a problem in this repository

Report vulnerabilities in the repository's own code, for example a verifier
that escapes loopback scope or a script that can execute arbitrary commands,
by email to:

    hello@paxdynamics.com

Send plain text. Include the affected path, a minimal description, and the
version or commit. Do not send a PoC that runs against third-party systems,
and do not include live credentials or personal data.

We will acknowledge valid reports and correct the repository artifacts. We do
not operate a bug bounty program.

## Vendor disclosure

This repository does not accept or broker vulnerability reports for PHP or
for third-party applications. Findings about PHP itself belong with the PHP
project at security@php.net. Findings about Drupal, Joomla, WordPress,
Roundcube, Composer packages, or other third-party code belong with the
respective vendor or maintainer. Follow each vendor's disclosure policy.

## What we will not accept

- Packaging or instructions for remote targets
- Reverse shells or command-and-control code
- Persistence, privilege escalation, or lateral movement
- Mass scanning or internet-wide enumeration
- Arbitrary command payloads beyond the benign allowlist

Such contributions will be closed without merge.
