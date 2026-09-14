# Security policy

Hyperconsciousness handles private knowledge and device permissions. Treat any
confidentiality, integrity, authorization, recovery, or update failure as a
security issue.

## Supported versions

Until 1.0, only the latest tagged prerelease and current `main` receive security
fixes. The project does not promise backward compatibility for unreleased APIs,
but it does preserve the documented encrypted record format.

## Reporting

Do not open a public issue containing an exploit, credential, private record,
recovery phrase, device key, grant, or customer data. Use GitHub's private
**Report a vulnerability** flow in the repository Security tab.

Include the affected version, operating system, expected security boundary, a
minimal reproduction, and whether any real data or keys were exposed. Replace
all sensitive values with synthetic examples.

The protocol threat model and stated limits live in
[`docs/CONSTRAINTS.md`](docs/CONSTRAINTS.md). Installing an agent skill does not
grant access to an encrypted store or to Hyperconsciousness Companion.
