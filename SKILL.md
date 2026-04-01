---
name: forgeguard-supply-chain
description: Perform deep security reviews of open-source software, internal repositories, dependencies, build pipelines, release artifacts, and software supply-chain trust signals. Use when reviewing a repository for malicious code, backdoors, maintainer-takeover risk, suspicious release engineering, CI/CD abuse, dependency risk, provenance/signature gaps, or source-vs-artifact inconsistencies, including xz-style attacks and other high-impact OSS compromise patterns.
---

# ForgeGuard Supply Chain

Use this skill for deep security reviews of repositories where trust, release integrity, and supply-chain compromise matter as much as traditional code defects.

Perform a trust-focused security review, not just a vulnerability scan. Treat the repository, its maintainers, dependencies, build logic, release process, and published artifacts as part of one attack surface.

## Quick Start

1. Establish scope: repository, package name, language, package manager, release channel, criticality.
2. Run `scripts/repo_triage.py <repo-root>` for a fast local triage.
3. Read `references/review-workflow.md` and follow the phases in order.
4. Load `references/xz-style-heuristics.md` when backdoor or release-engineering abuse is a concern.
5. Load `references/report-template.md` when producing a final report.

## Review Priorities

Prioritize these classes of risk:

- Malicious or suspicious code paths
- Dependency and transitive dependency compromise
- Build-script, CI/CD, release, and packaging abuse
- Source vs release artifact drift
- Maintainer trust and governance weaknesses
- Provenance, signing, reproducibility, and SBOM gaps
- Hidden payloads in tests, fixtures, generated files, compressed assets, or binaries

## Workflow

### 1. Classify the target

Capture:

- Repository URL and default branch
- Ecosystem: npm, PyPI, Cargo, Go, Maven, Debian/RPM, etc.
- Release outputs: source tarballs, binaries, containers, packages
- Whether the review is source-only or source plus published artifacts
- Whether the target is security-sensitive: crypto, compression, auth, update agent, networking, init/system service, package manager, kernel/driver, CI runner, secrets tooling

If the target is high-impact infrastructure or a transitive dependency used by many systems, raise scrutiny and prefer exhaustive review.

### 2. Perform fast local triage

Run the triage script and inspect:

- Executable hooks in package/build metadata
- Obfuscated, base64-heavy, binary, or compressed files in unusual places
- Network access in build/test/install scripts
- New or unusual CI workflows and release jobs
- Generated files checked into the repo
- High-risk file names and extension combinations

Do not treat script output as proof. Use it to focus manual review.

### 3. Review trust and governance

Check repository trust signals before reading code deeply:

- Recent maintainer changes and contributor churn
- Sudden privilege expansion or ownership transfer
- Branch protection and review enforcement
- Release cadence anomalies and rushed hotfix patterns
- Project bus factor and single-maintainer dependency
- Security policy, disclosure path, signed tags/releases, reproducible-build claims

A technically clean diff can still be high risk when governance signals are weak.

### 4. Review dependency risk

Inspect:

- Newly added direct dependencies
- Lockfile churn and unexpected transitive changes
- Postinstall/install/build hooks
- Git-based or URL-based dependencies
- Vendored code and copied third-party blobs
- Typosquatting, namespace confusion, abandoned packages, sudden maintainer changes

Prefer exact version pinning for critical builds. Treat floating ranges, remote downloads, and unaudited vendoring as risk amplifiers.

### 5. Review build, packaging, and release logic

Inspect every path from source to artifact:

- Makefiles, configure scripts, build.rs, setup.py, pyproject hooks, npm scripts, shell wrappers, Dockerfiles, release YAML
- Conditional logic triggered only in release mode, specific OSes, or specific build environments
- Generated code included in release archives but absent from main source review flow
- Test fixtures, compressed files, and binary blobs unpacked or executed during build/test
- Downloaded tools or remote scripts in CI/release jobs

If source tarballs or release archives exist, compare them with the repository source whenever possible.

### 6. Review code for malicious intent, not only bugs

Look for:

- Authentication bypasses, environment-gated behavior, and stealthy conditionals
- Logic triggered only for specific users, processes, keys, locale, hostname, build flags, or timing
- Data exfiltration paths disguised as telemetry, debug, crash reporting, or update checks
- Abuse of unsafe parsing, decompression, deserialization, reflection, dynamic loading, or shell execution
- Hidden crypto/key-material handling and trust-store tampering
- Suspicious anti-debug, anti-test, or anti-analysis logic

Ask: "What would I do here if I wanted a backdoor to survive review?"

### 7. Review source-vs-artifact integrity

When artifacts are available, compare:

- Repository tag vs release tarball contents
- Generated files and checksums
- Embedded objects, binary sections, scripts, and packed assets
- Signatures, attestations, provenance, SBOM presence, and digest consistency

Escalate findings where released artifacts contain code or data not easily attributable to reviewed source.

### 8. Produce a risk-ranked report

Structure findings by severity and exploitability:

- Critical: likely malicious, artifact drift, signed-release inconsistency, hidden execution path, credential exfil path
- High: trust breakdown, dangerous install/build hook, unaudited remote fetch, suspicious obfuscation in privileged path
- Medium: weak governance, poor provenance, unnecessary binary blobs, risky dependency policy
- Low: hygiene gaps and missing hardening controls

Always separate facts, evidence, hypotheses, and recommended validation steps.

## Decision Rules

Escalate immediately when any of these appear together:

- New maintainer or unusual social/governance change
- Release-only or environment-specific code path
- Binary or compressed blob with unclear origin
- Build/test/install script that downloads, unpacks, or executes hidden content
- Artifact contents not explained by source

Multiple weak signals together can justify a high-risk conclusion even if no single line is obviously malicious.

## Output Requirements

When reporting:

- Quote exact file paths and suspicious snippets
- Explain why the pattern matters operationally
- Distinguish observed behavior from inferred intent
- List confidence level and what would raise/lower confidence
- Recommend containment actions for severe findings

## Resources

- Review workflow: `references/review-workflow.md`
- XZ-style heuristics: `references/xz-style-heuristics.md`
- Report template: `references/report-template.md`
- Local triage script: `scripts/repo_triage.py`
