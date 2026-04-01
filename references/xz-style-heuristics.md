# XZ-Style Heuristics

Use this file when looking for sophisticated supply-chain abuse, especially where a patient attacker hides in normal project operations.

## High-Signal Patterns

### 1. Release-only differences

Look for logic or files that appear only in:

- release tarballs
- generated configure/build output
- packaging recipes
- CI release jobs
- downstream distro patches

Why it matters: a reviewer may inspect the repository while the payload lives in released artifacts or generated files.

### 2. Benign-looking test data or fixtures

Inspect:

- compressed test archives
- binary fixtures
- corpora files
- images/audio with unusual entropy or size
- test helpers that unpack and execute content

Why it matters: payload staging can hide in fixtures that look harmless.

### 3. Build-stage unpack / transform / execute chains

Flag chains like:

- extract -> decode -> patch -> compile
- test helper -> shell -> environment gate -> object injection
- m4/autoconf macros that write shell fragments

Why it matters: the malicious behavior may emerge only after multiple transformation steps.

### 4. Social and governance precursors

Check for:

- maintainer burnout or pressure
- sudden transfer of release responsibility
- unusual advocacy for broad distro adoption before scrutiny
- attacks on reviewers or pressure to merge quickly

Why it matters: xz was not just a code event; it was a trust and governance event.

### 5. Environment-gated execution

Look for conditions on:

- architecture
- distro or libc
- presence of specific binaries/processes
- package build flags
- deb/rpm build environments
- SSH/auth/service runtime context

Why it matters: targeted activation reduces discovery during casual testing.

### 6. Stealth and anti-analysis

Watch for:

- disabled logs
- checks that avoid running under tests, debuggers, sanitizers, CI, or containers
- misleading comments or innocuous names for high-impact code
- uncommon macro tricks or shell quoting layers

## Escalation Rule

Treat the situation as potentially critical when at least one governance anomaly and one technical anomaly point to the same code path or release path.
