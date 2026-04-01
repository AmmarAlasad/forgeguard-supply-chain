# ForgeGuard Supply Chain

ForgeGuard Supply Chain is an AgentSkill for deep security review of open-source software, internal repositories, dependencies, build pipelines, and release artifacts.

It is designed for reviews where traditional AppSec checks are not enough — especially when the goal is to detect or reduce the risk of:

- supply-chain compromise
- malicious or suspicious dependency changes
- maintainer-takeover risk
- build and CI/CD abuse
- source-vs-release drift
- xz-style backdoor patterns
- provenance, signing, and artifact-integrity gaps

## What it does

This skill helps an agent review software as a trust system, not just a codebase.

Core coverage:

- repository governance and trust signals
- dependency and transitive-dependency risk
- install/build/release hooks
- CI/CD and packaging abuse
- release-only payload patterns
- binary/compressed fixture inspection heuristics
- source vs artifact consistency review
- provenance, signing, reproducibility, and SBOM gaps
- structured risk-ranked reporting

## Included

- `SKILL.md` — main skill instructions
- `references/review-workflow.md` — full review flow
- `references/xz-style-heuristics.md` — heuristics for stealthy OSS compromise
- `references/report-template.md` — reporting format
- `scripts/repo_triage.py` — fast local triage scanner for suspicious patterns

## Example use cases

Use ForgeGuard when reviewing:

- an open-source dependency before adoption
- a sensitive transitive dependency in your build
- a suspicious upstream update
- a release process that may include generated or hidden artifacts
- a repo where you want more than classic secure-coding review
- infrastructure packages, auth components, crypto libraries, package tooling, update agents, compression libraries, and other high-impact software

## Quick start

### 1. Run the local triage script

```bash
python3 scripts/repo_triage.py /path/to/repo
```

### 2. Follow the review workflow

Start with:

- `references/review-workflow.md`
- `references/xz-style-heuristics.md`

### 3. Produce a report

Use:

- `references/report-template.md`

## Installation as a skill

If your environment supports packaged `.skill` files, package this directory and install the resulting artifact.

From a skill-development environment:

```bash
python3 /home/asapro/.npm-global/lib/node_modules/openclaw/skills/skill-creator/scripts/package_skill.py .
```

## Philosophy

Many dangerous compromises do not look like normal vulnerabilities. They look like:

- a convenient dependency change
- a harmless fixture or test archive
- a release-only script tweak
- a governance change nobody questioned
- a generated artifact nobody compared to source

ForgeGuard is built to surface those patterns early.

## License

MIT
