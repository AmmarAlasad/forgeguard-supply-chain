# Review Workflow

## 1. Intake

Collect:

- Repo URL / local path
- Ecosystem and build system
- Criticality of the component
- Intended deployment context
- Whether published artifacts are in scope

Questions to answer early:

- Is this project security-critical or widely transitive?
- Does it run with elevated privileges?
- Does it process untrusted input?
- Does it participate in update, authentication, package, build, or crypto workflows?

## 2. Repository Trust Review

Review governance and trust before deep code reading:

- Maintainer count and activity
- Recent ownership, permission, or release-manager changes
- Branch protection and required reviews
- Signed tags or release signatures
- Security policy and incident response path
- Sudden burst of low-quality commits or social pressure patterns

## 3. Dependency Review

Inspect:

- Manifest files
- Lockfiles
- Vendored directories
- Git submodules and subtree imports
- URL-based downloads
- Install/build hooks

Flag:

- Exact package newly added to privileged paths
- Postinstall/preinstall hooks
- Dependency swaps that change trust boundary
- Binary-only dependencies with weak provenance

## 4. Build and CI/CD Review

Read:

- GitHub Actions / GitLab CI / other workflow files
- Build scripts and wrappers
- Packaging recipes
- Release scripts
- Container build files

Flag:

- Curl | sh patterns
- Remote downloads without checksum verification
- Secret exposure in build logic
- Conditional jobs for tags, nightly, or release events only
- Generated source not regenerated in CI

## 5. Code Review for Malicious Behavior

Focus on:

- Conditional execution paths
- Dynamic loading and shell execution
- Encoded strings / runtime decoding
- Silent auth decisions
- Key / signature verification logic
- Memory-unsafe parsing in high-value paths
- Logging suppression or stealth behavior

## 6. Artifact Consistency Review

Compare source, tag, release, and package outputs:

- File list differences
- Embedded binaries and compressed fixtures
- Build-generated code
- Checksums and signature state
- SBOM / provenance claims

## 7. Reporting

For each finding, provide:

- Title
- Severity
- Confidence
- Evidence
- Abuse scenario
- Recommended validation / containment

Avoid overstating intent without evidence. State when something is suspicious versus proven malicious.
