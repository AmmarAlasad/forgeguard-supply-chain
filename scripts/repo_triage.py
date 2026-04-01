#!/usr/bin/env python3
import argparse
import json
import os
import re
from collections import defaultdict
from pathlib import Path

TEXT_EXTS = {
    '.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.hh', '.rs', '.go', '.py', '.sh', '.bash', '.zsh',
    '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java', '.kt', '.kts', '.scala', '.rb', '.php',
    '.pl', '.pm', '.swift', '.m', '.mm', '.cs', '.fs', '.lua', '.r', '.toml', '.yaml', '.yml', '.json',
    '.ini', '.cfg', '.conf', '.gradle', '.properties', '.mk', '.am', '.ac', '.m4', '.txt', '.md', '.service'
}

SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', 'dist', 'build', 'target', '.next', '.venv', 'venv', '__pycache__',
    '.idea', '.vscode', '.pytest_cache', '.mypy_cache'
}

HOOK_KEYS = [
    'preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly', 'prepack',
    'postpack', 'postversion', 'preversion', 'build', 'release', 'publish'
]

SUSPICIOUS_NAMES = [
    'postinstall', 'preinstall', 'configure', 'configure.ac', 'configure.in', 'makefile', 'dockerfile',
    'build.rs', 'setup.py', 'pyproject.toml', 'package.json', 'cargo.toml', '.github/workflows', '.gitlab-ci.yml'
]

REGEXES = {
    'network_or_remote_fetch': re.compile(r'(curl|wget|Invoke-WebRequest|powershell\s+-enc|git\s+clone\s+https?://|https?://)', re.I),
    'shell_exec': re.compile(r'(system\(|popen\(|exec\(|subprocess\.|Runtime\.getRuntime\(|ProcessBuilder\(|os\.system\(|child_process)', re.I),
    'encoded_blob': re.compile(r'(base64|fromBase64String|b64decode|[A-Za-z0-9+/]{200,}={0,2})'),
    'archive_ops': re.compile(r'(tar\s+-|unzip\s|gunzip|xz\s+-d|base64\s+-d|openssl\s+enc|uudecode)', re.I),
    'env_gating': re.compile(r'(getenv\(|os\.environ|process\.env|System\.getenv|std::env|uname\(|/proc/|whoami|id\s|hostname)', re.I),
    'anti_analysis': re.compile(r'(ptrace|tracerpid|debugger|sanitize|asan|ubsan|valgrind|strace|gdb|ci\b|github_actions)', re.I),
}

BINARY_EXTS = {'.gz', '.xz', '.bz2', '.zip', '.7z', '.jar', '.war', '.so', '.dll', '.dylib', '.o', '.a', '.bin', '.png', '.jpg', '.jpeg', '.gif', '.pdf'}


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    try:
        with path.open('rb') as f:
            chunk = f.read(2048)
        if b'\x00' in chunk:
            return False
        chunk.decode('utf-8')
        return True
    except Exception:
        return False


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def read_text(path: Path):
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return ''


def analyze_package_json(path: Path, findings: list):
    text = read_text(path)
    try:
        data = json.loads(text)
    except Exception:
        findings.append({'type': 'invalid_json', 'path': str(path), 'detail': 'package.json could not be parsed'})
        return
    scripts = data.get('scripts', {}) or {}
    for key in HOOK_KEYS:
        if key in scripts:
            findings.append({'type': 'npm_hook', 'path': str(path), 'detail': f'{key}: {scripts[key]}'})
    for dep_field in ['dependencies', 'devDependencies', 'optionalDependencies']:
        deps = data.get(dep_field, {}) or {}
        for name, version in deps.items():
            if isinstance(version, str) and ('git+' in version or 'http://' in version or 'https://' in version or version.startswith('github:')):
                findings.append({'type': 'remote_dependency', 'path': str(path), 'detail': f'{dep_field}.{name} -> {version}'})


def scan_file(path: Path, findings: list, stats: dict):
    stats['files_scanned'] += 1
    stats['bytes_scanned'] += path.stat().st_size
    lower_str = str(path).lower()
    for marker in SUSPICIOUS_NAMES:
        if marker in lower_str:
            findings.append({'type': 'high_value_file', 'path': str(path), 'detail': marker})
            break

    if path.suffix.lower() in BINARY_EXTS and path.stat().st_size > 64 * 1024:
        findings.append({'type': 'large_binary_or_archive', 'path': str(path), 'detail': f'{path.stat().st_size} bytes'})

    if path.name == 'package.json':
        analyze_package_json(path, findings)

    if not is_text_file(path):
        return

    text = read_text(path)
    if not text:
        return

    if len(text) > 500_000:
        findings.append({'type': 'large_text_file', 'path': str(path), 'detail': f'{len(text)} chars'})

    for key, regex in REGEXES.items():
        match = regex.search(text)
        if match:
            line_no = text[:match.start()].count('\n') + 1
            excerpt = text[max(0, match.start()-80):match.end()+120].replace('\n', ' ')
            findings.append({
                'type': key,
                'path': str(path),
                'detail': excerpt.strip(),
                'line': line_no,
            })


def summarize(findings: list):
    counts = defaultdict(int)
    for item in findings:
        counts[item['type']] += 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def main():
    parser = argparse.ArgumentParser(description='Fast local triage for OSS supply-chain review.')
    parser.add_argument('root', help='Repository root to scan')
    parser.add_argument('--json', action='store_true', help='Emit JSON')
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit(f'Invalid root: {root}')

    findings = []
    stats = {'files_scanned': 0, 'bytes_scanned': 0}

    for path in root.rglob('*'):
        if not path.is_file() or should_skip(path):
            continue
        try:
            scan_file(path, findings, stats)
        except Exception as exc:
            findings.append({'type': 'scan_error', 'path': str(path), 'detail': str(exc)})

    result = {
        'root': str(root),
        'stats': stats,
        'summary': summarize(findings),
        'findings': findings,
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f'Repository: {result["root"]}')
    print(f'Files scanned: {stats["files_scanned"]}')
    print(f'Bytes scanned: {stats["bytes_scanned"]}')
    print('\nSummary:')
    for key, count in result['summary'].items():
        print(f'  - {key}: {count}')

    print('\nFindings:')
    for item in findings[:200]:
        line = f":{item['line']}" if 'line' in item else ''
        print(f"  - [{item['type']}] {item['path']}{line} :: {item['detail']}")

    if len(findings) > 200:
        print(f'\n... truncated {len(findings) - 200} additional findings')


if __name__ == '__main__':
    main()
