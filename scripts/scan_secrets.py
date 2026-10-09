"""Bounded secret-pattern scan of current tracked and proposed repository files.

Only filenames, rule names and counts are reported. Not a DLP guarantee.
Generated keys in temporary test directories are outside repository scope.
"""
from pathlib import Path
import json
import re
import subprocess
import sys

RULES = {
    'private-key-block': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'github-token': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b'),
    'aws-access-key': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'slack-token': re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
    'openai-key': re.compile(rb'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b'),
}


def main():
    root = Path(__file__).resolve().parent.parent
    # Fixed arguments, no shell or external path interpolation.
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                            cwd=root, check=True, capture_output=True, timeout=30)
    findings, checked = [], 0
    for raw in result.stdout.split(b'\x00'):
        if not raw:
            continue
        path = root / raw.decode('utf-8')
        if path.is_symlink():
            findings.append({'path': str(path.relative_to(root)), 'rule': 'unexpected-symlink'})
            continue
        if not path.is_file():
            continue
        if path.stat().st_size > 5_000_000:
            findings.append({'path': str(path.relative_to(root)), 'rule': 'oversized-file-not-scanned'})
            continue
        data = path.read_bytes()
        checked += 1
        for name, pattern in RULES.items():
            count = len(pattern.findall(data))
            if count:
                findings.append({'path': str(path.relative_to(root)), 'rule': name, 'count': count})
    print(json.dumps({'files_checked': checked, 'findings': findings}, indent=2))
    return bool(findings)


if __name__ == '__main__':
    sys.exit(main())
