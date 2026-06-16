#!/usr/bin/env python3
"""
passguard-cli — Command-line password strength analyzer & breach checker.

Usage:
  passguard-cli                      # interactive prompt
  passguard-cli --password "mypass"  # analyze single password
  passguard-cli --csv passwords.csv  # bulk CSV audit
  passguard-cli --email user@x.com   # email breach check
  passguard-cli --help

Privacy: The raw password never leaves your machine.
Only the first 5 hex chars of the SHA-1 hash are sent to HIBP.
"""

import argparse
import csv
import hashlib
import json
import math
import re
import sys
import os
import urllib.request
import urllib.error
import getpass
from typing import Optional

# ── Strength labels ────────────────────────────────────────────────────────────
SCORE_LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']
ANSI = {
    'red': '\033[91m', 'orange': '\033[33m', 'yellow': '\033[93m',
    'purple': '\033[95m', 'green': '\033[92m', 'muted': '\033[90m',
    'bold': '\033[1m', 'reset': '\033[0m',
}

def color(text, c):
    if not sys.stdout.isatty():
        return text
    return f"{ANSI.get(c,'')}{text}{ANSI['reset']}"

# ── Entropy ────────────────────────────────────────────────────────────────────
def compute_entropy(password: str) -> float:
    cs = 0
    if re.search(r'[a-z]', password): cs += 26
    if re.search(r'[A-Z]', password): cs += 26
    if re.search(r'[0-9]', password): cs += 10
    if re.search(r'[^a-zA-Z0-9]', password): cs += 33
    if cs == 0 or len(password) == 0:
        return 0.0
    return round(math.log2(cs ** len(password)), 2)

# ── Crack time estimation ──────────────────────────────────────────────────────
def format_seconds(secs: float) -> str:
    if secs < 1: return 'less than a second'
    if secs < 60: return f'{int(secs)} seconds'
    if secs < 3600: return f'{int(secs/60)} minutes'
    if secs < 86400: return f'{int(secs/3600)} hours'
    if secs < 2592000: return f'{int(secs/86400)} days'
    if secs < 31536000: return f'{int(secs/2592000)} months'
    years = secs / 31536000
    if years > 1e12: return 'centuries'
    return f'{int(years):,} years'

def crack_times(entropy_bits: float) -> dict:
    guesses = 2 ** entropy_bits
    return {
        'online_throttled (~100/sec)': format_seconds(guesses / 100),
        'offline_slow_hash (~10K/sec)': format_seconds(guesses / 10_000),
        'offline_fast_hash (~10B/sec)': format_seconds(guesses / 10_000_000_000),
    }

# ── Penalty detection ──────────────────────────────────────────────────────────
def detect_penalties(password: str) -> list:
    p = []
    if len(password) < 8:
        p.append('Too short — aim for at least 12 characters.')
    if re.search(r'(.)\1{2,}', password):
        p.append('Repeated characters detected (e.g., "aaa").')
    m = re.search(r'qwerty|asdfgh|zxcvbn|12345|abcde', password, re.IGNORECASE)
    if m:
        p.append(f'Keyboard walk pattern detected: "{m.group()}".')
    if re.search(r'p[@4a]ss(w[o0]rd)?', password, re.IGNORECASE):
        p.append('Leetspeak substitution detected (e.g., p@ssw0rd).')
    if re.search(r'(19|20)\d{2}', password):
        p.append('Date/year pattern detected.')
    if re.fullmatch(r'[a-zA-Z]+', password):
        p.append('Only letters — add numbers and symbols.')
    if re.fullmatch(r'[0-9]+', password):
        p.append('Only digits — mix in letters and symbols.')
    return p

# ── Simple strength scoring (without zxcvbn in CLI) ───────────────────────────
def score_password(password: str, entropy: float, penalties: list) -> int:
    sc = 0
    if entropy >= 28: sc = 1
    if entropy >= 36: sc = 2
    if entropy >= 50: sc = 3
    if entropy >= 64: sc = 4
    deductions = min(2, len(penalties))
    return max(0, sc - deductions)

# ── HIBP k-anonymity breach check ─────────────────────────────────────────────
def check_breach(password: str) -> dict:
    sha = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}?addpadding=true'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'PassGuard-CLI/1.0'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            lines = resp.read().decode('utf-8').splitlines()
        for line in lines:
            parts = line.strip().split(':')
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                return {'pwned': True, 'count': count,
                        'message': f'Seen {count:,} times in known breaches!'}
        return {'pwned': False, 'count': 0, 'message': 'Not found in known breaches.'}
    except urllib.error.URLError as e:
        return {'pwned': None, 'count': 0, 'message': f'Breach check unavailable: {e}'}

# ── Analyze a single password ─────────────────────────────────────────────────
def analyze(password: str, do_breach: bool = True) -> dict:
    if len(password) > 512:
        return {'error': 'Password exceeds 512 character limit.'}
    entropy = compute_entropy(password)
    penalties = detect_penalties(password)
    sc = score_password(password, entropy, penalties)
    ct = crack_times(entropy)
    result = {
        'score': sc,
        'strength_label': SCORE_LABELS[sc],
        'entropy_bits': entropy,
        'crack_times': ct,
        'penalties': penalties,
        'breach_check': check_breach(password) if do_breach else None,
    }
    return result

# ── Pretty print ──────────────────────────────────────────────────────────────
SCORE_COLORS = ['red', 'orange', 'yellow', 'purple', 'green']

def print_result(result: dict, password_hint: str = ''):
    if 'error' in result:
        print(color(f'Error: {result["error"]}', 'red'))
        return

    score_color = SCORE_COLORS[result['score']]
    label = result['strength_label']
    bar = '█' * (result['score'] + 1) + '░' * (4 - result['score'])

    print()
    if password_hint:
        print(color(f'  Password: {password_hint}', 'muted'))
    print(f'  Strength: {color(label, score_color)} {color(bar, score_color)}')
    print(f'  Entropy:  {result["entropy_bits"]} bits')
    print()
    print(color('  Crack Times:', 'bold'))
    for profile, t in result['crack_times'].items():
        print(f'    {color(profile, "muted")}: {t}')

    if result['penalties']:
        print()
        print(color('  Weaknesses:', 'bold'))
        for p in result['penalties']:
            print(f'    {color("⚠", "yellow")} {p}')

    bc = result.get('breach_check')
    if bc:
        print()
        if bc['pwned'] is True:
            print(f'  Breach: {color("COMPROMISED", "red")} — {bc["message"]}')
        elif bc['pwned'] is False:
            print(f'  Breach: {color("Not found in known breaches", "green")}')
        else:
            print(f'  Breach: {color(bc["message"], "yellow")}')
    print()

# ── CSV bulk audit ────────────────────────────────────────────────────────────
def audit_csv(filepath: str, output_json: bool = False):
    results = []
    flagged = 0
    try:
        with open(filepath, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            col = next((c for c in reader.fieldnames or [] if 'password' in c.lower()), None)
            if not col:
                print(color(f'No "password" column found. Columns: {reader.fieldnames}', 'red'))
                sys.exit(1)
            rows = list(reader)

        print(f'\n{color("PassGuard CSV Audit", "bold")} — {len(rows)} passwords\n')

        for i, row in enumerate(rows, 1):
            pw = row.get(col, '').strip()
            if not pw:
                continue
            r = analyze(pw, do_breach=True)
            is_weak = r['score'] < 3
            is_pwned = r.get('breach_check', {}).get('pwned', False)
            flag = is_weak or is_pwned
            if flag:
                flagged += 1
            results.append({'row': i, **row, 'analysis': r, 'flagged': flag})
            status = color('FLAGGED', 'red') if flag else color('ok', 'green')
            hint = pw[:3] + '*' * max(0, len(pw) - 3)
            print(f'  [{i:>4}] {hint:<20} {r["strength_label"]:<12} {status}')

        print(f'\n  {flagged} / {len(results)} passwords flagged (weak or breached)\n')

        if output_json:
            out_path = filepath.replace('.csv', '_audit.json')
            with open(out_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f'  Detailed results saved to {out_path}')

    except FileNotFoundError:
        print(color(f'File not found: {filepath}', 'red'))
        sys.exit(1)

# ── Email check ───────────────────────────────────────────────────────────────
def check_email_breach(email: str):
    api_key = os.environ.get('HIBP_API_KEY', '')
    if not api_key:
        print(color('  HIBP_API_KEY not set. Email breach check requires an API key.', 'yellow'))
        print(color('  Get one at: https://haveibeenpwned.com/API/Key', 'muted'))
        return

    url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false'
    try:
        import urllib.parse
        req = urllib.request.Request(url, headers={
            'hibp-api-key': api_key,
            'User-Agent': 'PassGuard-CLI/1.0',
        })
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        print(f'\n  {color("BREACHED", "red")} — {email} found in {len(data)} breach(es):')
        for b in data:
            print(f'    • {b["Name"]} ({b["BreachDate"]}) — {", ".join(b["DataClasses"][:3])}')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f'\n  {color("No breaches found", "green")} for {email}')
        elif e.code == 401:
            print(color('  Invalid HIBP API key.', 'red'))
        elif e.code == 429:
            print(color('  HIBP rate limit hit. Please wait a moment.', 'yellow'))
        else:
            print(color(f'  HIBP error: {e.code}', 'yellow'))
    except Exception as e:
        print(color(f'  Email check failed: {e}', 'yellow'))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='PassGuard CLI — privacy-first password strength analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--password', '-p', help='Password to analyze')
    parser.add_argument('--csv', '-c', help='CSV file for bulk audit')
    parser.add_argument('--email', '-e', help='Email address to check for breaches')
    parser.add_argument('--no-breach', action='store_true', help='Skip HIBP breach check')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--output-csv-json', action='store_true', help='Save CSV audit results as JSON')
    args = parser.parse_args()

    print(color('\n  PassGuard CLI', 'bold') + color(' — Password Strength & Breach Checker', 'muted'))
    print(color('  Zero raw-password transmission. HIBP k-anonymity enforced.\n', 'muted'))

    if args.csv:
        audit_csv(args.csv, output_json=args.output_csv_json)
        return

    if args.email:
        import urllib.parse
        print(f'  Checking email: {color(args.email, "muted")}')
        check_email_breach(args.email)
        print()
        return

    password = args.password
    if not password:
        try:
            password = getpass.getpass('  Enter password (hidden): ')
        except KeyboardInterrupt:
            print('\n  Aborted.')
            sys.exit(0)

    if not password:
        print(color('  No password provided.', 'yellow'))
        sys.exit(1)

    result = analyze(password, do_breach=not args.no_breach)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result)

if __name__ == '__main__':
    main()
