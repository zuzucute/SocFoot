#!/usr/bin/env python3
"""SocFoot - authorized brand social media footprinter.

Checks whether an ORGANIZATION / BRAND handle is claimed on popular platforms and
generates look-alike handles (typos, homoglyphs, affixes) to surface possible
impersonation or squatting. Passive OSINT only: it requests public profile URLs and
records the HTTP status. It never logs in, scrapes page content, or profiles people.

For use only against brands you are explicitly authorized to assess.
"""
import argparse
import csv
import itertools
import json
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "1.0.0"
USER_AGENT = f"SocFoot/{__version__} (authorized security assessment)"
SAFE_DEFAULT_BRAND = "example"
HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,29}$")
STOP = threading.Event()  # kill switch: set by Ctrl+C / SIGTERM / STOP file

PLATFORMS = {
    "github": "https://github.com/{h}",
    "x": "https://x.com/{h}",
    "instagram": "https://www.instagram.com/{h}/",
    "tiktok": "https://www.tiktok.com/@{h}",
    "youtube": "https://www.youtube.com/@{h}",
    "reddit": "https://www.reddit.com/user/{h}",
    "facebook": "https://www.facebook.com/{h}",
    "linkedin": "https://www.linkedin.com/company/{h}",
    "medium": "https://medium.com/@{h}",
    "telegram": "https://t.me/{h}",
    "pinterest": "https://www.pinterest.com/{h}/",
    "twitch": "https://www.twitch.tv/{h}",
}

SUFFIXES = ["official", "hq", "team", "support", "help", "app", "inc"]
PREFIXES = ["the", "get", "real"]
HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}

BANNER = r"""
  ____             _____          _
 / ___|  ___   ___|  ___|__   ___ | |_
 \___ \ / _ \ / __| |_ / _ \ / _ \| __|
  ___) | (_) | (__|  _| (_) | (_) | |_
 |____/ \___/ \___|_|  \___/ \___/ \__|   v{ver}
 Brand social media footprinter (passive OSINT)
"""

DISCLAIMER = """\
================================ LEGAL DISCLAIMER ================================
This tool is for AUTHORIZED security assessments and education only.

Under the Computer Crimes Act 1997 (Act 563, Malaysia), unauthorized access to
computer material and related offences are criminal. Personal data is also
protected by the Personal Data Protection Act 2010 (Act 709). Equivalent laws apply
in other countries.

By continuing you confirm that:
  1. You have explicit, written authorization from the brand/organization owner
     (or the target is your own, or a safe test target such as 'example').
  2. You will stay inside the agreed scope and time window (see README, RoE).
  3. You will not use results to harass, dox or profile individuals.
The authors accept no liability for misuse.
==================================================================================
"""


# --------------------------------------------------------------------------- #
# Input validation and scope enforcement
# --------------------------------------------------------------------------- #
def validate_brand(raw):
    """Normalise a brand handle; reject anything that looks like a person/contact."""
    name = raw.strip().lower().lstrip("@")
    if "@" in name or " " in name or re.fullmatch(r"[+\d\-() ]{7,}", name):
        raise ValueError("target looks like an email, phone or full name; "
                         "SocFoot only supports organization/brand handles")
    if not HANDLE_RE.match(name):
        raise ValueError("brand must be 2-30 chars: a-z 0-9 . _ - (starting alphanumeric)")
    return name


def parse_time(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_scope(path):
    """Load the scope file that documents authorization (brand, owner, time window)."""
    with open(path, encoding="utf-8") as fh:
        scope = json.load(fh)
    missing = {"brand", "authorized_by", "valid_from", "valid_until"} - scope.keys()
    if missing:
        raise ValueError(f"scope file missing keys: {', '.join(sorted(missing))}")
    return scope


def enforce_scope(scope, brand, now=None):
    """Raise PermissionError unless brand is in scope and the time window is open."""
    now = now or datetime.now(timezone.utc)
    allowed = {validate_brand(scope["brand"])}
    allowed |= {validate_brand(a) for a in scope.get("aliases", [])}
    if brand not in allowed:
        raise PermissionError(f"'{brand}' is outside the authorized scope {sorted(allowed)}")
    if not parse_time(scope["valid_from"]) <= now <= parse_time(scope["valid_until"]):
        raise PermissionError("current time is outside the authorized time window")


# --------------------------------------------------------------------------- #
# Look-alike handle generation
# --------------------------------------------------------------------------- #
def generate_variants(brand, limit=15):
    """Return [(handle, category)] starting with the exact brand, then look-alikes.

    Categories are interleaved so a small limit still covers every technique.
    """
    groups = {k: [] for k in ("affix", "omission", "transposition", "duplication", "homoglyph")}
    seen = {brand}

    def add(cat, handle):
        if handle not in seen and HANDLE_RE.match(handle):
            seen.add(handle)
            groups[cat].append(handle)

    for s in SUFFIXES:
        add("affix", brand + s)
        add("affix", f"{brand}_{s}")
    for p in PREFIXES:
        add("affix", p + brand)
    for i in range(len(brand)):
        add("omission", brand[:i] + brand[i + 1:])
        add("duplication", brand[:i] + brand[i] + brand[i:])
        if brand[i] in HOMOGLYPHS:
            add("homoglyph", brand[:i] + HOMOGLYPHS[brand[i]] + brand[i + 1:])
        if i < len(brand) - 1:
            add("transposition", brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:])

    out = [(brand, "exact")]
    for tier in itertools.zip_longest(*[[(h, c) for h in v] for c, v in groups.items()]):
        out.extend(item for item in tier if item)
    return out[:limit]


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    platform: str
    handle: str
    category: str
    url: str
    status: int
    verdict: str  # found | not_found | inconclusive | error | skipped | planned
    checked_at: str


class RateLimiter:
    """Global minimum delay between outgoing requests (politeness / avoids bans)."""

    def __init__(self, delay):
        self.delay, self._last, self._lock = delay, 0.0, threading.Lock()

    def wait(self):
        with self._lock:
            sleep_for = self._last + self.delay - time.monotonic()
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last = time.monotonic()


def classify(status):
    if status in (200, 203):
        return "found"
    if status in (404, 410):
        return "not_found"
    if status in (401, 403, 429, 999):
        return "inconclusive"  # bot-blocked or rate limited: do not guess
    return "error"


def http_status(url, timeout):
    """GET the URL and return only the status code; the body is never read."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0


def build_jobs(variants, platforms, base_url=None):
    jobs = []
    for platform in platforms:
        for handle, category in variants:
            template = f"{base_url}/{{p}}/{{h}}" if base_url else PLATFORMS[platform]
            url = template.format(p=platform, h=handle)
            jobs.append((platform, handle, category, url))
    return jobs


def stop_requested(stop_file):
    return STOP.is_set() or os.path.exists(stop_file)


def run_scan(jobs, mode, delay, workers, timeout, stop_file):
    limiter = RateLimiter(delay)

    def work(job):
        platform, handle, category, url = job
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if mode == "dry-run":
            return Result(platform, handle, category, url, 0, "planned", now)
        if stop_requested(stop_file):
            return Result(platform, handle, category, url, 0, "skipped", now)
        limiter.wait()
        status = http_status(url, timeout)
        verdict = "error" if status == 0 else classify(status)
        return Result(platform, handle, category, url, status, verdict, now)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(work, jobs))


def analyse(results, known_official):
    """Turn raw results into findings an analyst can act on."""
    findings = []
    for r in results:
        if r.category == "exact" and r.verdict == "not_found":
            findings.append(("MEDIUM", f"Brand handle '{r.handle}' unclaimed on {r.platform} "
                                       "(squatting risk)", r.url))
        elif r.category != "exact" and r.verdict == "found" and r.handle not in known_official:
            findings.append(("HIGH", f"Look-alike '{r.handle}' ({r.category}) exists on "
                                     f"{r.platform}: review for impersonation", r.url))
    return findings


# --------------------------------------------------------------------------- #
# Reporting (local files only; metadata only, never page content)
# --------------------------------------------------------------------------- #
def write_reports(out_dir, meta, results, findings):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "results": [asdict(r) for r in results],
                   "findings": [dict(zip(("severity", "detail", "url"), f)) for f in findings]},
                  fh, indent=2)
    with open(os.path.join(out_dir, "results.csv"), "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(list(Result.__dataclass_fields__))
        writer.writerows(asdict(r).values() for r in results)
    with open(os.path.join(out_dir, "LABEL.txt"), "w", encoding="utf-8") as fh:
        fh.write("CONFIDENTIAL - security assessment output. Handle per your engagement's RoE.\n"
                 f"Brand: {meta['brand']} | Mode: {meta['mode']} | Generated: {meta['finished']}\n"
                 "Contains public profile URLs and HTTP status codes only.\n")


def print_table(results, findings):
    shown = [r for r in results if r.verdict in ("found", "planned", "inconclusive")]
    print(f"\n{'PLATFORM':<11}{'HANDLE':<20}{'TYPE':<15}{'STATUS':<8}VERDICT")
    print("-" * 66)
    for r in shown:
        print(f"{r.platform:<11}{r.handle:<20}{r.category:<15}{r.status or '-':<8}{r.verdict}")
    print(f"\nChecked {len(results)} URLs | findings: {len(findings)}")
    for severity, detail, url in findings:
        print(f"  [{severity}] {detail}\n          {url}")


# --------------------------------------------------------------------------- #
# Demo mock server (127.0.0.1 only) so the tool can be shown without real targets
# --------------------------------------------------------------------------- #
DEMO_EXISTING = {"github/example", "x/example", "github/example_official",
                 "reddit/examp1e", "instagram/exampleofficial", "x/exampleofficial"}


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path.strip("/") in DEMO_EXISTING else 404)
        self.end_headers()

    def log_message(self, *_):
        pass


def start_mock_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
EPILOG = """\
examples:
  socfoot.py                                  dry-run for 'example' (sends nothing)
  socfoot.py --demo                           run against a local mock server (safe)
  socfoot.py --brand acme --platforms github,x
                                              dry-run: list URLs that WOULD be checked
  socfoot.py --live --brand acme --scope-file scope.json --known-official acme
                                              real checks, requires signed-off scope file

kill switch: press Ctrl+C, or create a file named STOP inside the output directory.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="socfoot.py", description="Authorized brand social media footprinter.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--brand", default=SAFE_DEFAULT_BRAND,
                   help=f"organization/brand handle (default: {SAFE_DEFAULT_BRAND})")
    p.add_argument("--platforms", help="comma list (default: all). See --list-platforms")
    p.add_argument("--max-variants", type=int, default=15, help="handles per platform (default 15)")
    p.add_argument("--known-official", default="", help="comma list of handles you own (not flagged)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true",
                      help="send real requests to public platforms (needs --scope-file)")
    mode.add_argument("--demo", action="store_true", help="scan a local mock server on 127.0.0.1")
    p.add_argument("--scope-file", help="JSON: brand, authorized_by, valid_from, valid_until")
    p.add_argument("--workers", type=int, default=4, help="threads (default 4)")
    p.add_argument("--delay", type=float, default=1.0, help="seconds between requests (default 1.0)")
    p.add_argument("--timeout", type=float, default=8.0, help="request timeout seconds")
    p.add_argument("--output-dir", default="output", help="where reports are written (default output/)")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="skip the interactive confirmation (logged in the report)")
    p.add_argument("--list-platforms", action="store_true", help="list supported platforms and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def confirm_authorization(args):
    print(DISCLAIMER)
    if args.confirm_authorized:
        print("[!] Authorization confirmed via --confirm-authorized flag.\n")
        return True
    try:
        answer = input("Type 'I AUTHORIZE' to confirm you have permission to proceed: ")
    except EOFError:
        return False
    return answer.strip() == "I AUTHORIZE"


def install_kill_switch():
    def handler(signum, _frame):
        STOP.set()
        print("\n[!] Kill switch triggered: finishing in-flight requests, saving partial results...")
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.list_platforms:
        print("\n".join(PLATFORMS))
        return 0
    print(BANNER.format(ver=__version__))
    STOP.clear()
    install_kill_switch()
    if not confirm_authorization(args):
        print("Authorization not confirmed. Exiting.")
        return 2

    try:
        brand = validate_brand(args.brand)
        platforms = [x.strip() for x in args.platforms.split(",")] if args.platforms else list(PLATFORMS)
        unknown = [x for x in platforms if x not in PLATFORMS]
        if unknown:
            raise ValueError(f"unknown platform(s): {', '.join(unknown)}")
        mode = "live" if args.live else "demo" if args.demo else "dry-run"
        scope = None
        if args.live:
            if not args.scope_file:
                raise PermissionError("--live requires --scope-file (see README, Rules of Engagement)")
            scope = load_scope(args.scope_file)
            enforce_scope(scope, brand)
    except (ValueError, PermissionError, OSError, json.JSONDecodeError) as exc:
        print(f"[x] {exc}")
        return 2

    server, base_url = (None, None)
    if mode == "demo":
        server, base_url = start_mock_server()
        print(f"[demo] mock server on {base_url} (no real platforms contacted)")
    if mode == "dry-run":
        print("[dry-run] nothing will be sent. Use --demo (safe) or --live (scope file) to scan.")

    os.makedirs(args.output_dir, exist_ok=True)
    stop_file = os.path.join(args.output_dir, "STOP")
    if os.path.exists(stop_file):
        os.remove(stop_file)  # stale stop file from a previous run
    started = datetime.now(timezone.utc)
    variants = generate_variants(brand, args.max_variants)
    jobs = build_jobs(variants, platforms, base_url)
    print(f"[+] brand='{brand}' mode={mode} handles={len(variants)} "
          f"platforms={len(platforms)} requests={len(jobs)}")

    results = run_scan(jobs, mode, args.delay, max(1, args.workers), args.timeout, stop_file)
    if server:
        server.shutdown()
    aborted = any(r.verdict == "skipped" for r in results)
    known = {validate_brand(h) for h in args.known_official.split(",") if h.strip()}
    findings = analyse(results, known) if mode != "dry-run" else []

    meta = {"tool": "SocFoot", "version": __version__, "brand": brand, "mode": mode,
            "authorized_by": scope["authorized_by"] if scope else "n/a (non-live mode)",
            "confirmed_via_flag": args.confirm_authorized, "aborted_early": aborted,
            "started": started.isoformat(timespec="seconds"),
            "finished": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    out_dir = os.path.join(args.output_dir, f"{brand}_{started.strftime('%Y%m%d_%H%M%S')}")
    write_reports(out_dir, meta, results, findings)
    print_table(results, findings)
    print(f"\n[+] Reports saved locally in: {out_dir}")
    if aborted:
        print("[!] Scan was aborted early; results are partial.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
