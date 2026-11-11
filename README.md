# SocFoot - Brand Social Media Footprinter

> Course: IKB31603 Ethical Hacking, UniKL MIIT (Oct 2026) | Category: **Offensive OSINT** | Version 1.0.0

SocFoot is a command-line tool that maps an **organization's** social media footprint. For an authorized brand handle it:

1. checks whether the exact handle is claimed on 12 platforms (and flags **unclaimed** handles as squatting risk);
2. generates **look-alike handles** (typos, homoglyphs, prefixes/suffixes) and checks which already exist, so analysts can review them for **impersonation / phishing risk**;
3. writes a labeled local report (JSON, CSV, label file).

It is passive OSINT: it only requests public profile URLs and records the HTTP status code. It never logs in, never reads or stores page content, and refuses targets that look like individuals (emails, phone numbers, full names).

## Attack lifecycle mapping

| Lifecycle stage | What SocFoot does |
|---|---|
| Reconnaissance (passive) | Enumerates public profile URLs for the brand and its look-alikes |
| Scanning / Enumeration | Classifies each URL (found / not found / inconclusive) with rate limiting |
| Vulnerability analysis | Turns results into findings: unclaimed brand handle (MEDIUM), existing look-alike (HIGH) |
| Reporting | Local JSON + CSV + label file, flagged if the scan was aborted |
| Exploitation / Post-exploitation | **Intentionally out of scope.** Impersonation takedowns go through disclosure (below) |

## Installation

Python 3.9+ and **no third-party packages** (standard library only; `requirements.txt` documents this).

```bash
git clone https://github.com/<your-account>/socfoot.git
cd socfoot
python3 socfoot.py --help
```

## Usage

```bash
python3 socfoot.py                       # dry-run on safe default 'example' (sends nothing)
python3 socfoot.py --demo                # scans a local mock server on 127.0.0.1 (safe)
python3 socfoot.py --brand acme --platforms github,x      # dry-run: lists URLs that WOULD be checked
python3 socfoot.py --live --brand acme --scope-file scope.json --known-official acme
python3 socfoot.py --list-platforms
python3 -m unittest discover -s tests    # run the test-suite
```

Key options: `--max-variants`, `--delay` (default 1s between requests), `--workers`, `--timeout`, `--known-official`, `--output-dir`.

### Scope file (required for `--live`)

Copy `scope.example.json` and fill it in from your signed authorization letter:

```json
{
  "brand": "acme",
  "aliases": ["acmecorp"],
  "authorized_by": "Jane Doe, Head of Security, Acme Sdn Bhd (authorization ref ACME-2026-01)",
  "valid_from": "2026-10-25T09:00:00+08:00",
  "valid_until": "2026-10-25T18:00:00+08:00"
}
```

The tool refuses to run live if the brand is not in the file or the current time is outside the window.

### Example output (demo)

```
PLATFORM   HANDLE              TYPE           STATUS  VERDICT
github     example             exact          200     found
github     example_official    affix          200     found
x          exampleofficial     affix          200     found
Checked 180 URLs | findings: 13
  [HIGH] Look-alike 'exampleofficial' (affix) exists on x: review for impersonation
  [MEDIUM] Brand handle 'example' unclaimed on tiktok (squatting risk)
```

*(Add your own screenshot here: `docs/demo.png`.)*

## Ethical considerations and design decisions

| Guardrail | Implementation | Why |
|---|---|---|
| Safe defaults | Default brand `example`; default mode is dry-run; `--demo` only talks to `127.0.0.1` | An accidental run cannot touch a real target |
| Authorization scope | `--live` needs a scope file; brand + time window enforced | Proves who authorized what, and when |
| Legal disclaimer | Startup banner cites the Computer Crimes Act 1997 (Act 563) and PDPA 2010; must type `I AUTHORIZE` | Explicit, informed confirmation |
| Kill switch | `Ctrl+C`, `SIGTERM`, or a file named `STOP` in the output dir; partial results are saved and marked | Clean abort at any time |
| No people-profiling | Emails, phone numbers and names with spaces are rejected; only handles are recorded | Avoids doxxing and PDPA exposure |
| Data minimization | Only URL, status code, timestamp stored; page bodies never read | Nothing sensitive can be collected or leaked |
| Politeness | 1s global delay, identifying User-Agent, 4 threads | No hammering of platforms |
| Honest uncertainty | 403/429 are `inconclusive`, never guessed | Avoids false findings |

## Rules of Engagement (RoE)

- **Authorized scope:** only the brand handle(s) and aliases in the signed scope file, and look-alikes derived from them. Individuals' accounts are out of scope.
- **Time windows:** only inside `valid_from` / `valid_until` of the scope file (agreed with the client; run outside business-critical hours where possible).
- **Permitted techniques:** HTTP GET to public profile URLs, rate limited, status code only.
- **Prohibited actions:** logging in, bypassing bot protection or rate limits, scraping profile content, contacting or messaging account owners, reporting/takedown abuse, using output against anyone outside scope, running against real targets without written authorization.
- **Emergency stop:** press `Ctrl+C`, or `touch output/STOP`. If a platform asks you to stop or blocks you, stop and tell your engagement contact.

## Responsible disclosure

1. **Who:** report to the brand owner's security/brand-protection contact named in your authorization letter (never to third parties or publicly).
2. **What:** send only the confirmed look-alike URLs, why they look suspicious, and the report's timestamp. Do not include personal data about account holders.
3. **How/when:** within 3 working days over an agreed secure channel; the owner decides on takedown via the platform's impersonation form. Do not contact the look-alike's owner.
4. **Retention:** delete the `output/` data when the engagement ends (it is git-ignored and labeled CONFIDENTIAL).

## Data handling

Reports go to `output/<brand>_<timestamp>/` as `results.json`, `results.csv` and `LABEL.txt`. Nothing is sent anywhere else. `output/` is in `.gitignore`.

## Limitations

- Many platforms block bots or return 200 for any URL; these show as `inconclusive` or may give false "found" results. Confirm manually before acting.
- Detection is status-code based and cannot tell whether a found account is malicious or legitimate.
- Handle rules differ per platform; some generated handles may be invalid there.
- Only 12 platforms and 5 generation techniques in v1.0.0.

## Legal disclaimer

For authorized security assessments and education only. Unauthorized use may breach the Computer Crimes Act 1997 (Malaysia) and the Personal Data Protection Act 2010. The authors accept no liability for misuse.

## License

MIT, see `LICENSE`.
