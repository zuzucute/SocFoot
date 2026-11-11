import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import socfoot  # noqa: E402


class TestValidation(unittest.TestCase):
    def test_normalises(self):
        self.assertEqual(socfoot.validate_brand("  @ACME "), "acme")

    def test_rejects_people_and_contacts(self):
        for bad in ("john.doe@mail.com", "John Smith", "+60123456789", "a"):
            with self.assertRaises(ValueError):
                socfoot.validate_brand(bad)


class TestVariants(unittest.TestCase):
    def test_exact_first_and_unique(self):
        v = socfoot.generate_variants("example", limit=40)
        self.assertEqual(v[0], ("example", "exact"))
        handles = [h for h, _ in v]
        self.assertEqual(len(handles), len(set(handles)))

    def test_covers_all_techniques_with_small_limit(self):
        cats = {c for _, c in socfoot.generate_variants("example", limit=15)}
        self.assertTrue({"affix", "omission", "transposition", "duplication"} <= cats)


class TestScope(unittest.TestCase):
    def scope(self, hours_from=-1, hours_to=1):
        now = datetime.now(timezone.utc)
        return {"brand": "acme", "authorized_by": "Test", "aliases": ["acmecorp"],
                "valid_from": (now + timedelta(hours=hours_from)).isoformat(),
                "valid_until": (now + timedelta(hours=hours_to)).isoformat()}

    def test_in_scope(self):
        socfoot.enforce_scope(self.scope(), "acme")
        socfoot.enforce_scope(self.scope(), "acmecorp")

    def test_out_of_scope(self):
        with self.assertRaises(PermissionError):
            socfoot.enforce_scope(self.scope(), "other")

    def test_expired_window(self):
        with self.assertRaises(PermissionError):
            socfoot.enforce_scope(self.scope(-5, -2), "acme")


class TestEndToEnd(unittest.TestCase):
    def run_cli(self, *extra):
        out = tempfile.mkdtemp()
        code = socfoot.main(["--demo", "--confirm-authorized", "--delay", "0",
                             "--output-dir", out, *extra])
        return code, out

    def latest_results(self, out):
        run = os.path.join(out, sorted(os.listdir(out))[0])
        with open(os.path.join(run, "results.json")) as fh:
            return json.load(fh), run

    def test_demo_finds_lookalikes(self):
        code, out = self.run_cli()
        self.assertEqual(code, 0)
        data, run = self.latest_results(out)
        found = {(r["platform"], r["handle"]) for r in data["results"] if r["verdict"] == "found"}
        self.assertIn(("github", "example"), found)
        self.assertTrue(any(f["severity"] == "HIGH" for f in data["findings"]))
        self.assertTrue(os.path.exists(os.path.join(run, "LABEL.txt")))

    def test_dry_run_sends_nothing(self):
        out = tempfile.mkdtemp()
        code = socfoot.main(["--confirm-authorized", "--output-dir", out])
        self.assertEqual(code, 0)
        data, _ = self.latest_results(out)
        self.assertTrue(all(r["verdict"] == "planned" for r in data["results"]))

    def test_live_requires_scope_file(self):
        out = tempfile.mkdtemp()
        self.assertEqual(socfoot.main(["--live", "--confirm-authorized", "--output-dir", out]), 2)

    def test_declined_authorization_exits(self):
        import builtins
        original = builtins.input
        builtins.input = lambda *_: "no"
        try:
            self.assertEqual(socfoot.main([]), 2)
        finally:
            builtins.input = original

    def test_stop_file_aborts_cleanly(self):
        out = tempfile.mkdtemp()
        open(os.path.join(out, "STOP"), "w").close()
        # main() removes stale STOP files, so test the scan layer directly
        jobs = socfoot.build_jobs([("example", "exact")], ["github"], "http://127.0.0.1:9")
        results = socfoot.run_scan(jobs, "demo", 0, 1, 1, os.path.join(out, "STOP"))
        self.assertEqual(results[0].verdict, "skipped")


if __name__ == "__main__":
    unittest.main()
