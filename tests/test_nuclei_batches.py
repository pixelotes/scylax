import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from recon.config import RunContext, ScopeConfig
from recon.phases import active
from recon.runner import CmdResult, load_tool_failures


class NucleiBatchTests(unittest.TestCase):
    def _ctx(self, d: Path, resume=False):
        ips = ",".join(f'"203.0.113.{i}"' for i in range(1, 36))  # 35 targets -> 3 batches of 15/15/5
        toml = d / "s.toml"
        toml.write_text(
            f'[engagement]\nengagement="t"\nruns_dir="{d}/runs"\n[targets]\ndomains=["acme.com"]\nhvt_ips=[{ips}]\n'
            "[limits]\nnuclei_batch_size = 15\n"
        )
        return RunContext(root=d, scope=ScopeConfig.load(toml), run_date="2026-11-04", phases=["8"], resume=resume)

    def _run(self, ctx, outcomes):
        """outcomes: per-batch return codes; each batch writes one finding line to its -o file."""
        calls, fallback_targets = [], []

        def fake_ev(console_dir, phase, args, **kw):
            out = Path(args[args.index("-o") + 1])
            n = len(calls)
            calls.append(kw.get("timeout"))
            out.write_text(json.dumps({"template-id": f"t{n}"}) + "\n", encoding="utf-8")
            rc = outcomes[n]
            return CmdResult(args=list(args), returncode=rc, stdout="", stderr="", timed_out=(rc == 124))

        dm = SimpleNamespace(run_dir=ctx.run_dir, is_available=lambda t: True, build_cmd=lambda tool, a: [tool, *a])
        log = mock.Mock()
        with mock.patch.object(active, "ev", fake_ev), \
             mock.patch.object(active, "_sensitive_path_fallback", lambda c, l, targets: fallback_targets.extend(targets)):
            active.phase8(ctx, dm, log)
        return calls, fallback_targets

    def test_failed_batch_keeps_partial_findings_and_only_that_batch_falls_back(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self._ctx(Path(d))
            calls, fallback = self._run(ctx, [0, 124, 0])
            self.assertEqual(len(calls), 3)
            self.assertTrue(all(t == 40 * 60 for t in calls))
            self.assertEqual(len(fallback), 15)  # only the second batch (15 targets)
            merged = (ctx.web_dir / "nuclei.jsonl").read_text().splitlines()
            self.assertEqual(len(merged), 3)  # partial output of the failed batch is kept too
            fails = load_tool_failures(ctx.run_dir)
            self.assertEqual(len(fails), 1)
            self.assertIn("1 of 3 batch(es) failed", fails[0][2])

    def test_all_good_records_no_failure_and_resume_reuses_finished_batches(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self._ctx(Path(d))
            calls, fallback = self._run(ctx, [0, 0, 0])
            self.assertEqual((len(calls), fallback, load_tool_failures(ctx.run_dir)), (3, [], []))
            # same targets, --resume: nothing runs again
            ctx2 = self._ctx(Path(d), resume=True)
            calls, _ = self._run(ctx2, [])
            self.assertEqual(calls, [])
            self.assertEqual(len((ctx2.web_dir / "nuclei.jsonl").read_text().splitlines()), 3)
            # without --resume everything is re-run from scratch
            ctx3 = self._ctx(Path(d))
            calls, _ = self._run(ctx3, [0, 0, 0])
            self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
