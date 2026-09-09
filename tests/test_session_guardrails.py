from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))

import session
import governor


def shard(shard_id, stage, status="pending"):
    return {
        "id": shard_id,
        "stage": stage,
        "status": status,
        "model": "gemini-test",
        "thinking": 1024,
    }


class SubmitGuardrailTests(unittest.TestCase):
    def state(self):
        return {
            "corpus": 10,
            "shards": [
                shard("a01", "pass_a"),
                shard("a02", "pass_a"),
                shard("b01", "pass_b"),
                shard("c01", "pass_c"),
            ],
        }

    def submit_patches(self, state, action="PROCEED"):
        return (
            mock.patch.object(session, "load", return_value=state),
            mock.patch.object(
                session.governor,
                "project",
                return_value={"projected_total_thb": 9000},
            ),
            mock.patch.object(
                session.governor,
                "decide",
                return_value=(action, [f"{action} note"]),
            ),
            mock.patch.object(session, "rows_for", return_value=[{"cve": "CVE-TEST"}]),
            mock.patch.object(
                session.batch,
                "build",
                side_effect=lambda rows, shard_id, model, thinking: (
                    "input.jsonl", 1, 0, f"attempt-{shard_id}"
                ),
            ),
            mock.patch.object(
                session.batch,
                "submit",
                side_effect=lambda shard_id, model, attempt_id: {
                    "name": f"jobs/{shard_id}"
                },
            ),
            mock.patch.object(session, "save"),
        )

    def test_submit_limit_is_global_across_stage_caps(self):
        state = self.state()
        patches = self.submit_patches(state)
        with patches[0], patches[1], patches[2], patches[3], patches[4] as build, \
                patches[5] as submit, patches[6] as save:
            self.assertTrue(session.cmd_submit(2))

        self.assertEqual(build.call_count, 2)
        self.assertEqual(submit.call_count, 2)
        self.assertEqual([c.args[0] for c in submit.call_args_list], ["a01", "a02"])
        self.assertEqual(save.call_count, 2)
        self.assertEqual(state["shards"][2]["status"], "pending")

    def test_submit_limit_applies_after_full_stage(self):
        state = self.state()
        state["shards"] = [
            shard(f"a{i}", "pass_a", "submitted") for i in range(4)
        ] + [shard("a-pending", "pass_a"), shard("b01", "pass_b")]
        patches = self.submit_patches(state)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5] as submit, patches[6]:
            self.assertTrue(session.cmd_submit(1))

        submit.assert_called_once()
        self.assertEqual(submit.call_args.args[0], "b01")
        self.assertEqual(state["shards"][4]["status"], "pending")

    def test_sparse_stage_does_not_consume_later_stage_quota(self):
        state = self.state()
        state["shards"] = [
            shard("a01", "pass_a"),
            shard("b01", "pass_b"),
            shard("b02", "pass_b"),
        ]
        patches = self.submit_patches(state)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5] as submit, patches[6]:
            self.assertTrue(session.cmd_submit(3))

        self.assertEqual(
            [call.args[0] for call in submit.call_args_list],
            ["a01", "b01", "b02"],
        )

    def test_zero_row_build_does_not_consume_paid_submission_quota(self):
        state = self.state()
        patches = self.submit_patches(state)
        with patches[0], patches[1], patches[2], patches[3], \
                patches[4] as build, patches[5] as submit, patches[6]:
            build.side_effect = lambda rows, shard_id, model, thinking: (
                "input.jsonl",
                0 if shard_id == "a01" else 1,
                0,
                f"attempt-{shard_id}",
            )
            self.assertTrue(session.cmd_submit(1))

        self.assertEqual(build.call_count, 2)
        submit.assert_called_once()
        self.assertEqual(submit.call_args.args[0], "a02")

    def test_halt_and_cut_both_block_submission(self):
        for action in ("HALT", "CUT", "UNKNOWN"):
            with self.subTest(action=action):
                state = self.state()
                patches = self.submit_patches(state, action)
                with patches[0], patches[1], patches[2], patches[3], \
                        patches[4] as build, patches[5] as submit, \
                        patches[6] as save:
                    self.assertFalse(session.cmd_submit(2))

                build.assert_not_called()
                submit.assert_not_called()
                save.assert_not_called()
                self.assertTrue(all(s["status"] == "pending" for s in state["shards"]))

    def test_stretch_and_proceed_allow_submission(self):
        for action in ("STRETCH", "PROCEED"):
            with self.subTest(action=action):
                state = self.state()
                patches = self.submit_patches(state, action)
                with patches[0], patches[1], patches[2], patches[3], \
                        patches[4], patches[5] as submit, patches[6]:
                    self.assertTrue(session.cmd_submit(1))
                submit.assert_called_once()

    def test_zero_limit_is_a_successful_no_op(self):
        with mock.patch.object(session, "load") as load:
            self.assertTrue(session.cmd_submit(0))
        load.assert_not_called()

    def test_negative_or_non_integer_limits_fail_before_governor(self):
        with mock.patch.object(session, "load") as load:
            for value in (-1, 1.5, True, "1"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    session.cmd_submit(value)
        load.assert_not_called()


class SubmitArgumentTests(unittest.TestCase):
    def test_submit_argument_defaults_to_one(self):
        self.assertEqual(session._submit_limit(["session.py", "submit"]), 1)

    def test_submit_argument_allows_zero(self):
        self.assertEqual(session._submit_limit(["session.py", "submit", "0"]), 0)

    def test_submit_argument_rejects_invalid_or_extra_values(self):
        for argv in (
            ["session.py", "submit", "-1"],
            ["session.py", "submit", "nope"],
            ["session.py", "submit", "1", "extra"],
        ):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                session._submit_limit(argv)

    def test_main_returns_distinct_usage_and_governor_exit_codes(self):
        with mock.patch.object(session, "cmd_submit", return_value=False), \
                mock.patch("builtins.print"):
            self.assertEqual(session.main(["session.py", "submit", "1"]), 3)
        with mock.patch("builtins.print"):
            self.assertEqual(session.main(["session.py", "submit", "invalid"]), 2)

    def test_main_does_not_mislabel_operational_value_errors(self):
        with mock.patch.object(
                session, "cmd_submit", side_effect=ValueError("build failed")):
            with self.assertRaisesRegex(ValueError, "build failed"):
                session.main(["session.py", "submit", "1"])

    def test_run_reports_status_and_propagates_governor_block(self):
        with mock.patch.object(session, "cmd_harvest") as harvest, \
                mock.patch.object(session, "cmd_submit", return_value=False) as submit, \
                mock.patch.object(session, "cmd_status") as status:
            self.assertEqual(session.main(["session.py", "run"]), 3)

        harvest.assert_called_once_with()
        submit.assert_called_once_with(session.MAX_INFLIGHT)
        status.assert_called_once_with()


class GovernorReservationTests(unittest.TestCase):
    def test_unharvested_rows_remain_in_future_cost_projection(self):
        state = {
            "measured": {"pass_a": 1.0, "pass_b": 1.0, "pass_c": 1.0},
            "shards": [{
                "id": "a01", "stage": "pass_a", "status": "submitted",
                "job": "jobs/a01", "built": 80,
            }],
        }
        with mock.patch.object(governor.ledger, "totals", return_value={"thb": 100.0}), \
                mock.patch.object(
                    session.batch,
                    "get_job",
                    return_value={"completionStats": {"successfulCount": 80}},
                ) as get_job:
            projected = governor.project(state, 100, conflict_rate=0)

        get_job.assert_not_called()
        self.assertEqual(projected["remaining"]["pass_a"], 100)
        self.assertEqual(projected["future_thb"], 200.0)
        self.assertEqual(projected["projected_total_thb"], 300.0)

    def test_decision_thresholds_are_inclusive_and_fail_safe(self):
        cases = (
            ({"spent_thb": governor.HARDSTOP_THB,
              "projected_total_thb": governor.HARDSTOP_THB}, "HALT"),
            ({"spent_thb": 0,
              "projected_total_thb": governor.TARGET_THB + 0.01}, "CUT"),
            ({"spent_thb": 0,
              "projected_total_thb": governor.TARGET_THB}, "PROCEED"),
            ({"spent_thb": 0,
              "projected_total_thb": governor.FLOOR_THB}, "PROCEED"),
            ({"spent_thb": 0,
              "projected_total_thb": governor.FLOOR_THB - 0.01}, "STRETCH"),
        )
        for projection, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(governor.decide(projection)[0], expected)


if __name__ == "__main__":
    unittest.main()
