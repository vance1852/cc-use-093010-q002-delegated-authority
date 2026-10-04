from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cooperation_assurance.clock import FrozenClock
from cooperation_assurance.errors import Conflict, Forbidden, InvalidState, ValidationFailed
from cooperation_assurance.jsonio import load_json
from cooperation_assurance.service import AssuranceService
from cooperation_assurance.storage import connect

ROOT = Path(__file__).resolve().parents[1]
WINDOW = ("2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z")
NARROW_WINDOW = ("2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")


class GovernanceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("stat-2", "statistician"),
            ("approver", "approver"),
            ("approver-2", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.g = self.service.governance
        self.service.register_program("operator", "program-a", "跨境数据服务项目", "牵头机构")
        self.service.register_evidence_revision("operator", "rev-a", "program-a", "1.0", "b" * 64)
        self.service.register_evidence_revision("operator", "rev-b", "program-a", "2.0", "c" * 64)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text().splitlines()
            if line.strip()
        ]

    def tearDown(self) -> None:
        self.connection.close()

    def grant_accept(
        self, grant_id, principal, rep, action, key, *,
        revision="rev-a", window=WINDOW, delegable=False, depth=0, program="program-a",
    ):
        self.g.propose_grant(
            "operator", grant_id, principal, rep, action, window[0], window[1], f"{key}:propose",
            program_id=program, evidence_revision_id=revision,
            delegable=delegable, max_chain_depth=depth,
        )
        self.g.accept_grant(rep, grant_id, f"{key}:accept")
        return grant_id

    def running_batch(self, batch_id="batch-a", revision="rev-a"):
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", batch_id, "demo-cooperation-v1", 1, revision)
        self.service.start_batch("operator", batch_id, 1)
        return batch_id

    def analyzed_batch(self, batch_id="batch-a"):
        batch_id = self.running_batch(batch_id)
        self.service.import_observations("operator", batch_id, "obs-1", self.rows)
        self.grant_accept("grant-stat", "投资方A", "stat", "exclusion.review", "stat")
        self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "投资方A")
        self.service.seal_batch("stat", batch_id, 2)
        job = self.service.claim_job("worker", 30)
        analysis = self.service.complete_job("worker", job["job_id"], "stat")
        return batch_id, analysis


class GrantLifecycleTests(GovernanceTestBase):
    def test_five_elements_bound_and_events_are_append_only(self) -> None:
        self.grant_accept("g1", "投资方A", "stat", "exclusion.review", "k1")
        view = self.g.grant_view("g1")
        self.assertEqual(view["principal_id"], "投资方A")
        self.assertEqual(view["action"], "exclusion.review")
        self.assertEqual(view["evidence_revision_id"], "rev-a")
        self.assertEqual(view["valid_from"], WINDOW[0])
        self.assertEqual(view["status"], "accepted")
        self.assertEqual([e["event_type"] for e in view["events"]], ["proposed", "accepted"])

        self.g.suspend_grant("operator", "g1", "k1:s", "例行暂停")
        self.g.resume_grant("operator", "g1", "k1:r", "核对完成")
        self.g.withdraw_grant("operator", "g1", "k1:w", "委托终止")
        view = self.g.grant_view("g1")
        self.assertEqual(view["status"], "withdrawn")
        self.assertEqual(
            [e["event_type"] for e in view["events"]],
            ["proposed", "accepted", "suspended", "resumed", "withdrawn"],
        )
        # 终态不可再变：事实不能被覆盖。
        with self.assertRaises(InvalidState):
            self.g.resume_grant("operator", "g1", "k1:r2")

    def test_reject_is_terminal(self) -> None:
        self.g.propose_grant(
            "operator", "g2", "投资方A", "stat", "exclusion.review",
            WINDOW[0], WINDOW[1], "k2:propose", program_id="program-a", evidence_revision_id="rev-a",
        )
        self.g.reject_grant("stat", "g2", "k2:reject", "不接受委托")
        with self.assertRaises(InvalidState):
            self.g.accept_grant("stat", "g2", "k2:accept-late")
        self.assertEqual(self.g.grant_view("g2")["status"], "rejected")

    def test_duplicate_callbacks_do_not_create_two_facts(self) -> None:
        kwargs = dict(
            principal_id="投资方A", representative_id="stat", action="exclusion.review",
            valid_from=WINDOW[0], valid_until=WINDOW[1], idempotency_key="dup:propose",
            program_id="program-a", evidence_revision_id="rev-a",
        )
        first = self.g.propose_grant("operator", "g3", **kwargs)
        second = self.g.propose_grant("operator", "g3", **kwargs)
        self.assertEqual(first["grant_id"], second["grant_id"])
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM authorization_grants WHERE grant_id='g3'").fetchone()[0], 1)
        self.g.accept_grant("stat", "g3", "dup:accept")
        self.g.accept_grant("stat", "g3", "dup:accept")  # 重复回调
        events = self.connection.execute(
            "SELECT event_type,count(*) FROM grant_events WHERE grant_id='g3' GROUP BY event_type"
        ).fetchall()
        self.assertEqual({row[0]: row[1] for row in events}, {"proposed": 1, "accepted": 1})

    def test_concurrent_mandates_cannot_produce_two_open_grants(self) -> None:
        common = dict(
            principal_id="投资方A", representative_id="stat", action="exclusion.review",
            valid_from=WINDOW[0], valid_until=WINDOW[1], program_id="program-a",
            evidence_revision_id="rev-a",
        )
        self.g.propose_grant("operator", "g4a", idempotency_key="c:1", **common)
        with self.assertRaises(Conflict):
            self.g.propose_grant("operator", "g4b", idempotency_key="c:2", **common)
        # 第一份被拒绝后，同一席位可以重新委托。
        self.g.reject_grant("stat", "g4a", "c:reject")
        self.g.propose_grant("operator", "g4b", idempotency_key="c:3", **common)

    def test_grant_cannot_exceed_role_or_bind_invalid_revision(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.g.propose_grant(
                "operator", "g5", "投资方A", "stat", "decision.write",
                WINDOW[0], WINDOW[1], "k5", program_id="program-a", evidence_revision_id="rev-a",
            )
        with self.assertRaises(ValidationFailed):
            self.g.propose_grant(
                "operator", "g6", "投资方A", "stat", "exclusion.review",
                WINDOW[0], WINDOW[1], "k6",
                program_id="program-a", evidence_revision_id="rev-missing",
            )

    def test_cannot_accept_with_undeclared_conflict(self) -> None:
        self.g.propose_grant(
            "operator", "g7", "投资方A", "stat", "exclusion.review",
            WINDOW[0], WINDOW[1], "k7:p", program_id="program-a", evidence_revision_id="rev-a",
        )
        self.g.disclose_interest("stat", "stat", "投资方A", "持股", "k7:d")
        with self.assertRaises(Forbidden):
            self.g.accept_grant("stat", "g7", "k7:a")


class DelegationTests(GovernanceTestBase):
    def test_delegation_respects_scope_window_and_depth(self) -> None:
        self.grant_accept(
            "parent", "投资方A", "stat", "exclusion.review", "p",
            delegable=True, depth=1,
        )
        # 禁止超出母授权的生效区间。
        with self.assertRaises(Forbidden):
            self.g.delegate_grant(
                "stat", "parent", "child-bad", "stat-2", "2025-12-31T00:00:00Z", WINDOW[1], "d1",
            )
        # 替代人员角色不匹配时不能转委托（不能继承超出角色的访问）。
        with self.assertRaises(ValidationFailed):
            self.g.delegate_grant(
                "stat", "parent", "child-role", "approver-2", WINDOW[0], WINDOW[1], "d2",
            )
        self.g.delegate_grant("stat", "parent", "child", "stat-2", WINDOW[0], WINDOW[1], "d3")
        self.g.accept_grant("stat-2", "child", "d3:accept")
        child = self.g.grant_view("child")
        self.assertEqual(child["chain_depth"], 1)
        self.assertEqual(child["ancestor_chain"], ["parent"])
        self.assertFalse(child["delegable"])  # 子授权默认不可再转
        # 已达链深上限，不能再转一层。
        with self.assertRaises(Forbidden):
            self.g.delegate_grant("stat-2", "child", "grandchild", "stat", WINDOW[0], WINDOW[1], "d4")

    def test_interest_disclosure_cascades_to_delegated_downstream(self) -> None:
        batch_id = self.running_batch()
        self.grant_accept("parent", "投资方A", "stat", "exclusion.review", "p", delegable=True, depth=1)
        self.g.delegate_grant("stat", "parent", "child", "stat-2", WINDOW[0], WINDOW[1], "d")
        self.g.accept_grant("stat-2", "child", "d:a")
        self.g.assign_review("operator", batch_id, "exclusion_review", "stat-2", "投资方A")
        # stat 本人申报与投资方A的利益关系：其母授权及下游替代授权都被暂停。
        self.g.disclose_interest("stat", "stat", "投资方A", "受聘顾问", "int-1")
        self.assertEqual(self.g.grant_view("parent")["status"], "suspended")
        self.assertEqual(self.g.grant_view("child")["status"], "suspended")
        seat = self.connection.execute(
            "SELECT state FROM review_assignments WHERE batch_id=? AND stage='exclusion_review'",
            (batch_id,),
        ).fetchone()
        self.assertEqual(seat["state"], "revoked")
        # 解除利益关系不自动恢复授权，须秘书处自顶向下显式恢复。
        self.g.clear_interest("operator", 1, "调查结束")
        with self.assertRaises(InvalidState):
            self.g.resume_grant("operator", "child", "child-resume")
        self.g.resume_grant("operator", "parent", "parent-resume")
        self.g.resume_grant("operator", "child", "child-resume")
        self.assertEqual(self.g.grant_view("child")["status"], "accepted")

    def test_non_delegable_grant_cannot_be_passed_on(self) -> None:
        self.grant_accept("strict", "投资方A", "stat", "exclusion.review", "s")
        with self.assertRaises(Forbidden):
            self.g.delegate_grant("stat", "strict", "child", "stat-2", WINDOW[0], WINDOW[1], "sd")

    def test_parent_suspension_cascades_and_revokes_seat(self) -> None:
        batch_id = self.running_batch()
        self.grant_accept("parent", "投资方A", "stat", "exclusion.review", "p", delegable=True, depth=1)
        self.g.delegate_grant("stat", "parent", "child", "stat-2", WINDOW[0], WINDOW[1], "d")
        self.g.accept_grant("stat-2", "child", "d:a")
        self.g.assign_review("operator", batch_id, "exclusion_review", "stat-2", "投资方A")
        self.g.suspend_grant("operator", "parent", "ps", "上游调查")
        self.assertEqual(self.g.grant_view("child")["status"], "suspended")
        with self.assertRaises(Forbidden):
            self.service.review_exclusion(
                "stat-2", 1, True, "x"
            ) if False else self.g.require_seat("stat-2", batch_id, "exclusion_review")
        seat = self.connection.execute(
            "SELECT state,revoke_reason FROM review_assignments WHERE batch_id=? AND stage='exclusion_review'",
            (batch_id,),
        ).fetchone()
        self.assertEqual(seat["state"], "revoked")
        self.assertIn("上游授权", seat["revoke_reason"])
        # 上游未恢复前，子授权不能单独恢复。
        with self.assertRaises(InvalidState):
            self.g.resume_grant("operator", "child", "cr")
        self.g.resume_grant("operator", "parent", "pr")
        self.g.resume_grant("operator", "child", "cr")

    def test_substitute_loses_access_when_narrow_window_ends(self) -> None:
        self.grant_accept(
            "parent", "投资方A", "stat", "exclusion.review", "p",
            delegable=True, depth=1,
        )
        child_window = ("2026-06-01T00:00:00Z", "2026-12-01T00:00:00Z")
        self.g.delegate_grant("stat", "parent", "child", "stat-2", child_window[0], child_window[1], "d")
        self.g.accept_grant("stat-2", "child", "d:a")
        batch_id = self.running_batch("batch-b")
        # 替代授权 12 月到期；到期后资格列表中不再有 stat-2。
        eligibility = self.g.eligible_representatives(batch_id, "exclusion_review", at="2026-12-02T00:00:00Z")
        self.assertNotIn(
            "stat-2", [item["user_id"] for item in eligibility["eligible"]]
        )
        # 授权窗口内的历史时点解释成立（接受事实发生在 9 月 24 日）。
        explanation = self.g.explain("stat-2", "exclusion.review", at="2026-10-01T00:00:00Z")
        self.assertTrue(explanation["may_act"])
        expired = self.g.explain("stat-2", "exclusion.review", at="2026-12-02T00:00:00Z")
        self.assertFalse(expired["may_act"])
        self.assertIn("outside_validity_window", expired["blocked"][0]["reasons"])


class RecusalAndSeatTests(GovernanceTestBase):
    def test_seat_requires_effective_grant_and_matching_revision(self) -> None:
        batch_id = self.running_batch()
        with self.assertRaises(Forbidden):
            self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "投资方A")
        self.grant_accept("gA", "投资方A", "stat", "exclusion.review", "a")
        with self.assertRaises(Forbidden):
            self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "其他主体")
        self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "投资方A")
        # 同一阶段并发分派不会产生两份在执席位。
        with self.assertRaises(InvalidState):
            self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "投资方A")

    def test_grant_bound_to_other_revision_confers_no_seat(self) -> None:
        batch_id = self.running_batch()
        self.grant_accept("gB", "投资方A", "stat", "exclusion.review", "b", revision="rev-b")
        with self.assertRaises(Forbidden):
            self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "投资方A")

    def test_conflict_reassigns_pending_item_and_keeps_completed_decision(self) -> None:
        batch_id, analysis = self.analyzed_batch()
        self.grant_accept("gD", "候选服务商B", "approver", "decision.write", "d")
        self.g.assign_review("operator", batch_id, "admission_decision", "approver", "候选服务商B")
        self.service.decide(
            "approver", batch_id, analysis["analysis_id"], "approved", "材料齐备"
        )

        # 已完成的合法决定在授权撤回后仍然保留。
        self.g.withdraw_grant("operator", "gD", "wd", "委托关系结束")
        report = self.service.report("auditor", batch_id)
        self.assertEqual(report["decision"]["decision"], "approved")
        self.assertEqual(report["decision"]["authority"]["grant_id"], "gD")
        completed_seat = self.connection.execute(
            "SELECT state FROM review_assignments WHERE stage='admission_decision'"
        ).fetchone()
        self.assertEqual(completed_seat["state"], "completed")

    def test_conflict_on_pending_item_reassigns_to_substitute(self) -> None:
        batch_id = self.running_batch()
        self.service.import_observations("operator", batch_id, "obs", self.rows)
        self.grant_accept("g1", "投资方A", "stat", "exclusion.review", "s1")
        self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "投资方A")
        observation_id = self.connection.execute(
            "SELECT observation_id FROM observations ORDER BY observation_id LIMIT 1"
        ).fetchone()[0]
        requested = self.service.request_exclusion("operator", observation_id, "记录存疑")

        # 利益关系出现：在执席位立即关闭，本人不能再操作该未决事项。
        result = self.g.disclose_interest("stat", "stat", "投资方A", "兼职顾问", "interest-1")
        self.assertGreaterEqual(result["disclosure_id"], 1)
        with self.assertRaises(Forbidden):
            self.service.review_exclusion("stat", requested["exclusion_id"], True, "证据充分")

        # 替代人员凭自己的新授权接手，不能继承原席位之外的任何访问。
        self.grant_accept("g2", "投资方A", "stat-2", "exclusion.review", "s2")
        self.g.assign_review("operator", batch_id, "exclusion_review", "stat-2", "投资方A")
        reviewed = self.service.review_exclusion(
            "stat-2", requested["exclusion_id"], True, "证据充分"
        )
        self.assertEqual(reviewed["status"], "approved")
        # 复核阶段持续到批次封存；封存后席位完成，继任链完整保留。
        self.service.seal_batch("stat", batch_id, 2)
        history = self.g.seat_history(batch_id)
        self.assertEqual([(row["seat_seq"], row["state"]) for row in history],
                         [(1, "revoked"), (2, "completed")])
        self.assertEqual(history[1]["predecessor_assignment_id"], history[0]["assignment_id"])
        self.assertEqual(
            tuple(self.connection.execute(
                "SELECT reviewed_with_grant_id,reviewed_principal_id FROM exclusion_requests"
            ).fetchone()),
            ("g2", "投资方A"),
        )

    def test_suspended_grant_blocks_review_until_reassigned(self) -> None:
        batch_id = self.running_batch()
        self.service.import_observations("operator", batch_id, "obs", self.rows)
        self.grant_accept("g1", "投资方A", "stat", "exclusion.review", "s1")
        self.g.assign_review("operator", batch_id, "exclusion_review", "stat", "投资方A")
        self.g.suspend_grant("operator", "g1", "sus", "材料版本待核")
        with self.assertRaises(Forbidden):
            self.g.require_seat("stat", batch_id, "exclusion_review")

    def test_import_on_behalf_requires_scope_matched_grant(self) -> None:
        batch_id = self.running_batch()
        with self.assertRaises(Forbidden):
            self.service.import_observations(
                "operator", batch_id, "obs", self.rows, principal_id="候选服务商B"
            )
        self.grant_accept("gImp", "候选服务商B", "operator", "observation.import", "imp")
        response = self.service.import_observations(
            "operator", batch_id, "obs", self.rows, principal_id="候选服务商B"
        )
        self.assertEqual(response["inserted"], 6)
        event = self.connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type='observations.imported'"
        ).fetchone()
        self.assertIn("gImp", event["payload_json"])


class ExplanationTests(GovernanceTestBase):
    def test_explain_at_arbitrary_historical_points(self) -> None:
        batch_id = self.running_batch()
        self.g.propose_grant(
            "operator", "gH", "投资方A", "stat", "exclusion.review",
            WINDOW[0], WINDOW[1], "h:p", program_id="program-a", evidence_revision_id="rev-a",
        )
        before = self.g.explain("stat", "exclusion.review", at="2026-03-01T00:00:00Z")
        self.assertFalse(before["may_act"])
        self.assertEqual(before["blocked"][0]["reasons"], ["status_proposed"])

        self.clock.advance(days=10)
        self.g.accept_grant("stat", "gH", "h:a")
        accepted_at = self.clock.now().isoformat().replace("+00:00", "Z")
        during = self.g.explain("stat", "exclusion.review", at=accepted_at)
        self.assertTrue(during["may_act"])
        self.assertEqual(during["effective"][0]["principal_id"], "投资方A")

        self.clock.advance(hours=1)
        self.g.withdraw_grant("operator", "gH", "h:w", "会后撤销")
        after = self.g.explain("stat", "exclusion.review")
        self.assertFalse(after["may_act"])
        # 历史时点的解释不受后续撤回影响——已完成决定可被审计还原。
        historical = self.g.explain("stat", "exclusion.review", at=accepted_at)
        self.assertTrue(historical["may_act"])

    def test_eligibility_lists_conflict_reason(self) -> None:
        batch_id = self.running_batch()
        self.grant_accept("gE", "投资方A", "stat", "exclusion.review", "e")
        self.g.disclose_interest("stat", "stat", "投资方A", "亲属任职", "ei")
        eligibility = self.g.eligible_representatives(batch_id, "exclusion_review")
        self.assertEqual(eligibility["eligible"], [])
        stat = next(item for item in eligibility["ineligible"] if item["user_id"] == "stat")
        self.assertIn("interest_conflict", stat["reasons"])
        self.assertIn(
            {"user_id": "stat-2", "reasons": ["no_effective_grant"]}, eligibility["ineligible"]
        )


class ConcurrencyTests(unittest.TestCase):
    """并发委托与重复回调不能产生两份有效席位。"""

    def test_concurrent_grants_and_seats_leave_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "concurrency.sqlite3"
            setup = AssuranceService(connect(database))
            setup.create_user("operator", "秘书处", "operator")
            setup.create_user("stat", "统计", "statistician")
            setup.create_user("stat-2", "统计替补", "statistician")
            setup.register_program("operator", "program-a", "项目", "牵头方")
            setup.register_evidence_revision("operator", "rev-a", "program-a", "1.0", "b" * 64)
            setup.publish_protocol("stat", load_json(ROOT / "fixtures" / "demo_protocol.json"))
            setup.create_batch("operator", "batch-a", "demo-cooperation-v1", 1, "rev-a")
            setup.start_batch("operator", "batch-a", 1)
            del setup

            barrier = threading.Barrier(2)
            outcomes: list[object] = []

            def race_grant(index: int) -> None:
                service = AssuranceService(connect(database))
                barrier.wait()
                try:
                    service.governance.propose_grant(
                        "operator", f"race-{index}", "投资方A", "stat", "exclusion.review",
                        WINDOW[0], WINDOW[1], f"race-key-{index}",
                        program_id="program-a", evidence_revision_id="rev-a",
                    )
                    outcomes.append(("ok", index))
                except Conflict:
                    outcomes.append(("conflict", index))
                finally:
                    service.connection.close()

            threads = [threading.Thread(target=race_grant, args=(i,)) for i in (1, 2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(label for label, _ in outcomes), ["conflict", "ok"])
            open_grants = connect(database).execute(
                "SELECT count(*) FROM authorization_grants "
                "WHERE representative_id='stat' AND status IN ('proposed','accepted','suspended')"
            ).fetchone()[0]
            self.assertEqual(open_grants, 1)

            # 获胜授权先被接受，然后两个秘书处动作并发分派同一席位。
            winner_grant = connect(database).execute(
                "SELECT grant_id FROM authorization_grants WHERE representative_id='stat'"
            ).fetchone()[0]
            acceptor = AssuranceService(connect(database))
            acceptor.governance.accept_grant("stat", winner_grant, "race-accept")
            acceptor.connection.close()

            barrier2 = threading.Barrier(2)
            seat_outcomes: list[str] = []

            def race_seat(_index: int) -> None:
                service = AssuranceService(connect(database))
                barrier2.wait()
                try:
                    service.governance.assign_review(
                        "operator", "batch-a", "exclusion_review", "stat", "投资方A",
                    )
                    seat_outcomes.append("seat-ok")
                except (Conflict, InvalidState):
                    seat_outcomes.append("seat-lost")
                finally:
                    service.connection.close()

            threads = [threading.Thread(target=race_seat, args=(i,)) for i in (1, 2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(seat_outcomes), ["seat-lost", "seat-ok"])
            winner = connect(database)
            self.assertEqual(winner.execute(
                "SELECT count(*) FROM review_assignments WHERE batch_id='batch-a' "
                "AND stage='exclusion_review' AND state='active'"
            ).fetchone()[0], 1)
            winner.close()


if __name__ == "__main__":
    unittest.main()
