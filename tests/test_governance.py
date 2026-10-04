"""代表授权与回避治理的领域规则、事务、并发唯一性与历史解释测试。"""

from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from governance.clock import FrozenClock, utc_text
from governance.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from governance.service import GovernanceService
from governance.storage import connect


def iso(moment: datetime) -> str:
    return utc_text(moment.astimezone(timezone.utc))


class GovernanceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = connect(":memory:")
        self.start = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
        self.clock = FrozenClock(self.start)
        self.service = GovernanceService(self.connection, self.clock)
        self.service.bootstrap_user("sec", "秘书处", "secretariat")
        self.service.create_user("sec", "aud", "审计", "auditor")
        for user in ("alice", "bob", "carol"):
            self.service.create_user("sec", user, user, "delegate")
        self.service.create_party("sec", "fund", "投资基金", "investor")
        self.service.create_party("sec", "vendor", "候选服务商", "service_provider")
        self.service.register_material("sec", "mat", "1", "材料一版", "a" * 64)
        self.service.register_material("sec", "mat", "2", "材料二版", "b" * 64)
        self.end = iso(self.start + timedelta(days=30))
        self.scope2 = {"domain": "screen", "item_keys": ["p1", "p2"]}
        self.materials1 = [{"material_id": "mat", "version": "1"}]

    def tearDown(self) -> None:
        self.connection.close()

    def grant_accept(self, grant_id: str, grantee: str, principal: str = "fund",
                     role: str = "investor_representative", scope=None, materials=None,
                     **offer_kwargs) -> dict:
        self.service.offer_grant(
            "sec", grant_id, principal, grantee, role,
            scope or self.scope2, materials or self.materials1,
            iso(self.start), self.end, **offer_kwargs,
        )
        return self.service.respond_grant(grantee, grant_id, True, f"cb-{grant_id}")

    def fill(self, seat_id: str, person: str, principal: str = "fund",
             role: str = "investor_representative", scope=None) -> dict:
        self.service.open_seat("sec", seat_id, scope or self.scope2, role, principal)
        return self.service.fill_seat("sec", seat_id, person, f"cb-fill-{seat_id}")


class GrantLifecycleTests(GovernanceTestBase):
    def test_accept_reject_decline_are_append_only(self) -> None:
        self.grant_accept("g1", "alice")
        history = self.service.grant_history("aud", "g1")
        self.assertEqual([e["action"] for e in history["events"]], ["offered", "accepted"])

        self.service.offer_grant(
            "sec", "g2", "fund", "bob", "observer",
            {"domain": "screen", "item_keys": ["p1"]}, self.materials1,
            iso(self.start), self.end,
        )
        self.service.respond_grant("bob", "g2", False, "cb-g2", "拒绝")
        # 已拒绝的授权不能再接受。
        with self.assertRaises(InvalidState):
            self.service.respond_grant("bob", "g2", True, "cb-g2-again")
        self.assertEqual(self.service.grant_view("g2")["state"], "declined")

    def test_duplicate_accept_callback_returns_same_fact(self) -> None:
        self.service.offer_grant(
            "sec", "g1", "fund", "alice", "investor_representative",
            self.scope2, self.materials1, iso(self.start), self.end)
        first = self.service.respond_grant("alice", "g1", True, "same-key")
        second = self.service.respond_grant("alice", "g1", True, "same-key")
        self.assertEqual(first, second)
        count = self.connection.execute(
            "SELECT count(*) FROM grant_events WHERE grant_id='g1' AND action='accepted'"
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_only_grantee_can_respond(self) -> None:
        self.service.offer_grant(
            "sec", "g1", "fund", "alice", "investor_representative",
            self.scope2, self.materials1, iso(self.start), self.end,
        )
        with self.assertRaises(Forbidden):
            self.service.respond_grant("bob", "g1", True, "cb-x")

    def test_suspend_resume_revoke_transitions(self) -> None:
        self.grant_accept("g1", "alice")
        self.service.suspend_grant("sec", "g1", "核查")
        self.assertEqual(self.service.grant_view("g1")["state"], "suspended")
        with self.assertRaises(InvalidState):
            self.service.suspend_grant("sec", "g1", "重复暂停")
        self.service.resume_grant("sec", "g1", "恢复")
        self.service.revoke_grant("sec", "g1", "撤回")
        with self.assertRaises(InvalidState):
            self.service.resume_grant("sec", "g1", "已撤回不可恢复")
        actions = [
            row[0] for row in self.connection.execute(
                "SELECT action FROM grant_events WHERE grant_id='g1' ORDER BY event_id")
        ]
        self.assertEqual(actions, ["offered", "accepted", "suspended", "resumed", "revoked"])

    def test_validity_window_blocks_acceptance_after_end(self) -> None:
        self.service.offer_grant(
            "sec", "g1", "fund", "alice", "investor_representative",
            self.scope2, self.materials1, iso(self.start),
            iso(self.start + timedelta(days=1)),
        )
        self.clock.advance(days=2)
        with self.assertRaises(InvalidState):
            self.service.respond_grant("alice", "g1", True, "cb-late")

    def test_material_version_binding(self) -> None:
        # 只绑定 v1 的授权不能引用 v2 材料；通配引用（不指定版本）覆盖全部版本。
        self.grant_accept("g1", "alice")
        self.fill("s1", "alice")
        self.service.open_assignment(
            "sec", "a1", "p1", "screen", "investor_representative",
            "fund", "vendor", material_id="mat", material_version="2")
        self.assertEqual(self.service.dispatch("sec")["dispatched"], [])
        self.service.revoke_grant("sec", "g1", "换通配授权")
        self.grant_accept("g2", "alice",
                          materials=[{"material_id": "mat", "version": None}])
        self.service.fill_seat("sec", "s1", "alice", "cb-refill")
        result = self.service.dispatch("sec")
        self.assertEqual(len(result["dispatched"]), 1)


class DelegationTests(GovernanceTestBase):
    def delegated(self, new_id: str, parent: str, grantee: str, key: str, **overrides) -> dict:
        params = {
            "scope": {"domain": "screen", "item_keys": ["p1"]},
            "materials": self.materials1,
            "valid_from": iso(self.clock.now()),
            "valid_until": iso(self.clock.now() + timedelta(days=5)),
            "idempotency_key": key,
        }
        params.update(overrides)
        return self.service.delegate_grant("alice" if parent == "g1" else "bob",
                                           new_id, parent, grantee, **params)

    def test_delegation_respects_scope_window_material_and_depth(self) -> None:
        self.grant_accept("g1", "alice", delegation_allowed=True, delegation_depth=2)
        self.delegated("g2", "g1", "bob", "k1")
        self.service.respond_grant("bob", "g2", True, "cb-g2")
        # 超出原业务范围。
        with self.assertRaises(Forbidden):
            self.delegated("g-bad", "g1", "bob", "k2",
                           scope={"domain": "screen", "item_keys": ["p9"]})
        # 超出原材料版本。
        with self.assertRaises(Forbidden):
            self.delegated("g-bad2", "g1", "bob", "k3",
                           materials=[{"material_id": "mat", "version": "2"}])
        # 超出原生效区间。
        with self.assertRaises(Forbidden):
            self.delegated("g-bad3", "g1", "bob", "k4",
                           valid_until=iso(self.start + timedelta(days=90)))
        # 再转一层成功，第三层被拒绝。
        self.service.delegate_grant(
            "bob", "g3", "g2", "carol",
            {"domain": "screen", "item_keys": ["p1"]}, self.materials1,
            iso(self.clock.now()), iso(self.clock.now() + timedelta(days=2)), "k5")
        self.service.respond_grant("carol", "g3", True, "cb-g3")
        with self.assertRaises(Forbidden):
            self.service.delegate_grant(
                "carol", "g4", "g3", "alice",
                {"domain": "screen", "item_keys": ["p1"]}, self.materials1,
                iso(self.clock.now()), iso(self.clock.now() + timedelta(days=1)), "k6")
        self.assertEqual(self.service.grant_view("g3")["remaining_depth"], 0)

    def test_delegation_requires_flag(self) -> None:
        self.grant_accept("g1", "alice")  # 默认不可转委托
        with self.assertRaises(Forbidden):
            self.delegated("g2", "g1", "bob", "k1")

    def test_delegation_is_idempotent(self) -> None:
        self.grant_accept("g1", "alice", delegation_allowed=True, delegation_depth=2)
        first = self.delegated("g2", "g1", "bob", "dup")
        second = self.delegated("g2", "g1", "bob", "dup")
        self.assertEqual(first["grant_id"], second["grant_id"])
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM grants WHERE parent_grant_id='g1'").fetchone()[0],
            1,
        )


class SeatTests(GovernanceTestBase):
    def test_concurrent_filling_yields_single_occupancy(self) -> None:
        self.grant_accept("g1", "alice")
        self.service.open_seat("sec", "s1", self.scope2,
                               "investor_representative", "fund")
        self.service.fill_seat("sec", "s1", "alice", "k1")
        # 同维度第二席位即使换人也无法占用（部分唯一索引）。
        self.service.open_seat("sec", "s2", self.scope2,
                               "investor_representative", "fund")
        with self.assertRaises((Conflict, Forbidden)):
            self.service.fill_seat("sec", "s2", "bob", "k2")
        active = self.connection.execute(
            "SELECT count(*) FROM seats WHERE state='active'"
        ).fetchone()[0]
        self.assertEqual(active, 1)

    def test_duplicate_fill_callback_is_idempotent(self) -> None:
        self.grant_accept("g1", "alice")
        self.service.open_seat("sec", "s1", self.scope2,
                               "investor_representative", "fund")
        first = self.service.fill_seat("sec", "s1", "alice", "same")
        second = self.service.fill_seat("sec", "s1", "alice", "same")
        self.assertEqual(first, second)
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM seat_events WHERE action='filled'").fetchone()[0],
            1,
        )

    def test_cannot_fill_seat_without_effective_grant(self) -> None:
        self.service.open_seat("sec", "s1", self.scope2,
                               "investor_representative", "fund")
        with self.assertRaises(Forbidden):
            self.service.fill_seat("sec", "s1", "alice", "k1")

    def test_revoking_grant_vacates_seat_and_reopens_items(self) -> None:
        self.grant_accept("g1", "alice")
        self.fill("s1", "alice")
        self.service.open_assignment(
            "sec", "a1", "p1", "screen", "investor_representative",
            "fund", "vendor", material_id="mat", material_version="1")
        self.service.dispatch("sec")
        self.service.revoke_grant("sec", "g1", "授权撤销")
        self.assertEqual(self.service.seat_view("s1")["state"], "vacated")
        pending = self.service.dispatch("sec")
        self.assertEqual(pending["dispatched"], [])  # 阿琳已无席位，事项留在池中


class ConflictAndAssignmentTests(GovernanceTestBase):
    def _setup_two_items(self) -> None:
        self.grant_accept("g1", "alice")
        self.fill("s1", "alice")
        for item in ("p1", "p2"):
            self.service.open_assignment(
                "sec", f"a-{item}", item, "screen", "investor_representative",
                "fund", "vendor", material_id="mat", material_version="1")
        self.service.dispatch("sec")

    def test_conflict_recuses_only_unresolved_item_and_kept_decision(self) -> None:
        self._setup_two_items()
        self.service.attest_action(
            "alice", "screening.vote", "screen", "p1",
            "fund", "vendor", "mat", "1", "a-p1")
        self.service.resolve_assignment("sec", "a-p1", "合法办结")
        result = self.service.declare_conflict(
            "sec", "alice", "vendor", "investor_representative",
            {"domain": "screen", "item_keys": ["p2"]}, "受雇于候选服务商")
        self.assertEqual(result["reopened_items"], ["p2"])
        # 已办结保留。
        self.assertEqual(self.service.assignment_view("a-p1")["state"], "resolved")
        # 新未决记录回到池中。
        reopened_id = result["reopened_items"] and self.connection.execute(
            "SELECT assignment_id FROM assignments WHERE item_key='p2' AND state='unassigned'"
        ).fetchone()[0]
        self.assertTrue(reopened_id)
        # 席位范围被收窄而不是整个退出。
        self.assertEqual(self.service.seat_view("s1")["scope"]["item_keys"], ["p1"])
        # 阿琳对 p2 的操作被拒。
        with self.assertRaises(Forbidden):
            self.service.attest_action(
                "alice", "screening.vote", "screen", "p2",
                "fund", "vendor", "mat", "1")

    def test_replacement_gets_narrower_access_only(self) -> None:
        self._setup_two_items()
        self.service.declare_conflict(
            "sec", "alice", "vendor", "investor_representative",
            {"domain": "screen", "item_keys": ["p1", "p2"]}, "全面回避")
        # 博明只拿到 p2 的窄授权。
        self.grant_accept("g-bob", "bob",
                          scope={"domain": "screen", "item_keys": ["p2"]})
        self.service.open_seat(
            "sec", "s-bob", {"domain": "screen", "item_keys": ["p2"]},
            "investor_representative", "fund")
        self.service.fill_seat("sec", "s-bob", "bob", "kb")
        result = self.service.dispatch("sec")
        # p1 已无合格代表、留在未决池；p2 由博明接手。
        bob_rows = [d for d in result["dispatched"] if d["assignee_user_id"] == "bob"]
        self.assertEqual({d["item_key"] for d in bob_rows}, {"p2"})
        self.assertEqual(result["remaining_pending"], 1)
        # 博明不能访问 p1（未继承原授权宽度）。
        with self.assertRaises(Forbidden):
            self.service.attest_action(
                "bob", "screening.vote", "screen", "p1",
                "fund", "vendor", "mat", "1")

    def test_self_declaration_and_clear_conflict(self) -> None:
        self._setup_two_items()
        self.service.declare_conflict(
            "alice", "alice", "vendor", "investor_representative",
            {"domain": "screen", "item_keys": ["p1"]}, "自行申报")
        with self.assertRaises(Forbidden):
            self.service.attest_action(
                "alice", "screening.vote", "screen", "p1",
                "fund", "vendor", "mat", "1")
        conflict_id = self.connection.execute(
            "SELECT conflict_id FROM conflicts WHERE person_user_id='alice'").fetchone()[0]
        self.service.clear_conflict("sec", conflict_id, "关系终止")
        # 解除后资格恢复。
        eligibility = self.service.eligibility(
            "alice", "alice", "screening.vote", "screen", "p1",
            "fund", "vendor", "mat", "1")
        self.assertTrue(eligibility["eligible"])

    def test_duplicate_open_assignment_is_rejected(self) -> None:
        self.service.open_assignment(
            "sec", "a1", "p1", "screen", "investor_representative",
            "fund", "vendor")
        with self.assertRaises(Conflict):
            self.service.open_assignment(
                "sec", "a1", "p1", "screen", "investor_representative",
                "fund", "vendor")


class HistoricalExplanationTests(GovernanceTestBase):
    def test_explain_at_any_point_in_time(self) -> None:
        self.grant_accept("g1", "alice")
        self.fill("s1", "alice")
        before = iso(self.clock.now())
        self.clock.advance(hours=1)
        self.service.declare_conflict(
            "sec", "alice", "vendor", "investor_representative",
            {"domain": "screen", "item_keys": ["p1"]}, "利益关系")
        after = iso(self.clock.now())
        good = self.service.explain_at(
            "aud", "alice", "screening.vote", "screen", "p1",
            "fund", "vendor", before, "mat", "1")
        bad = self.service.explain_at(
            "aud", "alice", "screening.vote", "screen", "p1",
            "fund", "vendor", after, "mat", "1")
        self.assertTrue(good["eligible"])
        self.assertEqual(good["effective_grant_id"], "g1")
        self.assertEqual(good["seat_id"], "s1")
        self.assertFalse(bad["eligible"])
        self.assertIsNotNone(bad["active_conflict"])
        self.assertTrue(any("利益冲突" in b for b in bad["blockers"]))

    def test_explain_reconstructs_seat_scope_before_recusal(self) -> None:
        self.grant_accept("g1", "alice")
        self.fill("s1", "alice")
        checkpoint = iso(self.clock.now())
        self.clock.advance(hours=1)
        self.service.declare_conflict(
            "sec", "alice", "vendor", "investor_representative",
            {"domain": "screen", "item_keys": ["p2"]}, "回避 p2")
        # 历史时点 p2 仍在席位范围内。
        past = self.service.explain_at(
            "aud", "alice", "screening.review", "screen", "p2",
            "fund", "vendor", checkpoint, "mat", "1")
        self.assertTrue(past["eligible"])

    def test_auditor_only_endpoint_rejects_delegate(self) -> None:
        self.grant_accept("g1", "alice")
        with self.assertRaises(Forbidden):
            self.service.explain_at(
                "alice", "alice", "screening.vote", "screen", "p1",
                "fund", "vendor", iso(self.clock.now()))

    def test_audit_chain_covers_facts(self) -> None:
        self.grant_accept("g1", "alice")
        chain = self.service.audit_chain("aud")
        self.assertTrue(chain["valid"])
        self.assertGreater(chain["events"], 0)


class ImmutabilityTests(GovernanceTestBase):
    def test_fact_tables_reject_update_and_delete(self) -> None:
        self.grant_accept("g1", "alice")
        self.fill("s1", "alice")
        self.service.declare_conflict(
            "sec", "alice", "vendor", "investor_representative",
            {"domain": "screen", "item_keys": ["p1"]}, "利益关系")
        # 所有只追加事实表此时都至少有一行；UPDATE/DELETE 必须被触发器中止。
        for table in ("grant_events", "seat_events", "conflict_events", "gov_audit_events"):
            self.assertGreater(
                self.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0, table)
            with self.assertRaises(sqlite3.Error):
                self.connection.execute(f"UPDATE {table} SET actor_id='x'")
            with self.assertRaises(sqlite3.Error):
                self.connection.execute(f"DELETE FROM {table}")
            self.connection.rollback()


class ValidationTests(GovernanceTestBase):
    def test_window_must_be_ordered(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.offer_grant(
                "sec", "g1", "fund", "alice", "investor_representative",
                self.scope2, self.materials1,
                iso(self.start + timedelta(days=2)), iso(self.start))

    def test_scope_requires_items(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.offer_grant(
                "sec", "g1", "fund", "alice", "investor_representative",
                {"domain": "screen", "item_keys": []}, self.materials1,
                iso(self.start), self.end)

    def test_unknown_role_rejected(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.offer_grant(
                "sec", "g1", "fund", "alice", "emperor",
                self.scope2, self.materials1, iso(self.start), self.end)

    def test_bootstrap_only_once(self) -> None:
        with self.assertRaises(Conflict):
            self.service.bootstrap_user("sec2", "第二个秘书处", "secretariat")


if __name__ == "__main__":
    unittest.main()
