"""代表授权与回避治理的离线验收入口。

在临时 SQLite 数据库中演练：

* 授权绑定委托主体、业务范围、材料版本、生效区间与转委托条件，接受/拒绝/
  暂停/撤回形成追加事实；
* 同一人兼具投资方代表与候选服务商受托身份时，利益关系出现后只收回受影响的
  未决事项，已办结的合法决定保留，替代人员凭更窄的新授权接手且不能越权；
* 秘书处/审计按任意历史时点解释资格；
* 并发委托与重复回调不会产生两份有效席位，事实表与审计链不可篡改。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, TypeVar

from .clock import FrozenClock, utc_text
from .errors import Forbidden
from .service import GovernanceService
from .storage import connect, inspect_schema

T = TypeVar("T")


def _iso(moment: datetime) -> str:
    return utc_text(moment.astimezone(timezone.utc))


def expect_forbidden(action: Callable[[], T]) -> bool:
    try:
        action()
    except Forbidden:
        return True
    return False


def run(workspace: Path) -> dict[str, object]:
    start = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
    clock = FrozenClock(start)
    with tempfile.TemporaryDirectory(prefix="governance-") as temporary:
        database = Path(temporary) / "governance.sqlite3"
        connection = connect(database)
        try:
            service = GovernanceService(connection, clock)

            # ---- 基础资料：秘书处、审计、代表、投资方与候选服务商 ----
            service.bootstrap_user("sec", "秘书处", "secretariat")
            service.create_user("sec", "aud", "审计人员", "auditor")
            service.create_user("sec", "alice", "阿琳（双重身份代表）", "delegate")
            service.create_user("sec", "bob", "博明（替代代表）", "delegate")
            service.create_user("sec", "dana", "达娜（转委托人）", "delegate")
            service.create_user("sec", "erin", "艾琳（再转委托人）", "delegate")
            service.create_party("sec", "investor-1", "海湾投资基金", "investor")
            service.create_party("sec", "provider-1", "云端履约服务商", "service_provider")
            service.register_material("sec", "bid-pack", "1", "候选材料第一版", "a" * 64)
            service.register_material("sec", "bid-pack", "2", "候选材料第二版", "c" * 64)

            window_end = _iso(start + timedelta(days=30))
            scope_both = {"domain": "screening-2026", "item_keys": ["item-1", "item-2"]}
            materials_v1 = [{"material_id": "bid-pack", "version": "1"}]

            # ---- 投资方授权阿琳参加两个项目筛选，允许两级转委托 ----
            service.offer_grant(
                "sec", "g-inv", "investor-1", "alice", "investor_representative",
                scope_both, materials_v1, _iso(start), window_end,
                delegation_allowed=True, delegation_depth=2, reason="投资方代表团任命",
            )
            accepted = service.respond_grant("alice", "g-inv", True, "cb-accept-1", "接受任命")
            replayed = service.respond_grant("alice", "g-inv", True, "cb-accept-1", "接受任命")
            assert replayed["state"] == accepted["state"] == "accepted"

            # ---- 服务商同时委托阿琳提交履约材料（双重身份的来源） ----
            service.offer_grant(
                "sec", "g-agent", "provider-1", "alice", "service_provider_agent",
                scope_both, materials_v1, _iso(start), window_end, reason="履约材料委托",
            )
            service.respond_grant("alice", "g-agent", True, "cb-accept-2", "接受材料委托")

            # ---- 出席位并由阿琳占用；重复回调与并发占用都只有一份有效席位 ----
            service.open_seat("sec", "seat-inv", scope_both,
                              "investor_representative", "investor-1")
            filled = service.fill_seat("sec", "seat-inv", "alice", "cb-fill-1")
            filled_replay = service.fill_seat("sec", "seat-inv", "alice", "cb-fill-1")
            assert filled["grant_id"] == filled_replay["grant_id"] == "g-inv"
            service.open_seat("sec", "seat-inv-dup", scope_both,
                              "investor_representative", "investor-1")
            assert expect_forbidden(lambda: service.fill_seat(
                "sec", "seat-inv-dup", "bob", "cb-fill-2"))

            # ---- 两个筛选事项分派给阿琳 ----
            for item in ("item-1", "item-2"):
                service.open_assignment(
                    "sec", f"asg-{item}", item, "screening-2026",
                    "investor_representative", "investor-1", "provider-1",
                    material_id="bid-pack", material_version="1",
                )
            dispatch_1 = service.dispatch("sec")
            assert {row["assignee_user_id"] for row in dispatch_1["dispatched"]} == {"alice"}

            # ---- item-1 在利益关系暴露前已合法办结 ----
            service.attest_action(
                "alice", "screening.vote", "screening-2026", "item-1",
                "investor-1", "provider-1", "bid-pack", "1", "asg-item-1",
            )
            service.resolve_assignment("sec", "asg-item-1", "筛选通过，决定归档")
            time_before_conflict = _iso(clock.now())
            clock.advance(hours=2)

            # ---- 发现阿琳受雇于候选服务商：登记利益关系（仅污染 item-2） ----
            conflict = service.declare_conflict(
                "sec", "alice", "provider-1", "investor_representative",
                {"domain": "screening-2026", "item_keys": ["item-2"]},
                "近三年内任候选服务商顾问",
            )
            time_after_conflict = _iso(clock.now())

            # 未决 item-2 收回重分；item-1 办结保留；席位范围收窄到 item-1。
            assert conflict["reopened_items"] == ["item-2"]
            reopened = service.assignment_view(f"asg-item-2:r{conflict['conflict_id']}")
            assert reopened["state"] == "unassigned"
            assert service.assignment_view("asg-item-1")["state"] == "resolved"
            assert service.seat_view("seat-inv")["scope"]["item_keys"] == ["item-1"]
            assert expect_forbidden(lambda: service.attest_action(
                "alice", "screening.vote", "screening-2026", "item-2",
                "investor-1", "provider-1", "bid-pack", "1"))

            # ---- 替代代表博明凭更窄的新授权接手 item-2 ----
            clock.advance(hours=1)
            service.offer_grant(
                "sec", "g-bob", "investor-1", "bob", "investor_representative",
                {"domain": "screening-2026", "item_keys": ["item-2"]},
                materials_v1, _iso(clock.now()), window_end, reason="回避后补位授权",
            )
            service.respond_grant("bob", "g-bob", True, "cb-accept-bob", "接受补位")
            service.open_seat("sec", "seat-bob",
                              {"domain": "screening-2026", "item_keys": ["item-2"]},
                              "investor_representative", "investor-1")
            service.fill_seat("sec", "seat-bob", "bob", "cb-fill-bob")
            dispatch_2 = service.dispatch("sec")
            assert dispatch_2["dispatched"][0]["assignee_user_id"] == "bob"
            assert dispatch_2["remaining_pending"] == 0
            bob_assignment = f"asg-item-2:r{conflict['conflict_id']}"
            attest_2 = service.attest_action(
                "bob", "screening.review", "screening-2026", "item-2",
                "investor-1", "provider-1", "bid-pack", "1", bob_assignment,
            )
            # 博明不能继承阿琳授权的宽度：item-1 不在范围、第二版材料不在绑定内。
            assert expect_forbidden(lambda: service.attest_action(
                "bob", "screening.vote", "screening-2026", "item-1",
                "investor-1", "provider-1", "bid-pack", "1"))
            assert expect_forbidden(lambda: service.attest_action(
                "bob", "screening.vote", "screening-2026", "item-2",
                "investor-1", "provider-1", "bid-pack", "2"))

            # ---- 转委托只能在范围、期限、材料与层级内进行 ----
            service.delegate_grant(
                "alice", "g-dana", "g-inv", "dana",
                {"domain": "screening-2026", "item_keys": ["item-1"]},
                materials_v1, _iso(clock.now()),
                _iso(clock.now() + timedelta(days=5)), "cb-del-1", "转委托达娜",
            )
            service.respond_grant("dana", "g-dana", True, "cb-accept-dana", "接受")
            assert expect_forbidden(lambda: service.delegate_grant(
                "alice", "g-bad-scope", "g-inv", "dana",
                {"domain": "screening-2026", "item_keys": ["item-99"]},
                materials_v1, _iso(clock.now()), window_end, "cb-del-bad", "越界转委托"))
            assert expect_forbidden(lambda: service.delegate_grant(
                "alice", "g-bad-mat", "g-inv", "dana",
                {"domain": "screening-2026", "item_keys": ["item-1"]},
                [{"material_id": "bid-pack", "version": "2"}],
                _iso(clock.now()), window_end, "cb-del-mat", "越界材料"))
            service.delegate_grant(
                "dana", "g-erin", "g-dana", "erin",
                {"domain": "screening-2026", "item_keys": ["item-1"]},
                materials_v1, _iso(clock.now()),
                _iso(clock.now() + timedelta(days=2)), "cb-del-2", "再转委托艾琳",
            )
            service.respond_grant("erin", "g-erin", True, "cb-accept-erin", "接受")
            assert expect_forbidden(lambda: service.delegate_grant(
                "erin", "g-too-deep", "g-erin", "bob",
                {"domain": "screening-2026", "item_keys": ["item-1"]},
                materials_v1, _iso(clock.now()),
                _iso(clock.now() + timedelta(days=1)), "cb-del-3", "超出转委托层级"))
            erin_chain: list[str] = []
            current: str | None = "g-erin"
            while current:
                view = service.grant_view(current)
                erin_chain.append(current)
                current = view["parent_grant_id"]
            assert erin_chain == ["g-erin", "g-dana", "g-inv"]

            # ---- 拒绝、暂停、恢复、撤回都是不可覆盖的追加事实 ----
            service.offer_grant(
                "sec", "g-spare", "investor-1", "bob", "observer",
                {"domain": "screening-2026", "item_keys": ["item-3"]},
                materials_v1, _iso(clock.now()), window_end, reason="观察席",
            )
            service.respond_grant("bob", "g-spare", False, "cb-decline-spare", "无法兼任")
            service.suspend_grant("sec", "g-agent", "材料核查期间暂停")
            service.resume_grant("sec", "g-agent", "核查完成恢复")
            service.revoke_grant("sec", "g-bob", "会议结束撤回补位授权")
            history = service.grant_history("aud", "g-agent")
            assert [event["action"] for event in history["events"]] == [
                "offered", "accepted", "suspended", "resumed"
            ]

            # ---- 任意历史时点的资格解释 ----
            before = service.explain_at(
                "aud", "alice", "screening.vote", "screening-2026", "item-2",
                "investor-1", "provider-1", time_before_conflict, "bid-pack", "1",
            )
            after = service.explain_at(
                "aud", "alice", "screening.vote", "screening-2026", "item-2",
                "investor-1", "provider-1", time_after_conflict, "bid-pack", "1",
            )
            assert before["eligible"] is True
            assert before["effective_grant_id"] == "g-inv"
            assert after["eligible"] is False
            assert any("利益冲突" in reason for reason in after["blockers"])

            timeline = service.person_timeline("aud", "alice")
            chain = service.audit_chain("aud")
            schema = inspect_schema(connection)

            # ---- 事实表物理不可篡改 ----
            immutable_blocked = False
            try:
                connection.execute("UPDATE grant_events SET reason='x' WHERE grant_id='g-inv'")
            except sqlite3.Error:
                immutable_blocked = True
            assert immutable_blocked
            try:
                connection.execute("DELETE FROM gov_audit_events")
            except sqlite3.Error:
                connection.rollback()
            else:
                immutable_blocked = False
        finally:
            connection.close()

    return {
        "status": "ok",
        "conflict_id": conflict["conflict_id"],
        "resolved_assignment_kept": "asg-item-1",
        "reopened_assignment": reopened["assignment_id"],
        "replacement_attestation": attest_2["attestation_id"],
        "eligible_before_conflict": before["eligible"],
        "eligible_after_conflict": after["eligible"],
        "grant_history_actions": [event["action"] for event in history["events"]],
        "erin_delegation_chain": erin_chain,
        "alice_grants": timeline["grants"],
        "audit_events": chain["events"],
        "audit_chain_valid": chain["valid"],
        "schema_missing_tables": schema["missing_tables"],
        "schema_version": schema["schema_version"],
        "facts_immutable": immutable_blocked,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行代表授权与回避治理的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
