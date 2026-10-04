"""代表授权与回避治理。

本模块在账号角色之上增加一层"授权事实"：

* 授权（authorization_grants）把一次代表关系绑定到委托主体、代表人、业务动作、
  业务范围（项目与材料版本）、生效区间以及可转委托条件；
* 接受、拒绝、转授权、暂停、恢复、撤回全部以只增事件（grant_events）记录，
  授权行上的 status 只是事件流的当前投影，任何事实都不可覆盖；
* 利益关系（interest_disclosures）在申报时只暂停/撤回受影响的授权与席位，
  不触碰已完成的合法决定；
* 评审席位（review_assignments）把"谁在代表哪一方评审哪个批次"固化下来，
  动作发生时必须持有与当时有效授权绑定的在执席位。

所有时间均为带时区的 ISO-8611 UTC 字符串，可直接按字典序比较。
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any, Mapping, Sequence

from .clock import SystemClock, isoformat
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json
from .storage import transaction


# 可被授权代表行使的业务动作，及其要求的平台角色（角色与授权双重把关，
# 替代人员永远不能凭授权获得其角色之外的能力）。
ACTION_ROLES = {
    "observation.import": "operator",
    "exclusion.review": "statistician",
    "decision.write": "approver",
}

# 评审阶段 -> 行使该席位所需的授权动作。
STAGE_ACTIONS = {
    "exclusion_review": "exclusion.review",
    "admission_decision": "decision.write",
}

# 各授权事件允许的前置状态（终态 rejected/withdrawn 无任何后续转换）。
_EVENT_TRANSITIONS = {
    "accepted": {"proposed": "accepted"},
    "rejected": {"proposed": "rejected"},
    "suspended": {"accepted": "suspended"},
    "resumed": {"suspended": "accepted"},
    "withdrawn": {"accepted": "withdrawn", "suspended": "withdrawn"},
}


def parse_timestamp(value: str) -> str:
    """校验时间字符串并归一化为 UTC ISO 形式。"""

    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed("时间必须是带时区的 ISO-8601 字符串")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationFailed(f"时间格式无法解析: {value}") from exc
    if parsed.tzinfo is None:
        raise ValidationFailed("时间必须带时区")
    return isoformat(parsed)


class AuthorizationGovernance:
    """在与 AssuranceService 共享的 SQLite 连接上提供授权与回避用例。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()

    # -- 基础辅助 -----------------------------------------------------------

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(dict(payload)), self._now()),
        )

    def _grant(self, grant_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM authorization_grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"授权不存在: {grant_id}")
        return row

    def _append_event(
        self, grant_id: str, event_type: str, actor_id: str, reason: str, idempotency_key: str
    ) -> None:
        now = self._now()
        self.connection.execute(
            "INSERT INTO grant_events(grant_id,event_type,actor_id,reason,idempotency_key,effective_at,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (grant_id, event_type, actor_id, reason, idempotency_key, now, now),
        )

    def _events(self, grant_id: str) -> list[sqlite3.Row]:
        return list(self.connection.execute(
            "SELECT * FROM grant_events WHERE grant_id=? ORDER BY event_id", (grant_id,)
        ).fetchall())

    @staticmethod
    def _replay_status(events: Sequence[sqlite3.Row], at: str | None = None) -> str:
        """根据事实流重放到某时点（含该时点）的授权状态。"""

        status = "proposed"
        for event in events:
            if at is not None and event["effective_at"] > at:
                break
            if event["event_type"] == "delegated":
                continue  # 转授权事实记录在母授权上，但不改变母授权状态
            options = _EVENT_TRANSITIONS.get(event["event_type"], {})
            if status in options:
                status = options[status]
        return status

    def _active_conflict(self, user_id: str, principal_id: str, at: str | None = None) -> sqlite3.Row | None:
        """返回某人与某委托主体在指定时点生效的利益关系（若有）。"""

        if at is None:
            return self.connection.execute(
                "SELECT * FROM interest_disclosures WHERE user_id=? AND related_party_id=? AND active=1",
                (user_id, principal_id),
            ).fetchone()
        return self.connection.execute(
            "SELECT * FROM interest_disclosures "
            "WHERE user_id=? AND related_party_id=? AND declared_at<=? "
            "AND (cleared_at IS NULL OR cleared_at>?)",
            (user_id, principal_id, at, at),
        ).fetchone()

    def _chain_effective(self, row: sqlite3.Row, at: str) -> bool:
        """授权及其整条转委托祖先链在 at 时点均处于 accepted 且在生效区间内。"""

        current = row
        seen: set[str] = set()
        while True:
            if current["grant_id"] in seen:
                return False  # 防御性：链中出现环即无效
            seen.add(current["grant_id"])
            if not (current["valid_from"] <= at < current["valid_until"]):
                return False
            if self._replay_status(self._events(current["grant_id"]), at) != "accepted":
                return False
            if current["parent_grant_id"] is None:
                return True
            current = self._grant(current["parent_grant_id"])

    def _effective_grants(
        self,
        user_id: str,
        action: str,
        at: str,
        *,
        program_id: str | None = None,
        evidence_revision_id: str | None = None,
    ) -> list[sqlite3.Row]:
        """某人在 at 时点就指定动作/范围有效（整条授权链 accepted 且在生效区间内）的授权。"""

        rows = self.connection.execute(
            "SELECT * FROM authorization_grants WHERE representative_id=? AND action=?",
            (user_id, action),
        ).fetchall()
        result: list[sqlite3.Row] = []
        for row in rows:
            if program_id is not None and row["program_id"] is not None and row["program_id"] != program_id:
                continue
            if evidence_revision_id is not None and row["evidence_revision_id"] is not None \
                    and row["evidence_revision_id"] != evidence_revision_id:
                continue
            if self._chain_effective(row, at):
                result.append(row)
        return result

    def _batch_scope(self, batch_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT b.batch_id,b.evidence_revision_id,e.program_id FROM batches b "
            "JOIN evidence_revisions e ON e.evidence_revision_id=b.evidence_revision_id "
            "WHERE b.batch_id=?",
            (batch_id,),
        ).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return row

    def _descendant_grants(self, root_grant_id: str) -> list[sqlite3.Row]:
        """沿 parent_grant_id 递归找出由根授权派生的全部下游授权。"""

        return list(self.connection.execute(
            "WITH RECURSIVE chain(grant_id) AS ("
            "SELECT grant_id FROM authorization_grants WHERE parent_grant_id=? "
            "UNION ALL "
            "SELECT g.grant_id FROM authorization_grants g JOIN chain c ON g.parent_grant_id=c.grant_id"
            ") SELECT a.* FROM authorization_grants a JOIN chain c ON a.grant_id=c.grant_id",
            (root_grant_id,),
        ).fetchall())

    def _suspend_grant_sql(self, grant_id: str, actor_id: str, reason: str, idem_prefix: str) -> bool:
        """在调用方事务内把仍为 accepted 的授权（及其事件流）暂停，返回是否发生。"""

        if self._replay_status(self._events(grant_id)) != "accepted":
            return False
        self._append_event(grant_id, "suspended", actor_id, reason, f"{idem_prefix}:{grant_id}")
        self.connection.execute(
            "UPDATE authorization_grants SET status='suspended' WHERE grant_id=?", (grant_id,)
        )
        return True

    def _revoke_active_seats_sql(
        self, user_id: str | None, principal_id: str | None, grant_id: str | None, reason: str
    ) -> int:
        """在调用方事务内关闭符合条件的在执席位，返回关闭数量。"""

        clauses = ["state='active'"]
        params: list[Any] = []
        if user_id is not None:
            clauses.append("assignee_id=?")
            params.append(user_id)
        if principal_id is not None:
            clauses.append("principal_id=?")
            params.append(principal_id)
        if grant_id is not None:
            clauses.append("grant_id=?")
            params.append(grant_id)
        now = self._now()
        sql = (
            "UPDATE review_assignments SET state='revoked',revoke_reason=?,revoked_at=? "
            "WHERE " + " AND ".join(clauses)
        )
        cursor = self.connection.execute(sql, [reason, now, *params])
        return cursor.rowcount

    # -- 授权生命周期 -------------------------------------------------------

    def propose_grant(
        self,
        actor_id: str,
        grant_id: str,
        principal_id: str,
        representative_id: str,
        action: str,
        valid_from: str,
        valid_until: str,
        idempotency_key: str,
        *,
        program_id: str | None = None,
        evidence_revision_id: str | None = None,
        delegable: bool = False,
        max_chain_depth: int = 0,
        reason: str = "",
    ) -> dict[str, Any]:
        """由秘书处登记委托主体对代表的授权要约；代表接受后才产生代表权。"""

        actor = self._user(actor_id)
        if actor["role"] != "operator":
            raise Forbidden("只有秘书处可以登记授权要约")
        representative = self._user(representative_id)
        if action not in ACTION_ROLES:
            raise ValidationFailed(f"授权动作不在可代表范围: {action}")
        if representative["role"] != ACTION_ROLES[action]:
            raise ValidationFailed(
                f"代表人角色 {representative['role']} 不能持有 {action} 授权，"
                "授权不能超出其平台角色"
            )
        if not principal_id.strip():
            raise ValidationFailed("委托主体不能为空")
        valid_from = parse_timestamp(valid_from)
        valid_until = parse_timestamp(valid_until)
        if valid_until <= valid_from:
            raise ValidationFailed("生效区间必须满足 valid_until > valid_from")
        if delegable and max_chain_depth < 1:
            raise ValidationFailed("可转委托时最大转委托链深至少为 1")
        if not delegable:
            max_chain_depth = 0
        if evidence_revision_id is not None and program_id is None:
            raise ValidationFailed("绑定材料版本时必须同时绑定项目")
        if evidence_revision_id is not None:
            revision = self.connection.execute(
                "SELECT program_id FROM evidence_revisions WHERE evidence_revision_id=?",
                (evidence_revision_id,),
            ).fetchone()
            if revision is None:
                raise ValidationFailed("材料版本不存在")
            if program_id is not None and revision["program_id"] != program_id:
                raise ValidationFailed("材料版本与项目不一致")

        # 重复回调：同一幂等键直接返回已登记授权，绝不写第二份。
        existing = self.connection.execute(
            "SELECT * FROM authorization_grants WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing is not None:
            return self.grant_view(existing["grant_id"])

        scope = {"program_id": program_id, "evidence_revision_id": evidence_revision_id}
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO authorization_grants(grant_id,principal_id,representative_id,action,"
                    "program_id,evidence_revision_id,scope_json,valid_from,valid_until,delegable,"
                    "max_chain_depth,parent_grant_id,chain_depth,status,idempotency_key,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'proposed',?,?)",
                    (
                        grant_id, principal_id.strip(), representative_id, action, program_id,
                        evidence_revision_id, canonical_json(scope), valid_from, valid_until,
                        1 if delegable else 0, max_chain_depth, None, 0, idempotency_key, now,
                    ),
                )
                self._append_event(grant_id, "proposed", actor_id, reason, f"{idempotency_key}:proposed")
                self._audit("grant", grant_id, "grant.proposed", actor_id, {
                    "principal_id": principal_id, "representative_id": representative_id,
                    "action": action, "scope": scope,
                    "valid_from": valid_from, "valid_until": valid_until,
                    "delegable": delegable, "max_chain_depth": max_chain_depth,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("授权编号或幂等键冲突，或同一席位已有未终结授权") from exc
        return self.grant_view(grant_id)

    def _transition(
        self,
        actor_id: str,
        grant_id: str,
        event_type: str,
        idempotency_key: str,
        reason: str,
        *,
        allowed_actors: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        grant = self._grant(grant_id)
        self._user(actor_id)
        duplicate = self.connection.execute(
            "SELECT grant_id FROM grant_events WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if duplicate is not None:
            return self.grant_view(grant_id)  # 重复回调幂等返回
        current = self._replay_status(self._events(grant_id))
        expected = _EVENT_TRANSITIONS[event_type]
        if current not in expected:
            raise InvalidState(f"授权处于 {current}，不能 {event_type}")
        if allowed_actors is not None and actor_id not in allowed_actors and actor_id != grant["representative_id"]:
            raise Forbidden("无权改变该授权状态")
        if event_type == "accepted" and self._now() >= grant["valid_until"]:
            raise InvalidState("授权已超过生效截止时间，不能接受")
        if event_type == "accepted" and self._active_conflict(
            grant["representative_id"], grant["principal_id"]
        ):
            raise Forbidden("代表人与委托主体存在未解除的利益关系，不能接受授权")
        try:
            with transaction(self.connection, immediate=True):
                self._append_event(grant_id, event_type, actor_id, reason, idempotency_key)
                self.connection.execute(
                    "UPDATE authorization_grants SET status=? WHERE grant_id=?",
                    (expected[current], grant_id),
                )
                # 暂停或撤回立即关闭该授权支撑的在执席位，并沿转委托链级联：
                # 上游授权失效后，下游转授权不得继续生效；已完成的席位不受影响。
                if event_type in {"suspended", "withdrawn"}:
                    cascade_reason = f"上游授权 {event_type}: {reason}"
                    for descendant in self._descendant_grants(grant_id):
                        if self._suspend_grant_sql(
                            descendant["grant_id"], actor_id, cascade_reason,
                            f"{idempotency_key}:cascade",
                        ):
                            self._revoke_active_seats_sql(
                                None, None, descendant["grant_id"], cascade_reason
                            )
                    self._revoke_active_seats_sql(
                        None, None, grant_id, f"grant.{event_type}: {reason}".strip(": ")
                    )
                self._audit("grant", grant_id, f"grant.{event_type}", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("授权状态变更并发冲突") from exc
        return self.grant_view(grant_id)

    def accept_grant(self, actor_id: str, grant_id: str, idempotency_key: str, reason: str = "") -> dict[str, Any]:
        grant = self._grant(grant_id)
        if grant["parent_grant_id"] is not None and not self._chain_effective(
            self._grant(grant["parent_grant_id"]), self._now()
        ):
            raise InvalidState("上游转委托授权当前未生效，不能接受本授权")
        return self._transition(
            actor_id, grant_id, "accepted", idempotency_key, reason,
            allowed_actors=(grant["representative_id"],),
        )

    def reject_grant(self, actor_id: str, grant_id: str, idempotency_key: str, reason: str = "") -> dict[str, Any]:
        grant = self._grant(grant_id)
        return self._transition(
            actor_id, grant_id, "rejected", idempotency_key, reason,
            allowed_actors=(grant["representative_id"],),
        )

    def suspend_grant(self, actor_id: str, grant_id: str, idempotency_key: str, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ValidationFailed("暂停授权必须说明原因")
        if self._user(actor_id)["role"] != "operator":
            raise Forbidden("只有秘书处可以暂停授权")
        return self._transition(actor_id, grant_id, "suspended", idempotency_key, reason)

    def resume_grant(self, actor_id: str, grant_id: str, idempotency_key: str, reason: str = "") -> dict[str, Any]:
        grant = self._grant(grant_id)
        if self._user(actor_id)["role"] != "operator":
            raise Forbidden("只有秘书处可以恢复授权")
        if self._active_conflict(grant["representative_id"], grant["principal_id"]):
            raise Forbidden("利益关系尚未解除，不能恢复授权")
        if grant["parent_grant_id"] is not None and not self._chain_effective(
            self._grant(grant["parent_grant_id"]), self._now()
        ):
            raise InvalidState("上游转委托授权尚未恢复，本授权不能单独恢复")
        return self._transition(
            actor_id, grant_id, "resumed", idempotency_key, reason, allowed_actors=(actor_id,)
        )

    def withdraw_grant(self, actor_id: str, grant_id: str, idempotency_key: str, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ValidationFailed("撤回授权必须说明原因")
        if self._user(actor_id)["role"] != "operator":
            raise Forbidden("只有秘书处可以撤回授权")
        return self._transition(actor_id, grant_id, "withdrawn", idempotency_key, reason)

    def delegate_grant(
        self,
        actor_id: str,
        parent_grant_id: str,
        child_grant_id: str,
        representative_id: str,
        valid_from: str,
        valid_until: str,
        idempotency_key: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """代表人把母授权转委托；新授权范围、期间、链深都不得超出母授权。"""

        parent = self._grant(parent_grant_id)
        self._user(actor_id)
        if actor_id != parent["representative_id"]:
            raise Forbidden("只有授权代表人本人可以转委托")
        now = self._now()
        if not self._chain_effective(parent, now):
            raise InvalidState("母授权或其上游授权当前未生效，不能转委托")
        if not parent["delegable"]:
            raise Forbidden("该授权明确禁止转委托")
        child_depth = parent["chain_depth"] + 1
        if child_depth > parent["max_chain_depth"]:
            raise Forbidden("转委托链深超过授权约定的上限")
        valid_from = parse_timestamp(valid_from)
        valid_until = parse_timestamp(valid_until)
        if valid_until <= valid_from:
            raise ValidationFailed("生效区间必须满足 valid_until > valid_from")
        if valid_from < parent["valid_from"] or valid_until > parent["valid_until"]:
            raise Forbidden("转委托的生效区间不能超出母授权")
        delegate = self._user(representative_id)
        if delegate["role"] != ACTION_ROLES[parent["action"]]:
            raise ValidationFailed("替代人员的平台角色不满足该动作，转委托不能扩权")

        existing = self.connection.execute(
            "SELECT * FROM authorization_grants WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing is not None:
            return self.grant_view(existing["grant_id"])

        scope = {"program_id": parent["program_id"], "evidence_revision_id": parent["evidence_revision_id"]}
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO authorization_grants(grant_id,principal_id,representative_id,action,"
                    "program_id,evidence_revision_id,scope_json,valid_from,valid_until,delegable,"
                    "max_chain_depth,parent_grant_id,chain_depth,status,idempotency_key,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'proposed',?,?)",
                    (
                        child_grant_id, parent["principal_id"], representative_id, parent["action"],
                        parent["program_id"], parent["evidence_revision_id"], canonical_json(scope),
                        valid_from, valid_until, 0, 0, parent_grant_id, child_depth,
                        idempotency_key, now,
                    ),
                )
                self._append_event(
                    parent_grant_id, "delegated", actor_id, reason, f"{idempotency_key}:delegated"
                )
                self._append_event(
                    child_grant_id, "proposed", actor_id, reason, f"{idempotency_key}:child-proposed"
                )
                self._audit("grant", child_grant_id, "grant.delegated", actor_id, {
                    "parent_grant_id": parent_grant_id, "principal_id": parent["principal_id"],
                    "representative_id": representative_id, "action": parent["action"],
                    "scope": scope, "valid_from": valid_from, "valid_until": valid_until,
                    "chain_depth": child_depth,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("转授权编号或幂等键冲突，或同一席位已有未终结授权") from exc
        return self.grant_view(child_grant_id)

    # -- 利益关系 -----------------------------------------------------------

    def disclose_interest(
        self,
        actor_id: str,
        user_id: str,
        related_party_id: str,
        relation_type: str,
        idempotency_key: str,
        detail: str = "",
    ) -> dict[str, Any]:
        """登记利益关系事实，并只暂停/关闭受影响的授权与在执席位。"""

        actor = self._user(actor_id)
        target = self._user(user_id)
        if actor_id != user_id and actor["role"] != "operator":
            raise Forbidden("只有本人或秘书处可以登记利益关系")
        if not related_party_id.strip() or not relation_type.strip():
            raise ValidationFailed("相关方与关系类型不能为空")

        existing = self.connection.execute(
            "SELECT * FROM interest_disclosures WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing is not None:
            return dict(existing)

        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO interest_disclosures(user_id,related_party_id,relation_type,detail,"
                    "idempotency_key,active,declared_at) VALUES(?,?,?,?,?,1,?)",
                    (user_id, related_party_id.strip(), relation_type.strip(), detail, idempotency_key, now),
                )
                disclosure_id = cursor.lastrowid
                reason = f"利益关系申报 #{disclosure_id}: {relation_type}"

                # 只暂停与该相关方对应的、当前生效的授权；其它委托关系不受影响。
                affected_grants = self.connection.execute(
                    "SELECT grant_id FROM authorization_grants "
                    "WHERE representative_id=? AND principal_id=? AND status='accepted'",
                    (user_id, related_party_id.strip()),
                ).fetchall()
                suspended_total = 0
                for item in affected_grants:
                    if self._suspend_grant_sql(
                        item["grant_id"], actor_id, reason, f"{idempotency_key}:suspend"
                    ):
                        suspended_total += 1
                    # 利益关系同样沿转委托链级联：上游授权暂停后，
                    # 替代人员的下游授权不得继续生效。
                    cascade_reason = f"上游授权因利益关系暂停: {relation_type}"
                    for descendant in self._descendant_grants(item["grant_id"]):
                        if self._suspend_grant_sql(
                            descendant["grant_id"], actor_id, cascade_reason,
                            f"{idempotency_key}:cascade",
                        ):
                            suspended_total += 1
                            self._revoke_active_seats_sql(None, None, descendant["grant_id"], cascade_reason)

                # 关闭受影响的在执评审席位，未决事项随后由秘书处重新分派。
                revoked_seats = self._revoke_active_seats_sql(user_id, related_party_id.strip(), None, reason)
                self._audit("interest_disclosure", str(disclosure_id), "interest.declared", actor_id, {
                    "user_id": user_id, "related_party_id": related_party_id,
                    "relation_type": relation_type, "suspended_grants": suspended_total,
                    "revoked_seats": revoked_seats,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("该利益关系已在申报中，或幂等键冲突") from exc
        return {
            "disclosure_id": disclosure_id, "user_id": user_id,
            "related_party_id": related_party_id.strip(), "relation_type": relation_type.strip(),
            "active": 1, "declared_at": now,
        }

    def clear_interest(self, actor_id: str, disclosure_id: int, reason: str) -> dict[str, Any]:
        if self._user(actor_id)["role"] != "operator":
            raise Forbidden("只有秘书处可以解除利益关系")
        row = self.connection.execute(
            "SELECT * FROM interest_disclosures WHERE disclosure_id=?", (disclosure_id,)
        ).fetchone()
        if row is None:
            raise NotFound("利益关系申报不存在")
        if not row["active"]:
            raise InvalidState("利益关系已经解除")
        now = self._now()
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE interest_disclosures SET active=0,cleared_at=? WHERE disclosure_id=? AND active=1",
                (now, disclosure_id),
            )
            # 授权不自动恢复：秘书处核对后显式 resume，避免静默交还权限。
            self._audit("interest_disclosure", str(disclosure_id), "interest.cleared", actor_id, {"reason": reason})
        return {"disclosure_id": disclosure_id, "active": 0, "cleared_at": now}

    # -- 评审席位 -----------------------------------------------------------

    def _next_seat_seq(self, batch_id: str, stage: str) -> int:
        row = self.connection.execute(
            "SELECT COALESCE(MAX(seat_seq),0)+1 AS next_seq FROM review_assignments "
            "WHERE batch_id=? AND stage=?",
            (batch_id, stage),
        ).fetchone()
        return int(row["next_seq"])

    def assign_review(
        self, actor_id: str, batch_id: str, stage: str, assignee_id: str, principal_id: str
    ) -> dict[str, Any]:
        """按当前有效授权与利益关系为未决事项分派评审席位。"""

        if self._user(actor_id)["role"] != "operator":
            raise Forbidden("只有秘书处可以分派评审席位")
        if stage not in STAGE_ACTIONS:
            raise ValidationFailed(f"未知评审阶段: {stage}")
        assignee = self._user(assignee_id)
        scope = self._batch_scope(batch_id)
        now = self._now()

        active = self.connection.execute(
            "SELECT assignment_id FROM review_assignments WHERE batch_id=? AND stage=? AND state='active'",
            (batch_id, stage),
        ).fetchone()
        if active is not None:
            raise InvalidState("该阶段仍有在执席位，需先撤回或完成后才能重新分派")

        # 资格计算：动作匹配、角色匹配、材料版本匹配、生效区间、无利益冲突。
        action = STAGE_ACTIONS[stage]
        if assignee["role"] != ACTION_ROLES[action]:
            raise Forbidden(f"候选人角色 {assignee['role']} 不承担 {stage} 阶段")
        candidates = self._effective_grants(
            assignee_id, action, now,
            program_id=scope["program_id"], evidence_revision_id=scope["evidence_revision_id"],
        )
        grant = next((item for item in candidates if item["principal_id"] == principal_id), None)
        if grant is None:
            raise Forbidden(
                f"{assignee_id} 在 {now} 没有代表 {principal_id} 就该批次材料版本行使 {action} 的有效授权"
            )
        if self._active_conflict(assignee_id, principal_id):
            raise Forbidden("候选人与委托主体存在未解除的利益关系，应当回避")

        predecessor = self.connection.execute(
            "SELECT assignment_id FROM review_assignments WHERE batch_id=? AND stage=? "
            "ORDER BY seat_seq DESC LIMIT 1",
            (batch_id, stage),
        ).fetchone()
        seat_seq = self._next_seat_seq(batch_id, stage)
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO review_assignments(batch_id,stage,seat_seq,assignee_id,grant_id,"
                    "principal_id,state,predecessor_assignment_id,assigned_at) "
                    "VALUES(?,?,?,?,?,?,'active',?,?)",
                    (
                        batch_id, stage, seat_seq, assignee_id, grant["grant_id"], principal_id,
                        None if predecessor is None else predecessor["assignment_id"], now,
                    ),
                )
                assignment_id = cursor.lastrowid
                self._audit("seat", str(assignment_id), "seat.assigned", actor_id, {
                    "batch_id": batch_id, "stage": stage, "seat_seq": seat_seq,
                    "assignee_id": assignee_id, "principal_id": principal_id,
                    "grant_id": grant["grant_id"],
                    "predecessor_assignment_id": None if predecessor is None else predecessor["assignment_id"],
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("该阶段已存在在执席位（并发分派）") from exc
        return self.seat_view(assignment_id)

    def revoke_seat(self, actor_id: str, assignment_id: int, reason: str) -> dict[str, Any]:
        if self._user(actor_id)["role"] != "operator":
            raise Forbidden("只有秘书处可以撤回评审席位")
        if not reason.strip():
            raise ValidationFailed("撤回席位必须说明原因")
        row = self.connection.execute(
            "SELECT * FROM review_assignments WHERE assignment_id=?", (assignment_id,)
        ).fetchone()
        if row is None:
            raise NotFound("评审席位不存在")
        if row["state"] != "active":
            raise InvalidState("席位不在执行中")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE review_assignments SET state='revoked',revoke_reason=?,revoked_at=? "
                "WHERE assignment_id=? AND state='active'",
                (reason, self._now(), assignment_id),
            )
            self._audit("seat", str(assignment_id), "seat.revoked", actor_id, {
                "batch_id": row["batch_id"], "stage": row["stage"], "reason": reason,
            })
        return self.seat_view(assignment_id)

    def require_seat(self, actor_id: str, batch_id: str, stage: str) -> dict[str, Any]:
        """动作发生时校验：本人持在执席位，且席位绑定的授权此刻仍然有效、无冲突。"""

        seat = self.connection.execute(
            "SELECT * FROM review_assignments WHERE batch_id=? AND stage=? AND state='active'",
            (batch_id, stage),
        ).fetchone()
        if seat is None:
            raise Forbidden("该事项没有在执评审席位，需由秘书处按有效授权重新分派")
        if seat["assignee_id"] != actor_id:
            raise Forbidden("在执席位不属于当前操作人")
        grant = self._grant(seat["grant_id"])
        now = self._now()
        if self._replay_status(self._events(grant["grant_id"]), now) != "accepted":
            raise Forbidden("席位绑定的授权已不再有效，该事项需重新分派")
        if not (grant["valid_from"] <= now < grant["valid_until"]):
            raise Forbidden("席位绑定的授权不在生效区间内，该事项需重新分派")
        if self._active_conflict(actor_id, seat["principal_id"]):
            raise Forbidden("存在未解除的利益关系，应当回避；该事项需重新分派")
        result = dict(seat)
        result["grant"] = self.grant_view(grant["grant_id"])
        return result

    def require_effective_grant(
        self,
        actor_id: str,
        action: str,
        principal_id: str,
        *,
        program_id: str | None = None,
        evidence_revision_id: str | None = None,
    ) -> dict[str, Any]:
        """材料提交等非席位动作：声明受托主体，校验当时有效授权并返回授权视图。"""

        self._user(actor_id)
        now = self._now()
        grants = self._effective_grants(
            actor_id, action, now, program_id=program_id, evidence_revision_id=evidence_revision_id
        )
        grant = next((item for item in grants if item["principal_id"] == principal_id), None)
        if grant is None:
            raise Forbidden(
                f"{actor_id} 当前没有代表 {principal_id} 就该范围行使 {action} 的有效授权"
            )
        if self._active_conflict(actor_id, principal_id):
            raise Forbidden("与委托主体存在未解除的利益关系，应当回避")
        return self.grant_view(grant["grant_id"])

    def complete_seat_sql(self, assignment_id: int) -> None:
        """在调用方业务事务内把席位标记完成（与决定同提交、同回滚）。"""

        self.connection.execute(
            "UPDATE review_assignments SET state='completed',completed_at=? "
            "WHERE assignment_id=? AND state='active'",
            (self._now(), assignment_id),
        )

    # -- 资格预览与时点解释 -------------------------------------------------

    def eligible_representatives(self, batch_id: str, stage: str, at: str | None = None) -> dict[str, Any]:
        """列出某批次某阶段在指定时点（默认现在）适格/不适格的候选代表及原因。"""

        if stage not in STAGE_ACTIONS:
            raise ValidationFailed(f"未知评审阶段: {stage}")
        at = parse_timestamp(at) if at else self._now()
        scope = self._batch_scope(batch_id)
        action = STAGE_ACTIONS[stage]
        required_role = ACTION_ROLES[action]

        users = self.connection.execute(
            "SELECT user_id,role FROM users WHERE active=1 AND role=? ORDER BY user_id", (required_role,)
        ).fetchall()
        eligible: list[dict[str, Any]] = []
        ineligible: list[dict[str, Any]] = []
        for user in users:
            rows = [
                row for row in self.connection.execute(
                    "SELECT * FROM authorization_grants WHERE representative_id=? AND action=?",
                    (user["user_id"], action),
                ).fetchall()
                if not (row["program_id"] is not None and row["program_id"] != scope["program_id"])
                and not (row["evidence_revision_id"] is not None
                         and row["evidence_revision_id"] != scope["evidence_revision_id"])
            ]
            if not rows:
                ineligible.append({"user_id": user["user_id"], "reasons": ["no_effective_grant"]})
                continue
            mandates: list[dict[str, Any]] = []
            reasons: set[str] = set()
            for grant in rows:
                if self._active_conflict(user["user_id"], grant["principal_id"], at):
                    reasons.add("interest_conflict")
                if self._chain_effective(grant, at):
                    mandates.append({
                        "principal_id": grant["principal_id"], "grant_id": grant["grant_id"],
                        "chain_depth": grant["chain_depth"], "valid_until": grant["valid_until"],
                    })
                else:
                    reasons.add(f"grant_{self._replay_status(self._events(grant['grant_id']), at)}")
            # 同一时点存在另一有效授权即可参与；全部受阻时按实际原因回避。
            if mandates and "interest_conflict" not in reasons:
                eligible.append({"user_id": user["user_id"], "mandates": mandates})
            else:
                if not mandates and "interest_conflict" not in reasons:
                    reasons.add("no_effective_grant")
                ineligible.append({"user_id": user["user_id"], "reasons": sorted(reasons)})
        return {"batch_id": batch_id, "stage": stage, "at": at,
                "eligible": eligible, "ineligible": ineligible}

    def explain(
        self,
        user_id: str,
        action: str,
        at: str | None = None,
        *,
        program_id: str | None = None,
        evidence_revision_id: str | None = None,
    ) -> dict[str, Any]:
        """按任意历史时点解释某人为何能（或不能）代表某方执行某项操作。"""

        self._user(user_id)
        if action not in ACTION_ROLES:
            raise ValidationFailed(f"未知动作: {action}")
        at = parse_timestamp(at) if at else self._now()
        grants = self._effective_grants(
            user_id, action, at, program_id=program_id, evidence_revision_id=evidence_revision_id
        )
        effective: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        for grant in self.connection.execute(
            "SELECT * FROM authorization_grants WHERE representative_id=? AND action=? ORDER BY grant_id",
            (user_id, action),
        ).fetchall():
            if program_id is not None and grant["program_id"] is not None and grant["program_id"] != program_id:
                continue
            if evidence_revision_id is not None and grant["evidence_revision_id"] is not None \
                    and grant["evidence_revision_id"] != evidence_revision_id:
                continue
            status = self._replay_status(self._events(grant["grant_id"]), at)
            reasons: list[str] = []
            if status != "accepted":
                reasons.append(f"status_{status}")
            if not (grant["valid_from"] <= at < grant["valid_until"]):
                reasons.append("outside_validity_window")
            if self._active_conflict(user_id, grant["principal_id"], at):
                reasons.append("interest_conflict")
            if not reasons and not self._chain_effective(grant, at):
                reasons.append("ancestor_chain_not_effective")
            entry = {
                "grant_id": grant["grant_id"], "principal_id": grant["principal_id"],
                "action": grant["action"], "program_id": grant["program_id"],
                "evidence_revision_id": grant["evidence_revision_id"],
                "valid_from": grant["valid_from"], "valid_until": grant["valid_until"],
                "delegable": bool(grant["delegable"]), "chain_depth": grant["chain_depth"],
                "parent_grant_id": grant["parent_grant_id"], "status_at": status,
            }
            (effective if not reasons else blocked).append(entry | {"reasons": reasons})

        conflicts = [dict(row) for row in self.connection.execute(
            "SELECT disclosure_id,related_party_id,relation_type,declared_at,cleared_at "
            "FROM interest_disclosures WHERE user_id=? AND declared_at<=? "
            "AND (cleared_at IS NULL OR cleared_at>?) ORDER BY disclosure_id",
            (user_id, at, at),
        ).fetchall()]
        return {
            "user_id": user_id, "action": action, "at": at,
            "program_id": program_id, "evidence_revision_id": evidence_revision_id,
            "effective": effective, "blocked": blocked, "conflicts": conflicts,
            "may_act": bool(effective),
        }

    # -- 视图 ---------------------------------------------------------------

    def grant_view(self, grant_id: str) -> dict[str, Any]:
        grant = self._grant(grant_id)
        events = [
            {
                "event_id": row["event_id"], "event_type": row["event_type"], "actor_id": row["actor_id"],
                "reason": row["reason"], "effective_at": row["effective_at"],
            }
            for row in self._events(grant_id)
        ]
        chain: list[str] = []
        current = grant
        while current["parent_grant_id"] is not None:
            chain.append(current["parent_grant_id"])
            current = self._grant(current["parent_grant_id"])
        return {
            "grant_id": grant["grant_id"], "principal_id": grant["principal_id"],
            "representative_id": grant["representative_id"], "action": grant["action"],
            "program_id": grant["program_id"], "evidence_revision_id": grant["evidence_revision_id"],
            "valid_from": grant["valid_from"], "valid_until": grant["valid_until"],
            "delegable": bool(grant["delegable"]), "max_chain_depth": grant["max_chain_depth"],
            "parent_grant_id": grant["parent_grant_id"], "chain_depth": grant["chain_depth"],
            "status": grant["status"], "created_at": grant["created_at"],
            "ancestor_chain": list(reversed(chain)), "events": events,
        }

    def seat_view(self, assignment_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM review_assignments WHERE assignment_id=?", (assignment_id,)
        ).fetchone()
        if row is None:
            raise NotFound("评审席位不存在")
        return dict(row)

    def seat_history(self, batch_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM review_assignments WHERE batch_id=? ORDER BY stage,seat_seq", (batch_id,)
        ).fetchall()
        return [dict(row) for row in rows]
