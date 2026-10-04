"""代表授权与回避治理的领域用例。

设计要点：

* 授权（grant）绑定委托主体（principal，代表谁）、业务范围（scope，对哪些事项）、
  材料版本、生效区间与可转委托条件；接受、拒绝、转授权、暂停、恢复、撤回全部
  写入只追加事实表 grant_events，grants 当前状态只是事实的派生缓存。
* 事项（assignment）与动作另外携带评审对象 subject（利益相对方，例如候选服务商），
  与委托主体严格区分，从而能表达"同一人持投资方席位评审某候选服务商，同时受雇于
  该服务商"的利益冲突。
* 参与评审前按"当时有效授权 + 当时利益关系"逐事项计算资格；利益冲突出现时，
  只把受影响事项从当事代表处收回（席位范围相应收窄，必要时整个退出），
  未决事项重新分派，已办结（resolved）的合法决定不动。
* 席位（seat）由部分唯一索引保证同一委托主体/角色/业务范围至多一个占用人，
  并发委托与重复回调只会得到一次占有；替代人员凭自己的新授权占位，
  访问宽度以新授权为准。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Mapping, Sequence

from .clock import SystemClock, parse_utc, utc_text
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .models import MaterialRef, Scope, material_covers, parse_material_refs
from .storage import initialize, transaction


PARTY_KINDS = {"investor", "service_provider", "secretariat", "observer"}

# 评审身份及其可执行操作；授权只授予角色，执行时再核对动作。
ROLE_ACTIONS: dict[str, frozenset[str]] = {
    "investor_representative": frozenset(
        {"screening.review", "screening.vote", "material.read"}
    ),
    "service_provider_agent": frozenset({"material.submit", "material.read"}),
    "review_panelist": frozenset(
        {"screening.review", "screening.vote", "material.read", "decision.write"}
    ),
    "observer": frozenset({"material.read"}),
}

ROLE_PERMISSIONS = {
    "secretariat": {
        "party.write", "user.write", "material.write", "grant.offer", "grant.suspend",
        "grant.resume", "grant.revoke", "conflict.write", "seat.write", "assignment.dispatch",
        "audit.read",
    },
    "auditor": {"audit.read"},
    "delegate": set(),
}


class GovernanceService:
    """在单个 SQLite 连接上提供授权、回避、席位与分派操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    # ----- 基础辅助 -------------------------------------------------------

    def _now(self) -> str:
        return utc_text(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id,display_name,role,active FROM gov_users WHERE user_id=?",
            (user_id,),
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _party(self, party_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM parties WHERE party_id=?", (party_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"委托主体不存在: {party_id}")
        if not row["active"]:
            raise Forbidden("委托主体已停用")
        return row

    def _grant(self, grant_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"授权不存在: {grant_id}")
        return row

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM gov_audit_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": payload,
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO gov_audit_events(entity_type,entity_id,event_type,actor_id,"
            "payload_json,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                entity_type, entity_id, event_type, actor_id,
                canonical_json(payload), previous_hash, event_hash, body["created_at"],
            ),
        )

    def _idempotent(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM gov_idempotency WHERE scope=? AND idempotency_key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def _remember(self, scope: str, key: str, request_digest: str, response: Mapping[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO gov_idempotency(scope,idempotency_key,request_sha256,response_json,created_at) "
            "VALUES(?,?,?,?,?)",
            (scope, key, request_digest, canonical_json(response), self._now()),
        )

    def _grant_event(self, grant_id: str, action: str, actor_id: str, reason: str,
                     idempotency_key: str | None, payload: Mapping[str, Any]) -> None:
        now = self._now()
        self.connection.execute(
            "INSERT INTO grant_events(grant_id,action,actor_id,reason,idempotency_key,"
            "effective_at,created_at,payload_json) VALUES(?,?,?,?,?,?,?,?)",
            (grant_id, action, actor_id, reason, idempotency_key, now, now,
             canonical_json(payload)),
        )

    def _seat_event(self, seat_id: str, action: str, actor_id: str, grant_id: str | None,
                    reason: str, now: str, payload: Mapping[str, Any] | None = None) -> None:
        self.connection.execute(
            "INSERT INTO seat_events(seat_id,action,actor_id,grant_id,reason,effective_at,created_at,payload_json) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (seat_id, action, actor_id, grant_id, reason, now, now,
             canonical_json(payload if payload is not None else {})),
        )

    # ----- 基础资料 -------------------------------------------------------

    def bootstrap_user(self, user_id: str, display_name: str, role: str = "secretariat") -> dict[str, Any]:
        """建立首位治理用户（通常是秘书处）；仅当尚无任何用户时可用。"""

        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                count = self.connection.execute("SELECT count(*) FROM gov_users").fetchone()[0]
                if count:
                    raise Conflict("已经存在治理用户，引导操作被禁用")
                self.connection.execute(
                    "INSERT INTO gov_users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role, "bootstrapped": True}

    def create_user(self, actor_id: str, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        self._require(actor_id, "user.write")
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO gov_users(user_id,display_name,role,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def create_party(self, actor_id: str, party_id: str, name: str, kind: str) -> dict[str, Any]:
        self._require(actor_id, "party.write")
        if kind not in PARTY_KINDS:
            raise ValidationFailed(f"未知委托主体类型: {kind}")
        if not party_id.strip() or not name.strip():
            raise ValidationFailed("主体编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO parties(party_id,name,kind,created_at) VALUES(?,?,?,?)",
                    (party_id.strip(), name.strip(), kind, self._now()),
                )
                self._audit("party", party_id.strip(), "party.created", actor_id,
                            {"name": name, "kind": kind})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"委托主体已存在: {party_id}") from exc
        return {"party_id": party_id.strip(), "name": name.strip(), "kind": kind}

    def register_material(
        self, actor_id: str, material_id: str, version: str, title: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "material.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("材料摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO materials(material_id,version,title,content_sha256,registered_by,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (material_id, version, title, content_sha256.lower(), actor_id, self._now()),
                )
                self._audit(
                    "material", f"{material_id}@{version}", "material.registered", actor_id,
                    {"material_id": material_id, "version": version, "sha256": content_sha256.lower()},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("材料编号版本或摘要冲突") from exc
        return {"material_id": material_id, "version": version}

    # ----- 授权出具与回应 -------------------------------------------------

    def _validate_material_refs(self, refs: Sequence[MaterialRef]) -> None:
        for ref in refs:
            if ref.version is not None:
                row = self.connection.execute(
                    "SELECT 1 FROM materials WHERE material_id=? AND version=?",
                    (ref.material_id, ref.version),
                ).fetchone()
            else:
                row = self.connection.execute(
                    "SELECT 1 FROM materials WHERE material_id=? LIMIT 1", (ref.material_id,)
                ).fetchone()
            if row is None:
                raise ValidationFailed(f"材料版本不存在: {ref.material_id}@{ref.version or '*'}")

    @staticmethod
    def _normalize_window(valid_from: str, valid_until: str | None) -> tuple[str, str | None]:
        try:
            start = utc_text(parse_utc(valid_from, "valid_from"))
            end = None if valid_until is None else utc_text(parse_utc(valid_until, "valid_until"))
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        if end is not None and end <= start:
            raise ValidationFailed("valid_until 必须晚于 valid_from")
        return start, end

    @staticmethod
    def _scope_of(row: sqlite3.Row) -> Scope:
        data = json.loads(row["scope_json"])
        return Scope(domain=data["domain"], item_keys=tuple(data["item_keys"]))

    def offer_grant(
        self,
        actor_id: str,
        grant_id: str,
        principal_party_id: str,
        grantee_user_id: str,
        role_key: str,
        scope: Mapping[str, Any],
        materials: Sequence[Mapping[str, Any]],
        valid_from: str,
        valid_until: str | None = None,
        delegation_allowed: bool = False,
        delegation_depth: int = 0,
        reason: str = "",
    ) -> dict[str, Any]:
        self._require(actor_id, "grant.offer")
        if role_key not in ROLE_ACTIONS:
            raise ValidationFailed(f"未知代表角色: {role_key}")
        parsed_scope = Scope.from_dict(scope)
        parsed_materials = parse_material_refs(materials)
        start, end = self._normalize_window(valid_from, valid_until)
        if delegation_allowed and delegation_depth < 1:
            raise ValidationFailed("允许转委托时 delegation_depth 必须大于零")
        if delegation_depth < 0:
            raise ValidationFailed("delegation_depth 不能为负")
        self._party(principal_party_id)
        self._user(grantee_user_id)
        self._validate_material_refs(parsed_materials)
        scope_json = canonical_json(parsed_scope.to_dict())
        materials_json = canonical_json([ref.to_dict() for ref in parsed_materials])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO grants(grant_id,parent_grant_id,principal_party_id,grantee_user_id,role_key,"
                    "scope_json,materials_json,valid_from,valid_until,delegation_allowed,remaining_depth,"
                    "state,offered_by,offered_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        grant_id, None, principal_party_id, grantee_user_id, role_key,
                        scope_json, materials_json, start, end,
                        1 if delegation_allowed else 0, delegation_depth,
                        "offered", actor_id, self._now(),
                    ),
                )
                self._grant_event(
                    grant_id, "offered", actor_id, reason, None,
                    {"principal_party_id": principal_party_id, "grantee_user_id": grantee_user_id},
                )
                self._audit("grant", grant_id, "grant.offered", actor_id, {
                    "principal_party_id": principal_party_id,
                    "grantee_user_id": grantee_user_id,
                    "role_key": role_key,
                    "scope": parsed_scope.to_dict(),
                    "valid_from": start,
                    "valid_until": end,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"授权编号冲突或引用不存在: {grant_id}") from exc
        return self.grant_view(grant_id)

    def respond_grant(
        self, actor_id: str, grant_id: str, accept: bool,
        idempotency_key: str, reason: str = "",
    ) -> dict[str, Any]:
        """代表本人接受或拒绝授权；重复回调按幂等键返回同一事实。"""

        user = self._user(actor_id)
        digest = content_digest([{"grant_id": grant_id, "accept": accept}])
        idem_scope = f"grant-response:{grant_id}"
        with transaction(self.connection, immediate=True):
            cached = self._idempotent(idem_scope, idempotency_key, digest)
            if cached is not None:
                return cached
            grant = self._grant(grant_id)
            if grant["grantee_user_id"] != user["user_id"]:
                raise Forbidden("只有被授权代表本人可以接受或拒绝")
            if grant["state"] != "offered":
                raise InvalidState(f"授权当前状态为 {grant['state']}，不能再回应")
            now = self._now()
            if grant["valid_until"] is not None and grant["valid_until"] <= now:
                raise InvalidState("授权已超过生效区间终点，不能接受")
            new_state = "accepted" if accept else "declined"
            self.connection.execute(
                "UPDATE grants SET state=? WHERE grant_id=? AND state='offered'",
                (new_state, grant_id),
            )
            self._grant_event(
                grant_id, "accepted" if accept else "declined", actor_id, reason,
                idempotency_key, {"idempotency_key": idempotency_key},
            )
            self._audit("grant", grant_id, f"grant.{new_state}", actor_id, {"reason": reason})
            response = self.grant_view(grant_id)
            self._remember(idem_scope, idempotency_key, digest, response)
        return response

    def delegate_grant(
        self,
        actor_id: str,
        new_grant_id: str,
        parent_grant_id: str,
        grantee_user_id: str,
        scope: Mapping[str, Any],
        materials: Sequence[Mapping[str, Any]],
        valid_from: str,
        valid_until: str | None,
        idempotency_key: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """被授权人在授权允许的范围内转委托；范围、期限、材料都不能超出原授权。"""

        user = self._user(actor_id)
        parent = self._grant(parent_grant_id)
        request_digest = content_digest([{
            "new_grant_id": new_grant_id,
            "parent_grant_id": parent_grant_id,
            "grantee_user_id": grantee_user_id,
            "scope": scope,
            "materials": list(materials),
            "valid_from": valid_from,
            "valid_until": valid_until,
        }])
        idem_scope = f"grant-delegate:{parent_grant_id}"
        with transaction(self.connection, immediate=True):
            cached = self._idempotent(idem_scope, idempotency_key, request_digest)
            if cached is not None:
                return cached
            if parent["grantee_user_id"] != user["user_id"]:
                raise Forbidden("只有原授权持有人可以转委托")
            if parent["state"] != "accepted":
                raise InvalidState("只有已接受的授权可以转委托")
            if not parent["delegation_allowed"] or parent["remaining_depth"] < 1:
                raise Forbidden("本授权不允许转委托或转委托层级已用尽")
            now = self._now()
            if not (parent["valid_from"] <= now
                    and (parent["valid_until"] is None or parent["valid_until"] > now)):
                raise InvalidState("原授权不在生效区间内")

            child_scope = Scope.from_dict(scope)
            parent_scope = self._scope_of(parent)
            if not parent_scope.contains(child_scope):
                raise Forbidden("转委托业务范围不能超出原授权")
            child_materials = parse_material_refs(materials)
            parent_materials = parse_material_refs(json.loads(parent["materials_json"]))
            for ref in child_materials:
                if not material_covers(parent_materials, ref.material_id, ref.version):
                    raise Forbidden(f"转委托材料版本 {ref.material_id}@{ref.version or '*'} 超出原授权")
            start, end = self._normalize_window(valid_from, valid_until)
            if start < parent["valid_from"]:
                raise Forbidden("转委托生效起点不能早于原授权")
            if parent["valid_until"] is not None and (end is None or end > parent["valid_until"]):
                raise Forbidden("转委托生效终点不能超出原授权")
            self._user(grantee_user_id)
            self._validate_material_refs(child_materials)
            # remaining_depth 是转委托链深度上限（非可转发次数），只在子授权上递减。
            remaining = parent["remaining_depth"] - 1
            try:
                self.connection.execute(
                    "INSERT INTO grants(grant_id,parent_grant_id,principal_party_id,grantee_user_id,role_key,"
                    "scope_json,materials_json,valid_from,valid_until,delegation_allowed,remaining_depth,"
                    "state,offered_by,offered_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_grant_id, parent_grant_id, parent["principal_party_id"], grantee_user_id,
                        parent["role_key"], canonical_json(child_scope.to_dict()),
                        canonical_json([ref.to_dict() for ref in child_materials]),
                        start, end, 1 if remaining > 0 else 0, remaining,
                        "offered", actor_id, now,
                    ),
                )
                self._grant_event(
                    new_grant_id, "offered", actor_id, reason, None,
                    {"parent_grant_id": parent_grant_id, "idempotency_key": idempotency_key},
                )
                self._audit("grant", new_grant_id, "grant.delegated", actor_id, {
                    "parent_grant_id": parent_grant_id,
                    "grantee_user_id": grantee_user_id,
                    "remaining_depth": remaining,
                })
            except sqlite3.IntegrityError as exc:
                raise Conflict("转授权授权编号冲突或引用不存在") from exc
            response = self.grant_view(new_grant_id)
            self._remember(idem_scope, idempotency_key, request_digest, response)
        return response

    def suspend_grant(self, actor_id: str, grant_id: str, reason: str) -> dict[str, Any]:
        return self._set_grant_state(
            actor_id, grant_id, "grant.suspend", "suspended", frozenset({"accepted"}),
            "suspended", reason,
        )

    def resume_grant(self, actor_id: str, grant_id: str, reason: str) -> dict[str, Any]:
        return self._set_grant_state(
            actor_id, grant_id, "grant.resume", "resumed", frozenset({"suspended"}),
            "accepted", reason,
        )

    def revoke_grant(self, actor_id: str, grant_id: str, reason: str) -> dict[str, Any]:
        return self._set_grant_state(
            actor_id, grant_id, "grant.revoke", "revoked",
            frozenset({"offered", "accepted", "suspended"}), "revoked", reason,
        )

    def _set_grant_state(
        self, actor_id: str, grant_id: str, permission: str, action: str,
        expected: frozenset[str], target: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, permission)
        with transaction(self.connection, immediate=True):
            grant = self._grant(grant_id)
            if grant["state"] not in expected:
                raise InvalidState(f"授权当前状态为 {grant['state']}，不能{action}")
            self.connection.execute("UPDATE grants SET state=? WHERE grant_id=?", (target, grant_id))
            self._grant_event(grant_id, action, actor_id, reason, None, {})
            self._audit("grant", grant_id, f"grant.{action}", actor_id, {"reason": reason})
            # 暂停或撤回都使当前授权无法继续支撑席位；收回相关未决事项，已办结不动。
            if action in {"suspended", "revoked"}:
                label = "授权撤回" if action == "revoked" else "授权暂停"
                self._release_grant_seats(grant_id, actor_id, label)
        return self.grant_view(grant_id)

    def grant_view(self, grant_id: str) -> dict[str, Any]:
        grant = self._grant(grant_id)
        return {
            "grant_id": grant["grant_id"],
            "parent_grant_id": grant["parent_grant_id"],
            "principal_party_id": grant["principal_party_id"],
            "grantee_user_id": grant["grantee_user_id"],
            "role_key": grant["role_key"],
            "scope": json.loads(grant["scope_json"]),
            "materials": json.loads(grant["materials_json"]),
            "valid_from": grant["valid_from"],
            "valid_until": grant["valid_until"],
            "delegation_allowed": bool(grant["delegation_allowed"]),
            "remaining_depth": grant["remaining_depth"],
            "state": grant["state"],
            "offered_by": grant["offered_by"],
            "offered_at": grant["offered_at"],
        }

    def grant_history(self, actor_id: str, grant_id: str) -> dict[str, Any]:
        self._user(actor_id)
        self._grant(grant_id)
        events = self.connection.execute(
            "SELECT action,actor_id,reason,effective_at,payload_json FROM grant_events "
            "WHERE grant_id=? ORDER BY event_id",
            (grant_id,),
        ).fetchall()
        return {
            "grant_id": grant_id,
            "events": [
                {
                    "action": row["action"],
                    "actor_id": row["actor_id"],
                    "reason": row["reason"],
                    "effective_at": row["effective_at"],
                    "payload": json.loads(row["payload_json"]),
                }
                for row in events
            ],
        }

    # ----- 利益冲突（事项级回避） -----------------------------------------

    def declare_conflict(
        self,
        actor_id: str,
        person_user_id: str,
        subject_party_id: str,
        role_key: str,
        scope: Mapping[str, Any],
        relation: str,
        material: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """登记利益关系事实；只收回受影响事项，未决事项重新分派。

        秘书处可代登记，代表本人也可自行申报。scope.item_keys 给出受污染的事项集合，
        该代表在其他事项上的席位与授权不受影响（"只撤销受影响的权限"）。
        """

        actor = self._user(actor_id)
        if actor["role"] != "secretariat" and actor["user_id"] != person_user_id:
            raise Forbidden("只有秘书处或本人可以登记利益关系")
        if role_key not in ROLE_ACTIONS:
            raise ValidationFailed(f"未知代表角色: {role_key}")
        parsed_scope = Scope.from_dict(scope)
        tainted = set(parsed_scope.item_keys)
        self._party(subject_party_id)
        self._user(person_user_id)
        if not relation.strip():
            raise ValidationFailed("利益关系说明不能为空")
        material_ref = None if material is None else MaterialRef.from_dict(material, "material")
        if material_ref is not None:
            self._validate_material_refs((material_ref,))
        with transaction(self.connection, immediate=True):
            open_row = self.connection.execute(
                "SELECT conflict_id FROM conflicts WHERE person_user_id=? AND counterparty_party_id=? "
                "AND role_key=? AND status='active'",
                (person_user_id, subject_party_id, role_key),
            ).fetchone()
            if open_row is not None:
                raise Conflict("该利益关系已处于生效状态")
            now = self._now()
            cursor = self.connection.execute(
                "INSERT INTO conflicts(person_user_id,counterparty_party_id,role_key,scope_json,"
                "relation,material_id,material_version,status,declared_by,declared_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    person_user_id, subject_party_id, role_key,
                    canonical_json(parsed_scope.to_dict()), relation.strip(),
                    None if material_ref is None else material_ref.material_id,
                    None if material_ref is None else material_ref.version,
                    "active", actor_id, now,
                ),
            )
            conflict_id = int(cursor.lastrowid)
            self.connection.execute(
                "INSERT INTO conflict_events(conflict_id,action,actor_id,effective_at,created_at,payload_json) "
                "VALUES(?,?,?,?,?,?)",
                (conflict_id, "declared", actor_id, now, now, canonical_json({"relation": relation})),
            )
            affected_seats = self._recuse_seats(
                person_user_id, role_key, tainted, actor_id, conflict_id, now
            )
            reopened_items = self._recuse_assignments(
                person_user_id, subject_party_id, role_key, tainted, conflict_id, now
            )
            self._audit("conflict", str(conflict_id), "conflict.declared", actor_id, {
                "person_user_id": person_user_id,
                "subject_party_id": subject_party_id,
                "role_key": role_key,
                "affected_seats": affected_seats,
                "reopened_items": reopened_items,
            })
        return {
            "conflict_id": conflict_id,
            "status": "active",
            "affected_seats": affected_seats,
            "reopened_items": reopened_items,
        }

    def clear_conflict(self, actor_id: str, conflict_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "conflict.write")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM conflicts WHERE conflict_id=?", (conflict_id,)
            ).fetchone()
            if row is None:
                raise NotFound("利益关系记录不存在")
            if row["status"] != "active":
                raise InvalidState("利益关系已解除")
            now = self._now()
            self.connection.execute(
                "UPDATE conflicts SET status='cleared',cleared_by=?,cleared_at=?,clear_reason=? "
                "WHERE conflict_id=?",
                (actor_id, now, reason, conflict_id),
            )
            self.connection.execute(
                "INSERT INTO conflict_events(conflict_id,action,actor_id,effective_at,created_at,payload_json) "
                "VALUES(?,?,?,?,?,?)",
                (conflict_id, "cleared", actor_id, now, now, canonical_json({"reason": reason})),
            )
            restored = self._restore_seats(row, actor_id, now)
            self._audit("conflict", str(conflict_id), "conflict.cleared", actor_id,
                        {"reason": reason, "restored_seats": restored})
        return {"conflict_id": conflict_id, "status": "cleared"}

    def _restore_seats(self, conflict: sqlite3.Row, actor_id: str, now: str) -> list[dict[str, object]]:
        """利益关系解除后，把当时回避的事项还给仍在任的席位（其他冲突污染的除外）。"""

        events = self.connection.execute(
            "SELECT seat_id,payload_json FROM seat_events WHERE action='recused' "
            "AND json_extract(payload_json,'$.conflict_id')=? ORDER BY event_id",
            (conflict["conflict_id"],),
        ).fetchall()
        restored: list[dict[str, object]] = []
        for event in events:
            payload = json.loads(event["payload_json"])
            seat = self.connection.execute(
                "SELECT * FROM seats WHERE seat_id=? AND state='active'",
                (event["seat_id"],),
            ).fetchone()
            if seat is None:
                continue  # 席位已整个退出或换人，不自动复活。
            current = self._scope_of(seat)
            addable = [
                item for item in payload.get("removed_items", ())
                if item not in current.item_keys
                and self._active_conflict(
                    conflict["person_user_id"], conflict["counterparty_party_id"],
                    conflict["role_key"], item, now,
                ) is None
            ]
            if not addable:
                continue
            new_scope = Scope(current.domain, tuple(sorted(set(current.item_keys) | set(addable))))
            self.connection.execute(
                "UPDATE seats SET scope_json=? WHERE seat_id=? AND state='active'",
                (canonical_json(new_scope.to_dict()), seat["seat_id"]),
            )
            self._seat_event(seat["seat_id"], "restored", actor_id, seat["grant_id"],
                             f"利益冲突 #{conflict['conflict_id']} 解除", now,
                             {"conflict_id": conflict["conflict_id"], "added_items": addable})
            restored.append({"seat_id": seat["seat_id"], "added_items": addable})
        return restored

    def _recuse_seats(
        self, person: str, role_key: str, tainted: set[str],
        actor_id: str, conflict_id: int, now: str
    ) -> list[dict[str, str]]:
        """把受污染事项从当事代表占有的席位范围中剔除；范围清空则退出席位。"""

        rows = self.connection.execute(
            "SELECT * FROM seats WHERE holder_user_id=? AND state='active' AND role_key=?",
            (person, role_key),
        ).fetchall()
        affected: list[dict[str, str]] = []
        for row in rows:
            current = self._scope_of(row)
            overlap = sorted(set(current.item_keys) & tainted)
            if not overlap:
                continue
            remaining = tuple(item for item in current.item_keys if item not in tainted)
            if remaining:
                new_scope = Scope(current.domain, remaining)
                self.connection.execute(
                    "UPDATE seats SET scope_json=? WHERE seat_id=? AND state='active'",
                    (canonical_json(new_scope.to_dict()), row["seat_id"]),
                )
                action, target_state = "recused", "active"
            else:
                self.connection.execute(
                    "UPDATE seats SET state='vacated',vacated_at=? WHERE seat_id=? AND state='active'",
                    (now, row["seat_id"]),
                )
                action, target_state = "vacated", "vacated"
            self._seat_event(row["seat_id"], action, actor_id, row["grant_id"],
                             f"利益冲突 #{conflict_id} 事项回避", now, {
                                 "conflict_id": conflict_id,
                                 "removed_items": overlap,
                                 "state": target_state,
                             })
            affected.append({"seat_id": row["seat_id"], "action": action, "removed_items": overlap})
        return affected

    def _recuse_assignments(
        self, person: str, subject: str, role_key: str, tainted: set[str],
        conflict_id: int, now: str
    ) -> list[str]:
        rows = self.connection.execute(
            "SELECT * FROM assignments WHERE assignee_user_id=? AND state='active' AND role_key=?",
            (person, role_key),
        ).fetchall()
        items: list[str] = []
        for row in rows:
            item_scope = json.loads(row["item_scope_json"])
            if item_scope.get("item_key") not in tainted:
                continue
            if row["subject_party_id"] != subject:
                continue
            self.connection.execute(
                "UPDATE assignments SET state='reassigned',note=? WHERE assignment_id=? AND state='active'",
                (f"利益冲突 #{conflict_id}，重新分派", row["assignment_id"]),
            )
            self.connection.execute(
                "INSERT INTO assignments(assignment_id,item_key,item_scope_json,role_key,material_id,"
                "material_version,principal_party_id,subject_party_id,state,note,created_at) "
                "SELECT ?,item_key,item_scope_json,role_key,material_id,material_version,"
                "principal_party_id,subject_party_id,'unassigned',?,? FROM assignments WHERE assignment_id=?",
                (
                    f"{row['assignment_id']}:r{conflict_id}",
                    f"承接自 {row['assignment_id']}（利益冲突 #{conflict_id}）",
                    now, row["assignment_id"],
                ),
            )
            items.append(row["item_key"])
        return items

    # ----- 席位 -----------------------------------------------------------

    def open_seat(
        self, actor_id: str, seat_id: str, scope: Mapping[str, Any],
        role_key: str, principal_party_id: str
    ) -> dict[str, Any]:
        self._require(actor_id, "seat.write")
        if role_key not in ROLE_ACTIONS:
            raise ValidationFailed(f"未知代表角色: {role_key}")
        parsed_scope = Scope.from_dict(scope)
        self._party(principal_party_id)
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO seats(seat_id,scope_json,role_key,principal_party_id,state,"
                    "opened_by,opened_at) VALUES(?,?,?,?, 'open', ?,?)",
                    (seat_id, canonical_json(parsed_scope.to_dict()), role_key,
                     principal_party_id, actor_id, now),
                )
                self._seat_event(seat_id, "opened", actor_id, None, "", now,
                                 {"scope": parsed_scope.to_dict()})
                self._audit("seat", seat_id, "seat.opened", actor_id, {
                    "role_key": role_key,
                    "principal_party_id": principal_party_id,
                    "scope": parsed_scope.to_dict(),
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("席位编号冲突或委托主体不存在") from exc
        return self.seat_view(seat_id)

    def fill_seat(
        self, actor_id: str, seat_id: str, person_user_id: str, idempotency_key: str
    ) -> dict[str, Any]:
        """按当前有效授权占有席位；并发调用与重复回调只有一次成功。"""

        self._require(actor_id, "seat.write")
        self._user(person_user_id)
        digest = content_digest([{"seat_id": seat_id, "person_user_id": person_user_id}])
        idem_scope = f"seat-fill:{seat_id}"
        with transaction(self.connection, immediate=True):
            cached = self._idempotent(idem_scope, idempotency_key, digest)
            if cached is not None:
                return cached
            seat = self.connection.execute(
                "SELECT * FROM seats WHERE seat_id=?", (seat_id,)
            ).fetchone()
            if seat is None:
                raise NotFound("席位不存在")
            if seat["state"] not in {"open", "vacated"}:
                raise InvalidState(f"席位当前状态为 {seat['state']}，不能占用")
            seat_scope = self._scope_of(seat)
            grant = self._pick_grant(
                person_user_id, seat["role_key"], seat["principal_party_id"],
                seat_scope, None, self._now(),
            )
            if grant is None:
                raise Forbidden("该人员当前没有覆盖此席位委托主体、角色与业务范围的有效授权")
            now = self._now()
            try:
                cursor = self.connection.execute(
                    "UPDATE seats SET state='active',grant_id=?,holder_user_id=?,activated_at=? "
                    "WHERE seat_id=? AND state IN ('open','vacated')",
                    (grant["grant_id"], person_user_id, now, seat_id),
                )
            except sqlite3.IntegrityError as exc:
                # 不同席位行在同一业务维度上并发转 active，被部分唯一索引拒绝。
                raise Conflict("席位已被并发占用，重复回调不会产生第二份有效席位") from exc
            if cursor.rowcount != 1:
                # 同一席位行被并发抢先占用：条件更新匹配 0 行，必须中止。
                raise Conflict("席位已被并发占用，重复回调不会产生第二份有效席位")
            self._seat_event(seat_id, "filled", actor_id, grant["grant_id"], "", now,
                             {"idempotency_key": idempotency_key, "holder_user_id": person_user_id})
            self._audit("seat", seat_id, "seat.filled", actor_id, {
                "holder_user_id": person_user_id,
                "grant_id": grant["grant_id"],
            })
            response = self.seat_view(seat_id)
            self._remember(idem_scope, idempotency_key, digest, response)
        return response

    def suspend_seat(self, actor_id: str, seat_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "seat.write")
        with transaction(self.connection, immediate=True):
            seat = self._seat_state(seat_id, "active")
            now = self._now()
            self.connection.execute(
                "UPDATE seats SET state='suspended' WHERE seat_id=? AND state='active'",
                (seat_id,),
            )
            self._reopen_seat_assignments(seat, reason, now)
            self._seat_event(seat_id, "suspended", actor_id, seat["grant_id"], reason, now)
            self._audit("seat", seat_id, "seat.suspended", actor_id, {"reason": reason})
        return self.seat_view(seat_id)

    def resume_seat(self, actor_id: str, seat_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "seat.write")
        with transaction(self.connection, immediate=True):
            seat = self._seat_state(seat_id, "suspended")
            grant = self.connection.execute(
                "SELECT * FROM grants WHERE grant_id=?", (seat["grant_id"],)
            ).fetchone()
            if not self._grant_effective(grant, self._now()):
                raise InvalidState("席位背后的授权已失效，不能恢复；请重新分派")
            now = self._now()
            try:
                self.connection.execute(
                    "UPDATE seats SET state='active' WHERE seat_id=? AND state='suspended'",
                    (seat_id,),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("同一业务范围已存在其他有效席位") from exc
            self._seat_event(seat_id, "resumed", actor_id, seat["grant_id"], reason, now)
            self._audit("seat", seat_id, "seat.resumed", actor_id, {"reason": reason})
        return self.seat_view(seat_id)

    def vacate_seat(self, actor_id: str, seat_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "seat.write")
        with transaction(self.connection, immediate=True):
            self._vacate(seat_id, actor_id, reason, "seat.vacated")
        return self.seat_view(seat_id)

    def _release_grant_seats(self, grant_id: str, actor_id: str, reason: str) -> None:
        rows = self.connection.execute(
            "SELECT seat_id FROM seats WHERE grant_id=? AND state IN ('active','suspended')",
            (grant_id,),
        ).fetchall()
        for row in rows:
            self._vacate(row["seat_id"], actor_id, reason, "grant.released")

    def _reopen_seat_assignments(self, seat: sqlite3.Row, reason: str, now: str) -> None:
        items = self.connection.execute(
            "SELECT assignment_id,item_key FROM assignments WHERE seat_id=? AND state='active'",
            (seat["seat_id"],),
        ).fetchall()
        for index, item in enumerate(items):
            self.connection.execute(
                "UPDATE assignments SET state='reassigned',note=? WHERE assignment_id=? AND state='active'",
                (f"席位变动：{reason}", item["assignment_id"]),
            )
            self.connection.execute(
                "INSERT INTO assignments(assignment_id,item_key,item_scope_json,role_key,material_id,"
                "material_version,principal_party_id,subject_party_id,state,note,created_at) "
                "SELECT ?,item_key,item_scope_json,role_key,material_id,material_version,"
                "principal_party_id,subject_party_id,'unassigned',?,? FROM assignments WHERE assignment_id=?",
                (
                    f"{seat['seat_id']}:reopen{index}:{item['item_key']}",
                    f"承接自席位 {seat['seat_id']}（{reason}）", now, item["assignment_id"],
                ),
            )

    def _vacate(self, seat_id: str, actor_id: str, reason: str, audit_action: str) -> None:
        seat = self.connection.execute("SELECT * FROM seats WHERE seat_id=?", (seat_id,)).fetchone()
        if seat is None:
            raise NotFound("席位不存在")
        if seat["state"] not in {"active", "suspended"}:
            raise InvalidState(f"席位当前状态为 {seat['state']}")
        now = self._now()
        reopened = [
            row["item_key"]
            for row in self.connection.execute(
                "SELECT item_key FROM assignments WHERE seat_id=? AND state='active'", (seat_id,)
            ).fetchall()
        ]
        self._reopen_seat_assignments(seat, reason, now)
        self.connection.execute(
            "UPDATE seats SET state='vacated',vacated_at=? WHERE seat_id=?",
            (now, seat_id),
        )
        self._seat_event(seat_id, "vacated", actor_id, seat["grant_id"], reason, now)
        self._audit("seat", seat_id, f"seat.{audit_action}", actor_id, {
            "reason": reason,
            "reopened_items": reopened,
        })

    def _seat_state(self, seat_id: str, expected: str) -> sqlite3.Row:
        seat = self.connection.execute("SELECT * FROM seats WHERE seat_id=?", (seat_id,)).fetchone()
        if seat is None:
            raise NotFound("席位不存在")
        if seat["state"] != expected:
            raise InvalidState(f"席位当前状态为 {seat['state']}")
        return seat

    def seat_view(self, seat_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM seats WHERE seat_id=?", (seat_id,)).fetchone()
        if row is None:
            raise NotFound("席位不存在")
        return {
            "seat_id": row["seat_id"],
            "scope": json.loads(row["scope_json"]),
            "role_key": row["role_key"],
            "principal_party_id": row["principal_party_id"],
            "state": row["state"],
            "grant_id": row["grant_id"],
            "holder_user_id": row["holder_user_id"],
            "opened_at": row["opened_at"],
            "activated_at": row["activated_at"],
            "vacated_at": row["vacated_at"],
        }

    # ----- 授权/冲突/席位的时点重建 ---------------------------------------

    @staticmethod
    def _grant_state_at(event_list: Sequence[tuple[str, str]], at: str) -> str:
        """根据只追加事实重建某时点的授权状态。"""

        state = "offered"
        for action, effective_at in event_list:
            if effective_at <= at:
                if action == "resumed":
                    state = "accepted"
                elif action == "suspended":
                    state = "suspended"
                else:
                    state = {"offered": "offered", "accepted": "accepted",
                             "declined": "declined", "revoked": "revoked"}[action]
        return state

    def _grant_events(self, grant_id: str) -> list[tuple[str, str]]:
        rows = self.connection.execute(
            "SELECT action,effective_at FROM grant_events WHERE grant_id=? ORDER BY event_id",
            (grant_id,),
        ).fetchall()
        return [(row["action"], row["effective_at"]) for row in rows]

    def _grant_effective(self, grant_row: sqlite3.Row, at: str) -> bool:
        """指定时点授权是否可用：已接受、未暂停/撤回、在生效区间内。"""

        state = self._grant_state_at(self._grant_events(grant_row["grant_id"]), at)
        if state != "accepted":
            return False
        if grant_row["valid_from"] > at:
            return False
        if grant_row["valid_until"] is not None and grant_row["valid_until"] <= at:
            return False
        return True

    def _active_conflict(
        self, person: str, subject: str, role_key: str, item_key: str, at: str
    ) -> sqlite3.Row | None:
        """该人员相对某评审对象、在某事项上、某时点是否存在生效利益关系。"""

        rows = self.connection.execute(
            "SELECT c.*, "
            "(SELECT min(ce.effective_at) FROM conflict_events ce "
            "WHERE ce.conflict_id=c.conflict_id AND ce.action='declared') AS declared_effective, "
            "(SELECT min(ce2.effective_at) FROM conflict_events ce2 "
            "WHERE ce2.conflict_id=c.conflict_id AND ce2.action='cleared') AS cleared_effective "
            "FROM conflicts c WHERE c.person_user_id=? AND c.counterparty_party_id=? AND c.role_key=?",
            (person, subject, role_key),
        ).fetchall()
        for row in rows:
            if row["declared_effective"] > at:
                continue
            if row["cleared_effective"] is not None and row["cleared_effective"] <= at:
                continue
            data = json.loads(row["scope_json"])
            if item_key in data["item_keys"]:
                return row
        return None

    def _seat_state_at(self, seat_id: str, at: str) -> tuple[str, Scope]:
        """根据席位事件重建某时点的占有状态与业务范围（不读取被收窄的当前列）。"""

        seat = self.connection.execute("SELECT seat_id FROM seats WHERE seat_id=?", (seat_id,)).fetchone()
        state = "open"
        scope: Scope | None = None
        events = self.connection.execute(
            "SELECT action,effective_at,payload_json FROM seat_events WHERE seat_id=? ORDER BY event_id",
            (seat_id,),
        ).fetchall()
        for event in events:
            if event["effective_at"] > at:
                continue
            action = event["action"]
            payload = json.loads(event["payload_json"])
            if action == "opened":
                scope = Scope.from_dict(payload.get("scope", {})) if payload.get("scope") else scope
                state = "open"
            elif action == "recused":
                assert scope is not None
                removed = set(payload.get("removed_items", ()))
                scope = Scope(scope.domain, tuple(k for k in scope.item_keys if k not in removed))
                if payload.get("state") == "vacated":
                    state = "vacated"
            elif action == "restored":
                assert scope is not None
                added = set(payload.get("added_items", ()))
                scope = Scope(scope.domain, tuple(sorted(set(scope.item_keys) | added)))
            else:
                state = {
                    "filled": "active",
                    "suspended": "suspended", "resumed": "active", "vacated": "vacated",
                }.get(action, state)
        if scope is None:  # 没有 opened 事件（异常数据）时回退到当前列
            scope = self._scope_of(
                self.connection.execute("SELECT * FROM seats WHERE seat_id=?", (seat_id,)).fetchone()
            )
        return state, scope

    def _pick_grant(
        self,
        person: str,
        role_key: str,
        principal: str,
        scope: Scope,
        material: tuple[str, str | None] | None,
        at: str,
        subject: str | None = None,
    ) -> sqlite3.Row | None:
        """选出在给定维度上、当时有效的授权。

        subject 不为 None 时同时按利益关系回避；为空只用于占用席位前的粗校验。
        """

        rows = self.connection.execute(
            "SELECT * FROM grants WHERE grantee_user_id=? AND role_key=? AND principal_party_id=? "
            "ORDER BY offered_at,grant_id",
            (person, role_key, principal),
        ).fetchall()
        for row in rows:
            if not self._grant_effective(row, at):
                continue
            if not self._scope_of(row).contains(scope):
                continue
            if material is not None:
                refs = parse_material_refs(json.loads(row["materials_json"]))
                if not material_covers(refs, material[0], material[1]):
                    continue
            if subject is not None:
                for item_key in scope.item_keys:
                    if self._active_conflict(person, subject, role_key, item_key, at) is not None:
                        return None
            return row
        return None

    # ----- 资格计算与历史解释 ---------------------------------------------

    def _role_for_action(self, action: str) -> str:
        for role_key, actions in ROLE_ACTIONS.items():
            if action in actions:
                return role_key
        raise ValidationFailed(f"未知治理动作: {action}")

    def _explain_grant(
        self, grant: sqlite3.Row, scope: Scope,
        material: tuple[str | None, str | None], at: str
    ) -> dict[str, Any]:
        state = self._grant_state_at(self._grant_events(grant["grant_id"]), at)
        grant_scope = self._scope_of(grant)
        reasons: list[str] = []
        usable = True
        if state != "accepted":
            reasons.append(f"授权在该时点状态为 {state}")
            usable = False
        if grant["valid_from"] > at:
            reasons.append("尚未到生效起点")
            usable = False
        if grant["valid_until"] is not None and grant["valid_until"] <= at:
            reasons.append("已超过生效区间终点")
            usable = False
        if not grant_scope.contains(scope):
            reasons.append("业务范围不覆盖该事项")
            usable = False
        if material[0] is not None:
            refs = parse_material_refs(json.loads(grant["materials_json"]))
            if not material_covers(refs, material[0], material[1]):
                reasons.append("材料版本不在授权绑定范围内")
                usable = False
        return {
            "grant_id": grant["grant_id"],
            "parent_grant_id": grant["parent_grant_id"],
            "state_at": state,
            "valid_from": grant["valid_from"],
            "valid_until": grant["valid_until"],
            "scope": grant_scope.to_dict(),
            "materials": json.loads(grant["materials_json"]),
            "delegation_chain": self._grant_chain(grant["grant_id"]),
            "usable": usable,
            "reasons": reasons,
        }

    def _grant_chain(self, grant_id: str) -> list[str]:
        chain: list[str] = []
        current: str | None = grant_id
        seen: set[str] = set()
        while current is not None and current not in seen:
            seen.add(current)
            chain.append(current)
            row = self.connection.execute(
                "SELECT parent_grant_id FROM grants WHERE grant_id=?", (current,)
            ).fetchone()
            current = None if row is None else row["parent_grant_id"]
        return chain

    def eligibility(
        self,
        actor_id: str,
        person_user_id: str,
        action: str,
        item_domain: str,
        item_key: str,
        principal_party_id: str,
        subject_party_id: str,
        material_id: str | None = None,
        material_version: str | None = None,
        at: str | None = None,
    ) -> dict[str, Any]:
        """按当时有效授权和利益关系计算单事项资格，并给出可审计理由。"""

        self._user(actor_id)
        at = at or self._now()
        role_key = self._role_for_action(action)
        scope = Scope(item_domain, (item_key,))
        grants = self.connection.execute(
            "SELECT * FROM grants WHERE grantee_user_id=? AND role_key=? AND principal_party_id=? "
            "ORDER BY offered_at,grant_id",
            (person_user_id, role_key, principal_party_id),
        ).fetchall()
        candidates = [
            self._explain_grant(row, scope, (material_id, material_version), at) for row in grants
        ]
        chosen = next((candidate for candidate in candidates if candidate["usable"]), None)
        conflict = self._active_conflict(person_user_id, subject_party_id, role_key, item_key, at)
        seat_id = self._active_seat_id(person_user_id, role_key, principal_party_id, item_key, at)
        blockers: list[str] = []
        if conflict is not None:
            blockers.append(
                f"利益冲突 #{conflict['conflict_id']} 在该时点生效：{conflict['relation']}"
            )
        if chosen is None:
            if not candidates:
                blockers.append("没有绑定该委托主体与角色的授权")
            else:
                blockers.extend(
                    f"授权 {c['grant_id']}：{reason}"
                    for c in candidates for reason in c["reasons"]
                )
        if seat_id is None:
            blockers.append("该时点没有覆盖此事项的有效席位")
        return {
            "eligible": chosen is not None and conflict is None and seat_id is not None,
            "at": at,
            "person_user_id": person_user_id,
            "action": action,
            "role_key": role_key,
            "principal_party_id": principal_party_id,
            "subject_party_id": subject_party_id,
            "scope": scope.to_dict(),
            "material": None if material_id is None
            else {"material_id": material_id, "version": material_version},
            "effective_grant_id": None if chosen is None else chosen["grant_id"],
            "seat_id": seat_id,
            "active_conflict": None if conflict is None else {
                "conflict_id": conflict["conflict_id"],
                "relation": conflict["relation"],
            },
            "grant_checks": candidates,
            "blockers": blockers,
        }

    def _active_seat_id(
        self, person: str, role_key: str, principal: str, item_key: str, at: str
    ) -> str | None:
        seats = self.connection.execute(
            "SELECT seat_id FROM seats WHERE holder_user_id=? AND role_key=? AND principal_party_id=?",
            (person, role_key, principal),
        ).fetchall()
        for seat in seats:
            state, scope = self._seat_state_at(seat["seat_id"], at)
            if state == "active" and item_key in scope.item_keys:
                return seat["seat_id"]
        return None

    def explain_at(
        self,
        actor_id: str,
        person_user_id: str,
        action: str,
        item_domain: str,
        item_key: str,
        principal_party_id: str,
        subject_party_id: str,
        at: str,
        material_id: str | None = None,
        material_version: str | None = None,
    ) -> dict[str, Any]:
        """秘书处/审计按任意历史时点解释"某人为何能代表某方对某对象执行某项操作"。"""

        user = self._user(actor_id)
        if user["role"] not in {"secretariat", "auditor"}:
            raise Forbidden("只有秘书处和审计人员可以回溯解释授权")
        return self.eligibility(
            actor_id, person_user_id, action, item_domain, item_key,
            principal_party_id, subject_party_id, material_id, material_version, at=at,
        )

    # ----- 事项分派与执行凭据 ---------------------------------------------

    def open_assignment(
        self,
        actor_id: str,
        assignment_id: str,
        item_key: str,
        item_domain: str,
        role_key: str,
        principal_party_id: str,
        subject_party_id: str | None = None,
        material_id: str | None = None,
        material_version: str | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "seat.write")
        if role_key not in ROLE_ACTIONS:
            raise ValidationFailed(f"未知代表角色: {role_key}")
        self._party(principal_party_id)
        if subject_party_id is not None:
            self._party(subject_party_id)
        item_scope = canonical_json({"domain": item_domain, "item_key": item_key})
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO assignments(assignment_id,item_key,item_scope_json,role_key,material_id,"
                    "material_version,principal_party_id,subject_party_id,state,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,'unassigned',?)",
                    (
                        assignment_id, item_key, item_scope, role_key, material_id,
                        material_version, principal_party_id, subject_party_id, now,
                    ),
                )
                self._audit("assignment", assignment_id, "assignment.opened", actor_id, {
                    "item_key": item_key,
                    "role_key": role_key,
                    "principal_party_id": principal_party_id,
                    "subject_party_id": subject_party_id,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("该事项已有未决分派记录（重复回调）") from exc
        return self.assignment_view(assignment_id)

    def dispatch(self, actor_id: str, limit: int = 50) -> dict[str, Any]:
        """把未决事项分派给当前具备有效席位、授权且无利益冲突的代表；可重复调用。"""

        self._require(actor_id, "assignment.dispatch")
        if limit <= 0:
            raise ValidationFailed("limit 必须大于零")
        dispatched: list[dict[str, Any]] = []
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT * FROM assignments WHERE state='unassigned' ORDER BY created_at,assignment_id LIMIT ?",
                (limit,),
            ).fetchall()
            now = self._now()
            for item in pending:
                seat = self._find_seat_for(item, now)
                if seat is None:
                    continue
                self.connection.execute(
                    "UPDATE assignments SET state='active',seat_id=?,grant_id=?,assignee_user_id=?,"
                    "assigned_at=? WHERE assignment_id=? AND state='unassigned'",
                    (seat["seat_id"], seat["grant_id"], seat["holder_user_id"], now,
                     item["assignment_id"]),
                )
                self._audit("assignment", item["assignment_id"], "assignment.dispatched", actor_id, {
                    "item_key": item["item_key"],
                    "seat_id": seat["seat_id"],
                    "assignee_user_id": seat["holder_user_id"],
                    "grant_id": seat["grant_id"],
                })
                dispatched.append({
                    "assignment_id": item["assignment_id"],
                    "item_key": item["item_key"],
                    "seat_id": seat["seat_id"],
                    "assignee_user_id": seat["holder_user_id"],
                })
        return {"dispatched": dispatched, "remaining_pending": self._pending_count()}

    def _pending_count(self) -> int:
        return int(self.connection.execute(
            "SELECT count(*) FROM assignments WHERE state='unassigned'"
        ).fetchone()[0])

    def _find_seat_for(self, item: sqlite3.Row, at: str) -> sqlite3.Row | None:
        item_scope = json.loads(item["item_scope_json"])
        seats = self.connection.execute(
            "SELECT * FROM seats WHERE role_key=? AND principal_party_id=? AND state='active' "
            "ORDER BY activated_at,seat_id",
            (item["role_key"], item["principal_party_id"]),
        ).fetchall()
        for seat in seats:
            scope = self._scope_of(seat)
            if item_scope["item_key"] not in scope.item_keys \
                    or item_scope["domain"] != scope.domain:
                continue
            grant = self.connection.execute(
                "SELECT * FROM grants WHERE grant_id=?", (seat["grant_id"],)
            ).fetchone()
            if not self._grant_effective(grant, at):
                continue
            if item["material_id"] is not None:
                refs = parse_material_refs(json.loads(grant["materials_json"]))
                if not material_covers(refs, item["material_id"], item["material_version"]):
                    continue
            if item["subject_party_id"] is not None:
                conflict = self._active_conflict(
                    seat["holder_user_id"], item["subject_party_id"],
                    item["role_key"], item["item_key"], at,
                )
                if conflict is not None:
                    continue
            return seat
        return None

    def attest_action(
        self,
        actor_id: str,
        action: str,
        item_domain: str,
        item_key: str,
        principal_party_id: str,
        subject_party_id: str,
        material_id: str | None = None,
        material_version: str | None = None,
        assignment_id: str | None = None,
    ) -> dict[str, Any]:
        """代表执行发言/审批/查阅前的资格闸门，留下不可覆盖的凭据事实。"""

        person = self._user(actor_id)
        role_key = self._role_for_action(action)
        if action not in ROLE_ACTIONS[role_key]:
            raise Forbidden(f"角色 {role_key} 无权执行 {action}")
        at = self._now()
        scope = Scope(item_domain, (item_key,))
        assignment_row = None
        if assignment_id is not None:
            assignment_row = self.connection.execute(
                "SELECT * FROM assignments WHERE assignment_id=?", (assignment_id,)
            ).fetchone()
            if assignment_row is None:
                raise NotFound("分派事项不存在")
            if assignment_row["state"] != "active":
                raise InvalidState(f"事项当前状态为 {assignment_row['state']}，不能执行")
            if assignment_row["assignee_user_id"] != person["user_id"]:
                raise Forbidden("该事项未分派给当前代表")
        grant = self._pick_grant(
            person["user_id"], role_key, principal_party_id, scope,
            None if material_id is None else (material_id, material_version),
            at, subject=subject_party_id,
        )
        if grant is None:
            raise Forbidden("当前没有覆盖该操作的有效授权，或存在未回避的利益冲突")
        seat_id = self._active_seat_id(
            person["user_id"], role_key, principal_party_id, item_key, at
        )
        if seat_id is None:
            raise Forbidden("授权有效但未通过席位分派，不能直接执行")
        basis = self.eligibility(
            person["user_id"], person["user_id"], action, item_domain, item_key,
            principal_party_id, subject_party_id, material_id, material_version, at=at,
        )
        if not basis["eligible"]:
            raise Forbidden("资格校验未通过：" + "；".join(basis["blockers"]))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO action_attestations(person_user_id,action,scope_json,material_id,"
                "material_version,counterparty_party_id,grant_id,seat_id,assignment_id,basis_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    person["user_id"], action, canonical_json(scope.to_dict()),
                    material_id, material_version, subject_party_id,
                    grant["grant_id"], seat_id, assignment_id,
                    canonical_json(basis), at,
                ),
            )
            attestation_id = int(cursor.lastrowid)
            self._audit("attestation", str(attestation_id), "action.attested", person["user_id"], {
                "action": action,
                "item_key": item_key,
                "principal_party_id": principal_party_id,
                "subject_party_id": subject_party_id,
                "grant_id": grant["grant_id"],
                "seat_id": seat_id,
                "assignment_id": assignment_id,
            })
        return {
            "attestation_id": attestation_id,
            "person_user_id": person["user_id"],
            "action": action,
            "grant_id": grant["grant_id"],
            "seat_id": seat_id,
            "assignment_id": assignment_id,
            "basis": basis,
            "attested_at": at,
        }

    def resolve_assignment(self, actor_id: str, assignment_id: str, note: str) -> dict[str, Any]:
        """办结事项；已完成的合法决定保留，不因事后授权或利益变化而改动。"""

        self._require(actor_id, "seat.write")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM assignments WHERE assignment_id=?", (assignment_id,)
            ).fetchone()
            if row is None:
                raise NotFound("分派事项不存在")
            if row["state"] != "active":
                raise InvalidState(f"事项当前状态为 {row['state']}，不能办结")
            now = self._now()
            self.connection.execute(
                "UPDATE assignments SET state='resolved',resolved_at=?,resolved_by=?,note=? "
                "WHERE assignment_id=? AND state='active'",
                (now, actor_id, note, assignment_id),
            )
            self._audit("assignment", assignment_id, "assignment.resolved", actor_id, {"note": note})
        return self.assignment_view(assignment_id)

    def assignment_view(self, assignment_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM assignments WHERE assignment_id=?", (assignment_id,)
        ).fetchone()
        if row is None:
            raise NotFound("分派事项不存在")
        return {
            "assignment_id": row["assignment_id"],
            "item_key": row["item_key"],
            "item_scope": json.loads(row["item_scope_json"]),
            "role_key": row["role_key"],
            "material_id": row["material_id"],
            "material_version": row["material_version"],
            "principal_party_id": row["principal_party_id"],
            "subject_party_id": row["subject_party_id"],
            "seat_id": row["seat_id"],
            "grant_id": row["grant_id"],
            "assignee_user_id": row["assignee_user_id"],
            "state": row["state"],
            "note": row["note"],
            "assigned_at": row["assigned_at"],
            "resolved_at": row["resolved_at"],
            "resolved_by": row["resolved_by"],
        }

    # ----- 审计视图 -------------------------------------------------------

    def person_timeline(self, actor_id: str, person_user_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        self._user(person_user_id)
        grants = self.connection.execute(
            "SELECT grant_id FROM grants WHERE grantee_user_id=? ORDER BY offered_at,grant_id",
            (person_user_id,),
        ).fetchall()
        conflicts = self.connection.execute(
            "SELECT conflict_id,counterparty_party_id,relation,status,declared_at,cleared_at "
            "FROM conflicts WHERE person_user_id=? ORDER BY conflict_id",
            (person_user_id,),
        ).fetchall()
        seats = self.connection.execute(
            "SELECT seat_id,role_key,principal_party_id,state,activated_at,vacated_at,grant_id "
            "FROM seats WHERE holder_user_id=? ORDER BY activated_at,seat_id",
            (person_user_id,),
        ).fetchall()
        attestations = self.connection.execute(
            "SELECT attestation_id,action,counterparty_party_id,grant_id,seat_id,created_at "
            "FROM action_attestations WHERE person_user_id=? ORDER BY attestation_id",
            (person_user_id,),
        ).fetchall()
        return {
            "person_user_id": person_user_id,
            "grants": [row["grant_id"] for row in grants],
            "conflicts": [dict(row) for row in conflicts],
            "seats": [dict(row) for row in seats],
            "attestations": [dict(row) for row in attestations],
        }

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute(
            "SELECT * FROM gov_audit_events ORDER BY event_id"
        ).fetchall()
        previous_hash = "0" * 64
        valid = True
        for row in rows:
            body = {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                valid = False
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}
