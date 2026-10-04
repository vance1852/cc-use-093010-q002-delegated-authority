"""代表授权与回避治理 HTTP JSON 接口的路由与错误形态测试。"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from governance.api import JsonApplication
from governance.clock import FrozenClock, utc_text
from governance.service import GovernanceService
from governance.storage import connect


def iso(moment: datetime) -> str:
    return utc_text(moment.astimezone(timezone.utc))


class GovernanceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = connect(":memory:")
        start = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
        self.clock = FrozenClock(start)
        self.app = JsonApplication(GovernanceService(self.connection, self.clock))
        self.post("/bootstrap", {"user_id": "sec", "display_name": "秘书处"}, 201)
        self.post("/users", {"user_id": "aud", "display_name": "审计", "role": "auditor"}, 201)
        self.post("/users", {"user_id": "alice", "display_name": "阿琳", "role": "delegate"}, 201)
        self.post("/parties",
                  {"party_id": "fund", "name": "基金", "kind": "investor"}, 201)
        self.post("/parties",
                  {"party_id": "vendor", "name": "服务商", "kind": "service_provider"}, 201)
        self.post("/materials",
                  {"material_id": "mat", "version": "1", "title": "材料",
                   "content_sha256": "a" * 64}, 201)
        self.until = iso(start + timedelta(days=30))
        self.from_ = iso(start)

    def tearDown(self) -> None:
        self.connection.close()

    def request(self, method: str, path: str, payload=None, headers=None, status=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        response = self.app.handle(
            method, path, headers or {"x-actor-id": "sec"}, body)
        if status is not None:
            self.assertEqual(response.status, status, response.body)
        return response

    def post(self, path: str, payload, status=200, headers=None):
        return self.request("POST", path, payload, headers, status)

    def get(self, path: str, status=200, headers=None):
        return self.request("GET", path, None, headers, status)

    def _grant_and_accept(self) -> None:
        self.post("/grants", {
            "grant_id": "g1", "principal_party_id": "fund", "grantee_user_id": "alice",
            "role_key": "investor_representative",
            "scope": {"domain": "screen", "item_keys": ["p1"]},
            "materials": [{"material_id": "mat", "version": "1"}],
            "valid_from": self.from_, "valid_until": self.until,
        }, 201)
        self.post("/grants/g1/respond", {"accept": True},
                  headers={"x-actor-id": "alice", "Idempotency-Key": "cb1"})

    def test_health(self) -> None:
        response = self.get("/health")
        self.assertEqual(response.body["status"], "ok")

    def test_missing_actor_header(self) -> None:
        response = self.app.handle("POST", "/parties",
                                   body=json.dumps({"party_id": "x", "name": "x", "kind": "observer"}).encode())
        self.assertEqual(response.status, 422)

    def test_full_grant_seat_assignment_conflict_flow(self) -> None:
        self._grant_and_accept()
        self.post("/seats", {
            "seat_id": "s1", "scope": {"domain": "screen", "item_keys": ["p1"]},
            "role_key": "investor_representative", "principal_party_id": "fund",
        }, 201)
        fill = self.post("/seats/s1/fill", {"person_user_id": "alice"},
                         headers={"x-actor-id": "sec", "Idempotency-Key": "fill1"})
        self.assertEqual(fill.body["state"], "active")
        # 重复回调返回同一席位。
        replay = self.post("/seats/s1/fill", {"person_user_id": "alice"},
                           headers={"x-actor-id": "sec", "Idempotency-Key": "fill1"})
        self.assertEqual(replay.body["grant_id"], "g1")

        self.post("/assignments", {
            "assignment_id": "a1", "item_key": "p1", "item_domain": "screen",
            "role_key": "investor_representative", "principal_party_id": "fund",
            "subject_party_id": "vendor", "material_id": "mat", "material_version": "1",
        }, 201)
        dispatch = self.post("/assignments/dispatch", {})
        self.assertEqual(dispatch.body["dispatched"][0]["assignee_user_id"], "alice")

        # 利益冲突出现，未决事项重新分派。
        conflict = self.post("/conflicts", {
            "person_user_id": "alice", "subject_party_id": "vendor",
            "role_key": "investor_representative",
            "scope": {"domain": "screen", "item_keys": ["p1"]},
            "relation": "受雇于服务商",
        }, 201)
        self.assertEqual(conflict.body["reopened_items"], ["p1"])

        # 阿琳执行动作被资格闸门拒绝。
        denied = self.post("/attestations", {
            "action": "screening.vote", "item_domain": "screen", "item_key": "p1",
            "principal_party_id": "fund", "subject_party_id": "vendor",
            "material_id": "mat", "material_version": "1",
        }, 403, headers={"x-actor-id": "alice"})
        self.assertEqual(denied.body["error"]["code"], "forbidden")

    def test_explain_requires_privileged_role(self) -> None:
        self._grant_and_accept()
        payload = {
            "person_user_id": "alice", "action": "screening.vote",
            "item_domain": "screen", "item_key": "p1",
            "principal_party_id": "fund", "subject_party_id": "vendor",
            "at": self.from_,
        }
        denied = self.post("/explain", payload, 403, headers={"x-actor-id": "alice"})
        self.assertEqual(denied.body["error"]["code"], "forbidden")
        allowed = self.post("/explain", payload, 200, headers={"x-actor-id": "aud"})
        self.assertFalse(allowed.body["eligible"])  # 尚无席位

    def test_unknown_route(self) -> None:
        response = self.request("GET", "/nope")
        self.assertEqual(response.status, 404)

    def test_audit_chain_endpoint(self) -> None:
        self._grant_and_accept()
        response = self.get("/audit/chain", headers={"x-actor-id": "aud"})
        self.assertTrue(response.body["valid"])
        self.assertGreater(response.body["events"], 0)


if __name__ == "__main__":
    unittest.main()
