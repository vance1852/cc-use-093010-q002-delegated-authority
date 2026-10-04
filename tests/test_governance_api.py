from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from cooperation_assurance.api import JsonApplication
from cooperation_assurance.clock import FrozenClock
from cooperation_assurance.service import AssuranceService


class GovernanceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.app = JsonApplication(AssuranceService(self.connection, clock))
        s = self.app.service
        s.create_user("sec", "秘书处", "operator")
        s.create_user("stat", "统计负责人", "statistician")
        s.create_user("appr", "准入审批人", "approver")
        s.register_program("sec", "p1", "项目", "牵头方")
        s.register_evidence_revision("sec", "r1", "p1", "1.0", "a" * 64)

    def tearDown(self) -> None:
        self.connection.close()

    def request(self, method: str, path: str, payload: dict | None = None, actor: str = "sec"):
        body = json.dumps(payload or {}, ensure_ascii=False).encode()
        headers = {"X-Actor-Id": actor}
        return self.app.handle(method, path, headers, body)

    def test_grant_seat_decision_and_explain_over_http(self) -> None:
        grant_payload = {
            "grant_id": "g1", "principal_id": "投资方A", "representative_id": "stat",
            "action": "exclusion.review", "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z", "idempotency_key": "http-1",
            "program_id": "p1", "evidence_revision_id": "r1",
        }
        response = self.request("POST", "/grants", grant_payload)
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["status"], "proposed")

        accepted = self.request("POST", "/grants/g1/accept", {"idempotency_key": "http-2"}, actor="stat")
        self.assertEqual(accepted.status, 200)
        self.assertEqual(accepted.body["status"], "accepted")

        fetched = self.request("GET", "/grants/g1")
        self.assertEqual(fetched.status, 200)
        self.assertEqual(len(fetched.body["events"]), 2)

        # 重复回调返回同一结果，不产生第二条事实。
        replay = self.request("POST", "/grants/g1/accept", {"idempotency_key": "http-2"}, actor="stat")
        self.assertEqual(replay.status, 200)
        self.assertEqual(len(replay.body["events"]), 2)

        seats = self.request("GET", "/batches/unknown/seats")
        self.assertEqual(seats.status, 200)
        self.assertEqual(seats.body, {"seats": []})

        explain = self.request("GET", "/explain?user_id=stat&action=decision.write")
        self.assertEqual(explain.status, 200)
        self.assertFalse(explain.body["may_act"])
        explain_ok = self.request(
            "GET", "/explain?user_id=stat&action=exclusion.review&program_id=p1&evidence_revision_id=r1"
        )
        self.assertTrue(explain_ok.body["may_act"])

    def test_interests_and_seats_routes(self) -> None:
        self.request("POST", "/grants", {
            "grant_id": "g2", "principal_id": "投资方A", "representative_id": "appr",
            "action": "decision.write", "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z", "idempotency_key": "http-3",
            "program_id": "p1", "evidence_revision_id": "r1",
        })
        self.request("POST", "/grants/g2/accept", {"idempotency_key": "http-4"}, actor="appr")
        declared = self.request("POST", "/interests", {
            "user_id": "appr", "related_party_id": "投资方A",
            "relation_type": "持股", "idempotency_key": "http-5",
        }, actor="appr")
        self.assertEqual(declared.status, 201)
        # 利益关系存在时，授权被暂停。
        grant = self.request("GET", "/grants/g2")
        self.assertEqual(grant.body["status"], "suspended")


if __name__ == "__main__":
    unittest.main()
