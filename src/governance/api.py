"""代表授权与回避治理的无第三方依赖 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .errors import GovernanceError, ValidationFailed
from .service import GovernanceService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    """把 HTTP 路由映射到治理服务，便于无网络单元测试。"""

    def __init__(self, service: GovernanceService) -> None:
        self.service = service

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    @staticmethod
    def _opt_int(value: Any) -> int | None:
        return None if value is None else int(value)

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        path = urlparse(target).path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        service = self.service
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            actor = lambda: self._actor(normalized_headers)

            if method == "POST" and path == "/bootstrap":
                return Response(201, service.bootstrap_user(
                    payload["user_id"], payload["display_name"],
                    payload.get("role", "secretariat")))
            if method == "POST" and path == "/users":
                return Response(201, service.create_user(
                    actor(), payload["user_id"], payload["display_name"], payload["role"]))
            if method == "POST" and path == "/parties":
                return Response(201, service.create_party(
                    actor(), payload["party_id"], payload["name"], payload["kind"]))
            if method == "POST" and path == "/materials":
                return Response(201, service.register_material(
                    actor(), payload["material_id"], payload["version"],
                    payload["title"], payload["content_sha256"]))

            if method == "POST" and path == "/grants":
                return Response(201, service.offer_grant(
                    actor(), payload["grant_id"], payload["principal_party_id"],
                    payload["grantee_user_id"], payload["role_key"], payload["scope"],
                    payload["materials"], payload["valid_from"],
                    payload.get("valid_until"), bool(payload.get("delegation_allowed", False)),
                    int(payload.get("delegation_depth", 0)), payload.get("reason", "")))
            if method == "POST" and len(parts) == 3 and parts[0] == "grants" and parts[2] == "respond":
                return Response(200, service.respond_grant(
                    actor(), parts[1], bool(payload["accept"]),
                    normalized_headers.get("idempotency-key", "") or payload["idempotency_key"],
                    payload.get("reason", "")))
            if method == "POST" and len(parts) == 3 and parts[0] == "grants" and parts[2] == "delegate":
                return Response(201, service.delegate_grant(
                    actor(), payload["new_grant_id"], parts[1], payload["grantee_user_id"],
                    payload["scope"], payload["materials"], payload["valid_from"],
                    payload.get("valid_until"),
                    normalized_headers.get("idempotency-key", "") or payload["idempotency_key"],
                    payload.get("reason", "")))
            if method == "POST" and len(parts) == 3 and parts[0] == "grants" and parts[2] in {
                "suspend", "resume", "revoke"
            }:
                action = parts[2]
                method_map = {
                    "suspend": service.suspend_grant,
                    "resume": service.resume_grant,
                    "revoke": service.revoke_grant,
                }
                return Response(200, method_map[action](actor(), parts[1], payload.get("reason", "")))
            if method == "GET" and len(parts) == 2 and parts[0] == "grants":
                return Response(200, service.grant_view(parts[1]))
            if method == "GET" and len(parts) == 3 and parts[0] == "grants" and parts[2] == "history":
                return Response(200, service.grant_history(actor(), parts[1]))

            if method == "POST" and path == "/conflicts":
                return Response(201, service.declare_conflict(
                    actor(), payload["person_user_id"], payload["subject_party_id"],
                    payload["role_key"], payload["scope"], payload["relation"],
                    payload.get("material")))
            if method == "POST" and len(parts) == 3 and parts[0] == "conflicts" and parts[2] == "clear":
                return Response(200, service.clear_conflict(
                    actor(), int(parts[1]), payload.get("reason", "")))

            if method == "POST" and path == "/seats":
                return Response(201, service.open_seat(
                    actor(), payload["seat_id"], payload["scope"],
                    payload["role_key"], payload["principal_party_id"]))
            if method == "POST" and len(parts) == 3 and parts[0] == "seats" and parts[2] == "fill":
                key = normalized_headers.get("idempotency-key", "") or payload["idempotency_key"]
                return Response(200, service.fill_seat(
                    actor(), parts[1], payload["person_user_id"], key))
            if method == "POST" and len(parts) == 3 and parts[0] == "seats" and parts[2] in {
                "suspend", "resume", "vacate"
            }:
                action = parts[2]
                method_map = {
                    "suspend": service.suspend_seat,
                    "resume": service.resume_seat,
                    "vacate": service.vacate_seat,
                }
                return Response(200, method_map[action](actor(), parts[1], payload.get("reason", "")))

            if method == "POST" and path == "/assignments":
                return Response(201, service.open_assignment(
                    actor(), payload["assignment_id"], payload["item_key"], payload["item_domain"],
                    payload["role_key"], payload["principal_party_id"],
                    payload.get("subject_party_id"), payload.get("material_id"),
                    payload.get("material_version")))
            if method == "POST" and path == "/assignments/dispatch":
                return Response(200, service.dispatch(actor(), int(payload.get("limit", 50))))
            if method == "GET" and len(parts) == 2 and parts[0] == "assignments":
                return Response(200, service.assignment_view(parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "assignments" and parts[2] == "resolve":
                return Response(200, service.resolve_assignment(
                    actor(), parts[1], payload.get("note", "")))

            if method == "POST" and path == "/eligibility":
                return Response(200, service.eligibility(
                    actor(), payload["person_user_id"], payload["action"],
                    payload["item_domain"], payload["item_key"],
                    payload["principal_party_id"], payload["subject_party_id"],
                    payload.get("material_id"), payload.get("material_version"),
                    payload.get("at")))
            if method == "POST" and path == "/explain":
                return Response(200, service.explain_at(
                    actor(), payload["person_user_id"], payload["action"],
                    payload["item_domain"], payload["item_key"],
                    payload["principal_party_id"], payload["subject_party_id"],
                    payload["at"], payload.get("material_id"), payload.get("material_version")))
            if method == "POST" and path == "/attestations":
                return Response(201, service.attest_action(
                    actor(), payload["action"], payload["item_domain"], payload["item_key"],
                    payload["principal_party_id"], payload["subject_party_id"],
                    payload.get("material_id"), payload.get("material_version"),
                    payload.get("assignment_id")))

            if method == "GET" and len(parts) == 3 and parts[0] == "people" and parts[2] == "timeline":
                return Response(200, service.person_timeline(actor(), parts[1]))
            if method == "GET" and path == "/audit/chain":
                return Response(200, service.audit_chain(actor()))

            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except GovernanceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Governance/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动代表授权与回避治理 HTTP 服务")
    parser.add_argument("--database", type=Path, default=Path("governance.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    application = JsonApplication(GovernanceService(connection))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(application))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
