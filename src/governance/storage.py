"""代表授权与回避治理的 SQLite 模式与事务辅助。

事实表（grant_events / conflict_events / seat_events / gov_audit_events）只允许
INSERT，并通过触发器拒绝 UPDATE 与 DELETE，保证接受、拒绝、转授权、暂停、撤回等
事实不可覆盖；当前状态列只是事实的派生缓存。
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS gov_schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parties (
    party_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('investor', 'service_provider', 'secretariat', 'observer')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gov_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('secretariat', 'auditor', 'delegate')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS materials (
    material_id TEXT NOT NULL,
    version TEXT NOT NULL,
    title TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    registered_by TEXT NOT NULL REFERENCES gov_users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (material_id, version)
);

CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY,
    parent_grant_id TEXT REFERENCES grants(grant_id),
    principal_party_id TEXT NOT NULL REFERENCES parties(party_id),
    grantee_user_id TEXT NOT NULL REFERENCES gov_users(user_id),
    role_key TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    materials_json TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    delegation_allowed INTEGER NOT NULL DEFAULT 0 CHECK (delegation_allowed IN (0, 1)),
    remaining_depth INTEGER NOT NULL DEFAULT 0 CHECK (remaining_depth >= 0),
    state TEXT NOT NULL CHECK (state IN ('offered', 'accepted', 'declined', 'suspended', 'revoked')),
    offered_by TEXT NOT NULL REFERENCES gov_users(user_id),
    offered_at TEXT NOT NULL,
    CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants(grantee_user_id);
CREATE INDEX IF NOT EXISTS idx_grants_principal ON grants(principal_party_id);

CREATE TABLE IF NOT EXISTS grant_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    action TEXT NOT NULL CHECK (action IN ('offered', 'accepted', 'declined', 'suspended', 'resumed', 'revoked')),
    actor_id TEXT NOT NULL REFERENCES gov_users(user_id),
    reason TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT,
    effective_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_event_one_accept
ON grant_events(grant_id) WHERE action = 'accepted';
CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_event_one_decline
ON grant_events(grant_id) WHERE action = 'declined';
CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_event_one_revoke
ON grant_events(grant_id) WHERE action = 'revoked';
CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_event_idem
ON grant_events(grant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_grant_events_no_update
BEFORE UPDATE ON grant_events
BEGIN
    SELECT RAISE(ABORT, 'grant_events 是只追加事实表，禁止修改');
END;
CREATE TRIGGER IF NOT EXISTS trg_grant_events_no_delete
BEFORE DELETE ON grant_events
BEGIN
    SELECT RAISE(ABORT, 'grant_events 是只追加事实表，禁止删除');
END;

CREATE TABLE IF NOT EXISTS conflicts (
    conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_user_id TEXT NOT NULL REFERENCES gov_users(user_id),
    counterparty_party_id TEXT NOT NULL REFERENCES parties(party_id),
    role_key TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    relation TEXT NOT NULL,
    material_id TEXT,
    material_version TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'cleared')),
    declared_by TEXT NOT NULL REFERENCES gov_users(user_id),
    declared_at TEXT NOT NULL,
    cleared_by TEXT REFERENCES gov_users(user_id),
    cleared_at TEXT,
    clear_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_conflicts_person ON conflicts(person_user_id, status);

CREATE TABLE IF NOT EXISTS conflict_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    conflict_id INTEGER NOT NULL REFERENCES conflicts(conflict_id),
    action TEXT NOT NULL CHECK (action IN ('declared', 'cleared')),
    actor_id TEXT NOT NULL REFERENCES gov_users(user_id),
    effective_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_conflict_events_no_update
BEFORE UPDATE ON conflict_events
BEGIN
    SELECT RAISE(ABORT, 'conflict_events 是只追加事实表，禁止修改');
END;
CREATE TRIGGER IF NOT EXISTS trg_conflict_events_no_delete
BEFORE DELETE ON conflict_events
BEGIN
    SELECT RAISE(ABORT, 'conflict_events 是只追加事实表，禁止删除');
END;

CREATE TABLE IF NOT EXISTS seats (
    seat_id TEXT PRIMARY KEY,
    scope_json TEXT NOT NULL,
    role_key TEXT NOT NULL,
    principal_party_id TEXT NOT NULL REFERENCES parties(party_id),
    state TEXT NOT NULL CHECK (state IN ('open', 'active', 'suspended', 'vacated')),
    grant_id TEXT REFERENCES grants(grant_id),
    holder_user_id TEXT REFERENCES gov_users(user_id),
    opened_by TEXT NOT NULL REFERENCES gov_users(user_id),
    opened_at TEXT NOT NULL,
    activated_at TEXT,
    vacated_at TEXT
);

-- 同一委托主体、同一角色、同一业务范围至多一个占有的席位（暂停仍占有，防止并发双占）。
CREATE UNIQUE INDEX IF NOT EXISTS idx_seat_one_occupied
ON seats(scope_json, role_key, principal_party_id)
WHERE state IN ('active', 'suspended');

CREATE INDEX IF NOT EXISTS idx_seats_holder ON seats(holder_user_id);

CREATE TABLE IF NOT EXISTS seat_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    seat_id TEXT NOT NULL REFERENCES seats(seat_id),
    action TEXT NOT NULL CHECK (action IN ('opened', 'filled', 'suspended', 'resumed', 'vacated', 'recused', 'restored')),
    actor_id TEXT NOT NULL REFERENCES gov_users(user_id),
    grant_id TEXT,
    reason TEXT NOT NULL DEFAULT '',
    effective_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_seat_events_no_update
BEFORE UPDATE ON seat_events
BEGIN
    SELECT RAISE(ABORT, 'seat_events 是只追加事实表，禁止修改');
END;
CREATE TRIGGER IF NOT EXISTS trg_seat_events_no_delete
BEFORE DELETE ON seat_events
BEGIN
    SELECT RAISE(ABORT, 'seat_events 是只追加事实表，禁止删除');
END;

CREATE TABLE IF NOT EXISTS assignments (
    assignment_id TEXT PRIMARY KEY,
    item_key TEXT NOT NULL,
    item_scope_json TEXT NOT NULL,
    role_key TEXT NOT NULL,
    material_id TEXT,
    material_version TEXT,
    principal_party_id TEXT NOT NULL REFERENCES parties(party_id),
    subject_party_id TEXT REFERENCES parties(party_id),
    seat_id TEXT REFERENCES seats(seat_id),
    grant_id TEXT REFERENCES grants(grant_id),
    assignee_user_id TEXT REFERENCES gov_users(user_id),
    state TEXT NOT NULL CHECK (state IN ('unassigned', 'active', 'resolved', 'reassigned')),
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    assigned_at TEXT,
    resolved_at TEXT,
    resolved_by TEXT REFERENCES gov_users(user_id)
);

-- 同一事项至多一条在办（未分派或已分派）记录；重复回调不会产生两条待办。
-- 回避后原记录转为 reassigned，即可插入新的 unassigned 记录。
CREATE UNIQUE INDEX IF NOT EXISTS idx_assignment_one_open
ON assignments(item_key) WHERE state IN ('unassigned', 'active');
CREATE INDEX IF NOT EXISTS idx_assignment_assignee ON assignments(assignee_user_id, state);

CREATE TABLE IF NOT EXISTS action_attestations (
    attestation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_user_id TEXT NOT NULL REFERENCES gov_users(user_id),
    action TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    material_id TEXT,
    material_version TEXT,
    counterparty_party_id TEXT,
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    seat_id TEXT REFERENCES seats(seat_id),
    assignment_id TEXT REFERENCES assignments(assignment_id),
    basis_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attestations_person ON action_attestations(person_user_id, attestation_id);

CREATE TABLE IF NOT EXISTS gov_idempotency (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, idempotency_key)
);

CREATE TABLE IF NOT EXISTS gov_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gov_audit_entity
ON gov_audit_events(entity_type, entity_id, event_id);

CREATE TRIGGER IF NOT EXISTS trg_gov_audit_no_update
BEFORE UPDATE ON gov_audit_events
BEGIN
    SELECT RAISE(ABORT, 'gov_audit_events 是只追加事实表，禁止修改');
END;
CREATE TRIGGER IF NOT EXISTS trg_gov_audit_no_delete
BEFORE DELETE ON gov_audit_events
BEGIN
    SELECT RAISE(ABORT, 'gov_audit_events 是只追加事实表，禁止删除');
END;
"""

REQUIRED_TABLES = frozenset({
    "gov_schema_meta", "parties", "gov_users", "materials", "grants", "grant_events",
    "conflicts", "conflict_events", "seats", "seat_events", "assignments",
    "action_attestations", "gov_idempotency", "gov_audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化治理表，重复执行不改变已有事实。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO gov_schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM gov_schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
