"""统计分析准入服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 3

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_catalog (
    protocol_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    title TEXT NOT NULL,
    task_family TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (protocol_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS cooperation_programs (
    program_id TEXT PRIMARY KEY,
    program_name TEXT NOT NULL,
    lead_organization TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_revisions (
    evidence_revision_id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES cooperation_programs(program_id),
    version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (program_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    evidence_revision_id TEXT NOT NULL REFERENCES evidence_revisions(evidence_revision_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    sealed_at TEXT,
    FOREIGN KEY (protocol_id, protocol_version) REFERENCES protocol_catalog(protocol_id, version)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    source_batch TEXT NOT NULL,
    source_row TEXT NOT NULL,
    program_id TEXT NOT NULL REFERENCES cooperation_programs(program_id),
    stratum_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    imported_by TEXT NOT NULL REFERENCES users(user_id),
    imported_at TEXT NOT NULL,
    UNIQUE (batch_id, source_batch, source_row)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES observations(observation_id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT,
    reviewed_with_grant_id TEXT REFERENCES authorization_grants(grant_id),
    reviewed_principal_id TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_observation
ON exclusion_requests(observation_id)
WHERE status IN ('pending', 'approved');

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision)
);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    protocol_sha256 TEXT NOT NULL CHECK (length(protocol_sha256) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision, input_sha256)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    decided_with_grant_id TEXT REFERENCES authorization_grants(grant_id),
    decided_principal_id TEXT,
    UNIQUE (batch_id, analysis_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 代表授权：绑定委托主体、代表人、业务动作、材料版本、生效区间与可转委托条件。
-- 授权本身是一行不可变的委托关系；其生命周期状态全部记录在 grant_events 中，
-- 任何接受、拒绝、转授权、暂停、恢复、撤回都只追加事实，从不覆盖。
CREATE TABLE IF NOT EXISTS authorization_grants (
    grant_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    representative_id TEXT NOT NULL REFERENCES users(user_id),
    action TEXT NOT NULL,
    program_id TEXT REFERENCES cooperation_programs(program_id),
    evidence_revision_id TEXT REFERENCES evidence_revisions(evidence_revision_id),
    scope_json TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    delegable INTEGER NOT NULL DEFAULT 0 CHECK (delegable IN (0, 1)),
    max_chain_depth INTEGER NOT NULL DEFAULT 0 CHECK (max_chain_depth >= 0),
    parent_grant_id TEXT REFERENCES authorization_grants(grant_id),
    chain_depth INTEGER NOT NULL DEFAULT 0 CHECK (chain_depth >= 0),
    status TEXT NOT NULL
        CHECK (status IN ('proposed', 'accepted', 'rejected', 'suspended', 'withdrawn')),
    idempotency_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (valid_until > valid_from),
    CHECK (parent_grant_id IS NOT NULL OR chain_depth = 0)
);

-- 同一委托主体对同一代表人、同一业务动作、同一材料版本只允许存在一条未终结的授权；
-- 并发或重复回调时第二个事务命中此索引，绝不会产生两份有效席位。
CREATE UNIQUE INDEX IF NOT EXISTS one_open_grant_per_mandate
ON authorization_grants(principal_id, representative_id, action,
                        COALESCE(program_id, ''), COALESCE(evidence_revision_id, ''))
WHERE status IN ('proposed', 'accepted', 'suspended');

CREATE UNIQUE INDEX IF NOT EXISTS grant_idempotency_unique
ON authorization_grants(idempotency_key);

-- 授权生命周期事实流，只增不改不删。
CREATE TABLE IF NOT EXISTS grant_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id TEXT NOT NULL REFERENCES authorization_grants(grant_id),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'proposed', 'accepted', 'rejected', 'delegated', 'suspended', 'resumed', 'withdrawn'
    )),
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 重复回调携带同一幂等键时命中此索引，不会写入第二条事实。
CREATE UNIQUE INDEX IF NOT EXISTS grant_event_idempotency_unique
ON grant_events(idempotency_key);

CREATE INDEX IF NOT EXISTS grant_events_by_grant
ON grant_events(grant_id, event_id);

-- 利益关系申报与解除，同样是只增事实；active 由事件序列决定，
-- 但保留部分唯一索引，确保同一人与同一相关方不会并存两条生效申报。
CREATE TABLE IF NOT EXISTS interest_disclosures (
    disclosure_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    related_party_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    declared_at TEXT NOT NULL,
    cleared_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_open_disclosure
ON interest_disclosures(user_id, related_party_id)
WHERE active = 1;

CREATE UNIQUE INDEX IF NOT EXISTS disclosure_idempotency_unique
ON interest_disclosures(idempotency_key);

-- 评审/审批席位：每个批次每个阶段至多一份有效席位，席位必须绑定当时有效的授权。
-- 授权失效或利益冲突出现时席位关闭（state='revoked'），未决事项据此重新分派；
-- 已完成（'completed'）的席位永久保留，合法决定不被追溯。
CREATE TABLE IF NOT EXISTS review_assignments (
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    stage TEXT NOT NULL CHECK (stage IN ('exclusion_review', 'admission_decision')),
    seat_seq INTEGER NOT NULL CHECK (seat_seq >= 1),
    assignee_id TEXT NOT NULL REFERENCES users(user_id),
    grant_id TEXT NOT NULL REFERENCES authorization_grants(grant_id),
    principal_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'completed', 'revoked')),
    revoke_reason TEXT NOT NULL DEFAULT '',
    predecessor_assignment_id INTEGER REFERENCES review_assignments(assignment_id),
    assigned_at TEXT NOT NULL,
    completed_at TEXT,
    revoked_at TEXT,
    UNIQUE (batch_id, stage, seat_seq)
);

-- 数据库层保证同一阶段只有一份在执席位，并发分派也不会产生两份有效席位。
CREATE UNIQUE INDEX IF NOT EXISTS one_active_seat_per_stage
ON review_assignments(batch_id, stage)
WHERE state = 'active';
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "protocol_catalog", "users", "cooperation_programs", "evidence_revisions", "batches",
    "observations", "idempotency_keys", "exclusion_requests", "analysis_jobs",
    "analyses", "decisions", "audit_events",
    "authorization_grants", "grant_events", "interest_disclosures", "review_assignments",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
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
    """初始化基础资料表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
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
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
