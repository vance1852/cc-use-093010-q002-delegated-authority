"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .jsonio import load_json
from .service import AssuranceService
from .storage import connect, inspect_schema


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    protocol = load_json(fixtures / "demo_protocol.json")
    observation_rows = [
        json.loads(line)
        for line in (fixtures / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="cooperation-assurance-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = AssuranceService(connection)
            service.create_user("operator-1", "测试操作员", "operator")
            service.create_user("stat-1", "统计负责人", "statistician")
            service.create_user("stat-2", "回避替补统计", "statistician")
            service.create_user("approver-1", "分析准入审批人", "approver")
            service.create_user("auditor-1", "审计人员", "auditor")
            governance = service.governance
            service.register_program("operator-1", "program-a", "跨境数据服务合作项目", "示例牵头机构")
            service.register_evidence_revision("operator-1", "evidence_revision-a1", "program-a", "1.0.0", "a" * 64)
            service.publish_protocol("stat-1", protocol)
            service.create_batch("operator-1", "batch-demo", protocol["protocol_id"], protocol["version"], "evidence_revision-a1")
            service.start_batch("operator-1", "batch-demo", 1)
            window = ("2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z")
            # 投资方委托 stat-1 代表其参与项目筛选（材料版本绑定到当前证据版本）。
            governance.propose_grant(
                "operator-1", "grant-stat-review", "投资方A", "stat-1", "exclusion.review",
                window[0], window[1], "acc-grant-1",
                program_id="program-a", evidence_revision_id="evidence_revision-a1",
            )
            governance.accept_grant("stat-1", "grant-stat-review", "acc-accept-1")
            # 候选服务商委托 approver-1 提交并就其履约材料接受准入决定。
            governance.propose_grant(
                "operator-1", "grant-approver", "候选服务商B", "approver-1", "decision.write",
                window[0], window[1], "acc-grant-2",
                program_id="program-a", evidence_revision_id="evidence_revision-a1",
            )
            governance.accept_grant("approver-1", "grant-approver", "acc-accept-2")
            imported = service.import_observations(
                "operator-1", "batch-demo", "demo-import-1", observation_rows
            )
            # 评审前按当时有效授权与利益关系计算资格并分派席位。
            eligibility = governance.eligible_representatives("batch-demo", "exclusion_review")
            if not any(item["user_id"] == "stat-1" for item in eligibility["eligible"]):
                raise RuntimeError("stat-1 应当具备排除复核资格")
            governance.assign_review(
                "operator-1", "batch-demo", "exclusion_review", "stat-1", "投资方A"
            )
            service.seal_batch("stat-1", "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], "stat-1")
            governance.assign_review(
                "operator-1", "batch-demo", "admission_decision", "approver-1", "候选服务商B"
            )
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            service.decide(
                "approver-1", "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            # 审计时点解释：决定作出时 approver-1 为何能代表候选服务商B。
            explanation = governance.explain(
                "approver-1", "decision.write",
                program_id="program-a", evidence_revision_id="evidence_revision-a1",
            )
            if not explanation["may_act"]:
                raise RuntimeError("授权时点解释失败：approver-1 应当有效")
            report = service.report("auditor-1", "batch-demo")
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行校准数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
