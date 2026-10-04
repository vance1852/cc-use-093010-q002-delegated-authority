# 全球数字贸易合作运营平台

本项目是一套可离线运行的 Python 服务端平台，用于管理跨境数字合作中的资源流转、项目证据评估和统计资料质量。平台把运营节点、合作通道、资源申请、项目版本、分析决定、样本观测、权限和审计事件持久化到 SQLite，供秘书处、项目办公室、数据团队和审计人员协作使用。

## 目录

- src/trade_flow/：运营节点、合作通道、资源批次、额度申请、分配和情景分析；
- src/cooperation_assurance/：合作项目、证据版本、评估协议、观测导入、分析任务、准入决定，以及代表授权与回避治理（授权事实流、转委托链、利益冲突、评审席位、时点解释）；
- src/metric_quality/：统计样本批次、指标观测、质量分析、账号权限和审批；
- fixtures/：离线验收使用的评估协议与结构化观测；
- tests/：领域规则、错误边界、事务、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

    PYTHONPATH=src python3 -m unittest discover -s tests -v

## 构建检查

    python3 -m compileall -q src tests

## 离线验收

    PYTHONPATH=src python3 -m trade_flow.acceptance --workspace .
    PYTHONPATH=src python3 -m cooperation_assurance.acceptance --workspace .
    PYTHONPATH=src python3 -m metric_quality.acceptance

三条命令会在临时 SQLite 数据库中完成合作资源流转、项目证据评估和统计资料质量流程，不访问外部网络。

## HTTP 服务

    PYTHONPATH=src python3 -m trade_flow.api --database trade-flow.sqlite3 --host 127.0.0.1 --port 8080
    PYTHONPATH=src python3 -m cooperation_assurance.api --database cooperation-assurance.sqlite3 --host 127.0.0.1 --port 8081
    PYTHONPATH=src python3 -m metric_quality.api --database metric-quality.sqlite3 --host 127.0.0.1 --port 8082

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 代表授权与回避治理

`cooperation_assurance` 在账号角色之上提供授权事实层（`governance.py`）：

- 授权（`POST /grants`）把一次代表关系绑定到**委托主体、代表人、业务动作、项目与材料版本、生效区间、可转委托条件（是否允许、最大链深）**；授权要约须由代表本人在 `POST /grants/{id}/accept|reject` 接受或拒绝，接受时即校验利益冲突；
- `accept / reject / delegate / suspend / resume / withdraw` 全部写入只增事实表 `grant_events`，授权行状态只是事件流的当前投影，任何事实不可覆盖；
- 转授权（`POST /grants/{id}/delegate`）的业务范围、生效区间和链深不得超出母授权；母授权暂停或撤回沿链级联，恢复须自顶向下；
- 利益关系（`POST /interests`、`POST /interests/{id}/clear`）出现时，只暂停与该相关方对应的授权并关闭其在执评审席位，其它委托关系不受影响；
- 评审席位（`POST /seats`）把"谁代表哪一方评审哪个批次"固定下来；排除复核与准入决定发生时必须持有绑定当前有效授权的在执席位。冲突出现后未决事项由秘书处重新分派给替代人员，替代人员只能凭自己的新授权获席；**已完成的合法决定永久保留**；
- 部分唯一索引（`one_open_grant_per_mandate`、`one_active_seat_per_stage`）与幂等键在数据库层保证：并发委托或重复回调不会产生两份有效席位或两条相同事实；
- 秘书处与审计人员可按任意历史时点解释资格：`GET /explain?user_id=..&action=..&at=..&program_id=..&evidence_revision_id=..`，以及 `GET /batches/{id}/eligibility?stage=..` 与 `GET /batches/{id}/seats`。
