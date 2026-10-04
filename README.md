# 全球数字贸易合作运营平台

本项目是一套可离线运行的 Python 服务端平台，用于管理跨境数字合作中的资源流转、项目证据评估和统计资料质量。平台把运营节点、合作通道、资源申请、项目版本、分析决定、样本观测、权限和审计事件持久化到 SQLite，供秘书处、项目办公室、数据团队和审计人员协作使用。

## 目录

- src/trade_flow/：运营节点、合作通道、资源批次、额度申请、分配和情景分析；
- src/cooperation_assurance/：合作项目、证据版本、评估协议、观测导入、分析任务与准入决定；
- src/metric_quality/：统计样本批次、指标观测、质量分析、账号权限和审批；
- src/governance/：代表授权（委托主体、业务范围、材料版本、生效区间、转委托）、利益冲突回避、唯一席位、事项分派与历史资格解释；
- fixtures/：离线验收使用的评估协议与结构化观测；
- tests/：领域规则、错误边界、事务、权限、并发席位、HTTP API 和命令行验收测试。

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
    PYTHONPATH=src python3 -m governance.acceptance --workspace .

前三条命令会在临时 SQLite 数据库中完成合作资源流转、项目证据评估和统计资料质量流程，不访问外部网络。
治理验收额外演练双重身份代表的授权、利益冲突事项级回避、未决事项重分、办结决定保留、
替代人员窄授权接手、任意历史时点资格解释，以及并发委托下唯一席位的保证。

## HTTP 服务

    PYTHONPATH=src python3 -m trade_flow.api --database trade-flow.sqlite3 --host 127.0.0.1 --port 8080
    PYTHONPATH=src python3 -m cooperation_assurance.api --database cooperation-assurance.sqlite3 --host 127.0.0.1 --port 8081
    PYTHONPATH=src python3 -m metric_quality.api --database metric-quality.sqlite3 --host 127.0.0.1 --port 8082
    PYTHONPATH=src python3 -m governance.api --database governance.sqlite3 --host 127.0.0.1 --port 8083

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 代表授权与回避治理模型

- 授权 `grants` 绑定委托主体、业务范围 `scope`、材料版本集合、生效区间
  （valid_from/valid_until）与转委托条件（是否允许、链深度）；接受、拒绝、
  转授权、暂停、恢复、撤回只追加写入 `grant_events`，当前状态列是事实的派生缓存。
- 转委托（`POST /grants/{id}/delegate`）由原持有人发起，子授权的范围、期限、
  材料版本和链深度都不能超出父授权。
- 利益关系 `conflicts` 按"人员 × 评审对象 × 角色 × 事项集合"登记，追加
  `conflict_events`；登记时只把受污染的未决事项收回重分（席位范围相应收窄，
  清空才整个退出），已办结（resolved）的合法决定保留。
- 席位 `seats` 用部分唯一索引保证同一委托主体/角色/业务范围至多一个占用人；
  占用条件更新带 rowcount 守卫，因此并发委托和重复回调（Idempotency-Key）
  不会产生两份有效席位。替代人员凭自己的新授权占位，访问宽度不继承原持有人。
- 每次发言/审批/查阅经 `POST /attestations` 资格闸门落一条执行凭据，记录当时
  命中的授权、席位与资格理由；秘书处和审计可用 `POST /explain`（带 `at`）
  按任意历史时点解释"某人为何能代表某方对某对象执行某项操作"。

