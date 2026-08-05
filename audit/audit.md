# 你是一名资深 Rust 安全基础设施工程师、金融交易风控架构师、分布式系统工程师和开源项目维护者。

请对以下仓库执行完整的代码审计、校验缺口识别和分阶段修复：

Repository:https://github.com/chuhemiao/agentic-transaction-firewall

项目正式名称：
Agentic Transaction Firewall

项目定位：
面向 AI Agent 金融行为的开源 Transaction Intent、Identity、Policy、Risk、Simulation、Approval、Execution Control、Reconciliation 和 Audit 控制层。

项目边界：

1. 不托管用户资产。
2. 不保存生产私钥。
3. 不替代钱包、Safe、Fireblocks、Privy、交易所或支付协议。
4. 不使用 LLM 作为最终 Permit、Deny 或 Review 决策者。
5. 不生成投资策略。
6. 不负责寻找 Alpha。
7. Shadow Mode 优先于 Enforce Mode。
8. 所有不确定错误必须 Fail Closed。
9. 所有金融金额禁止使用浮点数。
10. 所有最终执行必须绑定原始 Intent 和批准结果。

你的任务不是重新设计一个新项目，而是在现有 PRD、Architecture、Threat Model、代码、测试和 Roadmap 基础上，识别缺失的校验机制，并逐步将当前 Skeleton/Shadow Mode 项目推进为可验证、可重放、可审计的开源参考实现。

第一阶段：读取仓库和建立真实基线

开始修改前必须完整读取：

1. AGENTS.md。
2. README.md。
3. Cargo.toml。
4. docs/PRD.md。
5. docs/architecture.md。
6. docs/threat-model.md。
7. docs/intent-spec.md，如果存在。
8. docs/policy-model.md，如果存在。
9. docs/audit-model.md，如果存在。
10. schemas/ 下所有 Schema。
11. crates/ 下所有已加入 Workspace 的 crate。
12. services/gateway。
13. cli/atf-cli。
14. conformance/。
15. fuzz/。
16. migrations/。
17. deploy/。
18. .github/workflows/。
19. 最近提交记录。
20. 当前 Issues 和 Pull Requests。

运行：

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo deny check

不得仅根据 README 判断完成度。必须通过实际代码、测试、Workspace Membership、路由和运行路径验证。

将每个模块标记为：

IMPLEMENTED_AND_WIRED
IMPLEMENTED_BUT_UNWIRED
PARTIALLY_IMPLEMENTED
SCAFFOLD_ONLY
DOCUMENTED_ONLY
MISSING
IMPLEMENTATION_DOCUMENTATION_DRIFT

第二阶段：生成校验缺口矩阵

按照以下维度生成 Gap Matrix：

1. Intent Schema Validation。
2. Cross-field Semantic Validation。
3. Agent Identity Verification。
4. Authentication and Authorization。
5. Idempotency and Replay Protection。
6. Policy Bundle Validation。
7. Financial Risk Validation。
8. Context Provenance and Freshness。
9. Deterministic Replay。
10. Budget Concurrency。
11. Simulation。
12. Decision Binding。
13. Approval。
14. Execution Authorization。
15. Adapter Validation。
16. Settlement and Reconciliation。
17. Audit Integrity。
18. Persistence。
19. API Security。
20. Observability。
21. CI and Supply-chain Security。
22. Documentation Consistency。
23. Production Readiness。

每个缺口必须包含：

gap_id
module
current_state
evidence
security_impact
financial_impact
severity
recommended_change
required_tests
dependencies
target_release
acceptance_criteria

Severity 使用：

CRITICAL
HIGH
MEDIUM
LOW

第三阶段：重点检查 Transaction Intent

检查当前 Transaction Intent 是否存在以下问题：

1. amount 是否允许负数或零值。
2. max_fee 是否允许负数。
3. leverage 是否允许负数或零值。
4. slippage_bps 是否有 0—10000 范围约束。
5. created_at 是否可能晚于 expires_at。
6. Intent 有效时间是否存在最大限制。
7. intent_id 是否验证为合法 ULID。
8. idempotency_key 是否有长度和字符约束。
9. organization_id、agent_id、mandate_id 是否允许空白字符。
10. spec_version 是否有受支持版本列表。
11. asset 和 network 是否采用可验证的标准标识。
12. Transfer 是否必须包含 destination。
13. Contract Call 是否必须包含 contract 和 calldata_hash。
14. Token Approval 是否必须包含 spender 和 allowance。
15. Exchange Order 是否必须包含 symbol、side、order_type、quantity。
16. Prediction Market Order 是否必须包含 market、outcome、side 和 price。
17. Withdrawal 是否必须进行更高风险处理。
18. amount 与 max_fee 是否使用相同计价资产。
19. fee_asset 与 transaction asset 不同时是否有报价转换。
20. metadata 和 context 中是否允许未受限制的数据影响最终决策。
21. Schema 中 additionalProperties 是否导致未验证字段进入 Canonical Hash 或被静默忽略。
22. 不同 Action Category 是否需要独立 Profile Schema。

在保持通用 Intent Envelope 的前提下，评估是否应该建立：

ATF Payment Intent Profile
ATF EVM Transaction Profile
ATF Exchange Order Profile
ATF Treasury Intent Profile
ATF Prediction Market Intent Profile
ATF Agent Commerce Intent Profile

所有跨字段校验不得只依靠 JSON Schema。建立 Rust Semantic Validator，并返回稳定的机器可读 Error Code。

第四阶段：完善 Identity Validation

检查并实现：

1. 将 atf-identity 接入 Gateway。
2. 身份校验必须在 Policy 和 Risk 之前执行。
3. Agent 身份必须绑定 organization_id。
4. 请求必须包含明确的签名 Header 或 Signed Envelope。
5. 签名内容不得只使用无上下文 Hash 字符串。
6. 增加 Domain Separation。
7. 增加 audience。
8. 增加 environment。
9. 增加 nonce。
10. 增加 issued_at 和 expires_at。
11. 防止跨组织重放。
12. 防止跨环境重放。
13. 防止跨协议重放。
14. 支持公钥激活、失效和撤销时间。
15. 支持密钥轮换重叠窗口。
16. 支持 key_id。
17. Agent 被 PAUSED、REVOKED 或 EXPIRED 后立即拒绝。
18. Identity 验证失败不得继续执行 Policy 和 Risk。
19. 所有身份失败写入 Audit。
20. 私钥与钱包执行签名密钥必须保持隔离。

建议签名 Domain：

ATF_INTENT_V1
organization_id
agent_id
key_id
intent_hash
issued_at
expires_at
nonce
audience
environment

第五阶段：实现真实 Idempotency 和 Replay Protection

当前存在 idempotency_key 字段不等于系统已经幂等。

必须实现：

1. PostgreSQL 唯一约束：
   organization_id + idempotency_key。

2. 同一 Idempotency Key、同一 Intent Hash：
   返回原始 Decision，不重新评估。

3. 同一 Idempotency Key、不同 Intent Hash：
   返回 409 IDEMPOTENCY_CONFLICT。

4. 并发提交：
   只能有一个请求进入评估。

5. Intent Nonce：
   防止身份签名重放。

6. Approval Nonce：
   防止审批重放。

7. Execution Grant Nonce：
   保证只能执行一次。

8. Payment Proof：
   防止结算证明重放。

9. 重启后幂等状态不得丢失。

10. 所有 Replay Detection 必须记录 Audit Event。

第六阶段：修复 Audit 和交易生命周期

定义完整 Intent Lifecycle State Machine：

RECEIVED
IDENTITY_VERIFIED
IDENTITY_REJECTED
POLICY_EVALUATED
RISK_EVALUATED
SIMULATED
DECIDED_PERMIT
DECIDED_REVIEW
DECIDED_DENY
APPROVAL_PENDING
APPROVED
REJECTED
EXECUTION_AUTHORIZED
EXECUTION_SUBMITTED
EXECUTION_CONFIRMED
EXECUTION_FAILED
SETTLEMENT_VERIFIED
RECONCILIATION_FAILED
EXPIRED
CANCELLED

补充 Audit Event：

IntentReceived
IdentityVerified
IdentityRejected
ContextEnriched
PolicyEvaluated
RiskEvaluated
SimulationCompleted
DecisionRecorded
ApprovalRequested
ApprovalApproved
ApprovalRejected
ExecutionGrantIssued
ExecutionSubmitted
ExecutionConfirmed
ExecutionFailed
SettlementVerified
ReconciliationFailed
AgentPaused
PolicyChanged
BudgetReserved
BudgetCommitted
BudgetReleased
KillSwitchEnabled
KillSwitchDisabled

当前重复购买校验不得继续只查询 IntentReceived。

正确语义应明确区分：

REQUESTED
PERMITTED
EXECUTED
SETTLED

重复购买规则应根据业务配置选择 DecisionRecorded(PERMIT)、ExecutionConfirmed 或 SettlementVerified 作为统计依据。

Audit 必须满足：

1. PostgreSQL 持久化。
2. Append-only。
3. 数据库事务。
4. 哈希链。
5. 每个组织独立链或明确的全局链策略。
6. 可按 intent_id、agent_id、organization_id、event_type、时间查询。
7. 定期 Merkle Checkpoint。
8. Checkpoint 可写入独立对象存储。
9. Enforce Mode 下 Audit 写入失败必须 Fail Closed。
10. Shadow Mode 下可以进入有界本地缓冲，但必须告警。
11. 服务重启后不得丢失已接受 Intent 和 Decision。

第七阶段：实现确定性评估和 Replay

任何决定最终结果的代码不得直接读取：

Timestamp::now()
随机数
非版本化外部数据
当前数据库隐式状态
未记录的环境变量

引入 EvaluationContext：

evaluation_id
evaluation_time
policy_bundle_version
policy_bundle_hash
risk_rule_set_version
risk_rule_set_hash
context_snapshot_id
context_snapshot_hash
market_data_snapshot_id
simulation_block_number
simulator_version
adapter_version
external_evidence
environment

Risk Rule 必须读取 EvaluationContext 中的 evaluation_time，不得直接调用系统当前时间。

Replay 必须支持：

1. Original Replay：
   使用原始 Snapshot 和原始版本，得到相同 Decision。

2. Counterfactual Replay：
   使用新 Policy 或 Risk Rule 重新评估，但明确标记为新 Evaluation。

3. Replay 结果不得覆盖原始 Decision。

第八阶段：校验 Context Provenance

将 Context 分为：

AGENT_PROVIDED
ATF_ENRICHED
ORACLE_PROVIDED
ADAPTER_PROVIDED
ADMIN_PROVIDED
SIGNED_EXTERNAL_EVIDENCE

每个可能影响 Decision 的字段必须记录：

value
source
source_id
observed_at
expires_at
evidence_hash
signature
confidence
freshness_status

禁止 Agent 自己提交以下字段后直接影响最终 Permit：

historical_vendor_median
market_price
account_balance
position
leverage
daily_spend
protocol_risk
address_reputation
market_data_freshness
simulation_result

这些字段必须由可信 Enricher、Adapter、Oracle 或持久化状态生成。

数据缺失或过期时，根据规则返回：

DENY
REVIEW
INSUFFICIENT_DATA

不得静默使用默认值 Permit。

第九阶段：完善 Policy Validation

实现：

1. Cedar Schema Validation。
2. Policy Bundle Manifest。
3. Bundle Version。
4. Bundle Hash。
5. Bundle Signature。
6. organization_id Scope。
7. environment Scope。
8. created_at。
9. activated_at。
10. expires_at。
11. author。
12. approvers。
13. previous_version。
14. Rollback。
15. Dry Run。
16. Shadow Comparison。
17. Canary Release。
18. Multi-bundle Conflict Resolution。
19. Obligation 输出。
20. Required Approval 输出。
21. Policy Change Audit。
22. 高风险 Policy 发布需要多人批准。

Policy Bundle 加载失败、签名失败、版本冲突或 Schema 不匹配时必须 Fail Closed。

第十阶段：完善 Financial Risk Rules

在现有规则基础上实现并测试：

1. Daily Cumulative Spend。
2. Weekly Cumulative Spend。
3. First-time Destination。
4. First-time Contract。
5. First-time Vendor。
6. Order Frequency。
7. Split-order Detection。
8. Multi-agent Budget Evasion。
9. Venue Concentration。
10. Protocol Concentration。
11. Asset Concentration。
12. Stablecoin Concentration。
13. Unlimited Token Approval。
14. Suspicious Calldata。
15. Contract Allowlist。
16. Destination Allowlist。
17. Withdrawal Blocking。
18. Maximum Leverage。
19. Position Limit。
20. Reduce-only Enforcement。
21. Liquidation Distance。
22. Market Data Freshness。
23. Price Deviation。
24. Slippage Limit。
25. Fee Quote Validation。
26. Cross-chain Bridge Risk。
27. Stale Simulation。
28. Vendor Delivery Failure History。
29. Abnormal Request Velocity。
30. Kill Switch State。

风险规则必须：

1. 确定性。
2. 版本化。
3. 可解释。
4. 有稳定 Error Code。
5. 有独立单元测试。
6. 有边界测试。
7. 有缺失数据测试。
8. 有属性测试。
9. 不依赖 LLM 直接作出最终判定。

第十一阶段：Decision 强绑定

Decision 至少包含：

decision_id
intent_id
intent_hash
decision_kind
reasons
obligations
required_approvals
policy_bundle_version
policy_bundle_hash
risk_rule_set_version
risk_rule_set_hash
context_snapshot_hash
simulation_result_hash
evaluation_time
expires_at
execution_constraints
decision_hash

Execution Grant 必须绑定：

intent_hash
decision_hash
approval_hash
adapter_id
adapter_version
execution_request_hash
nonce
expires_at

任何字段变化必须使原 Decision 或 Approval 失效。

第十二阶段：Simulator、Adapter、Approval 和 Reconciliation

不要在持久化、幂等和 Replay 完成前接入真实资金。

按以下顺序实现：

1. Mock Simulator。
2. Mock Adapter。
3. Adapter SDK。
4. Adapter Manifest。
5. Adapter Conformance Test。
6. x402 Adapter。
7. Safe Adapter。
8. Hyperliquid Adapter。
9. Approval Engine。
10. Execution Grant。
11. Kill Switch。
12. Enforce Mode Feature Flag。
13. Settlement Verification。
14. Reconciliation Worker。

Adapter 必须验证：

1. Capability。
2. Network。
3. Asset。
4. Venue。
5. Request Hash。
6. Simulation Freshness。
7. Deadline。
8. Secret Reference。
9. Adapter Version。
10. Response Schema。
11. Timeout。
12. Retry Safety。
13. Idempotency。
14. Partial Execution。
15. Unknown Execution State。

第十三阶段：API 与服务校验

实现或检查：

POST /v1/intents
GET /v1/intents/{intent_id}/decision
POST /v1/shadow/evaluate
GET /v1/audit/intents/{intent_id}
POST /v1/approvals
POST /v1/approvals/{approval_id}/approve
POST /v1/approvals/{approval_id}/reject
POST /v1/intents/{intent_id}/execute
GET /metrics

所有接口必须具备：

Authentication
Organization Isolation
RBAC
Rate Limit
Request Size Limit
Timeout
Idempotency
Structured Error Code
Correlation ID
Trace ID
Audit
Safe Logging
No Secret Logging
Versioned Response Schema

第十四阶段：测试要求

必须增加：

1. Unit Tests。
2. Integration Tests。
3. End-to-end Tests。
4. PostgreSQL Persistence Tests。
5. Concurrent Idempotency Tests。
6. Concurrent Budget Reservation Tests。
7. Property Tests。
8. Fuzz Tests。
9. Schema Compatibility Tests。
10. Replay Determinism Tests。
11. Audit Tamper Tests。
12. Identity Replay Tests。
13. Approval Replay Tests。
14. Execution Grant Single-use Tests。
15. Adapter Failure Tests。
16. Partial Execution Tests。
17. Unknown Settlement Tests。
18. Kill Switch Tests。
19. Fail-closed Tests。
20. Documentation Examples Tests。

CI 增加：

cargo fmt
cargo clippy
cargo test
cargo deny
cargo fuzz
secret scanning
SAST
container scanning
SBOM generation
artifact signing
migration tests
Docker Compose end-to-end test

第十五阶段：修复文档漂移

检查 README、Architecture、Threat Model、PRD、crate-level documentation 与实际代码是否一致。

发现以下类型问题必须修复：

1. 文档声称模块不存在，但代码已经实现。
2. 文档声称模块已接入，但代码未接入。
3. Roadmap 状态与 Workspace 不一致。
4. API 文档与实际路由不一致。
5. Threat Model 缓解状态与实际代码不一致。
6. README 的完成度高于真实完成度。
7. 示例请求无法通过当前 Schema 或 Policy。
8. 注释描述仍停留在旧 Phase。

每次代码变更必须同步：

README.md
docs/architecture.md
docs/threat-model.md
docs/roadmap.md
CHANGELOG.md

第十六阶段：实施顺序

第一批只实施 Durable Shadow Mode，不要一次性实现真实执行：

P0.1 PostgreSQL Persistence。
P0.2 Intent Lifecycle State Machine。
P0.3 DecisionRecorded。
P0.4 Idempotency。
P0.5 Identity Gateway Wiring。
P0.6 EvaluationContext。
P0.7 Deterministic Replay。
P0.8 Context Provenance。
P0.9 Policy Bundle Versioning。
P0.10 Metrics and Audit Query API。

完成第一批后，重新运行完整测试并输出：

1. 已发现问题。
2. 已修改文件。
3. 数据库迁移。
4. 新增测试。
5. 安全影响。
6. 未完成问题。
7. 下一批建议。
8. PRD 和 Roadmap 状态变化。

工作原则：

1. 不删除现有有效实现。
2. 不进行无必要的大规模重构。
3. 每次只完成一个可验证的垂直功能。
4. 修改前说明依据。
5. 修改后运行测试。
6. 任何失败都不得被解释为 Permit。
7. 不写入生产 Secret。
8. 不接入真实钱包或主网资金。
9. 先实现 Mock 和 Shadow，再实现 Enforce。
10. 所有实现必须附带 Acceptance Criteria。