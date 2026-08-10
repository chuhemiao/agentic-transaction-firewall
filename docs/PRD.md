# Agentic Transaction Firewall 产品需求文档

项目名称：Agentic Transaction Firewall
项目简称：ATF
仓库：agentic-transaction-firewall
产品类型：开源基础设施
核心语言：Rust
开源许可：Apache License 2.0
文档版本：PRD v1.4（Authenticated Operations Metrics 修订版）
更新日期：2026-08-10
项目阶段：Phase 2 已通过 Checkpoint C4；Phase 3 RA-001 待启动
目标定位：面向 AI Agent 金融行为的非托管、确定性、可验证控制与证据层

---

## 0. 文档定位与当前基线

本 PRD 同时定义长期产品目标与当前版本的交付门槛。带有“必须”“禁止”“不得”的条目是规范性要求；目标架构不代表当前仓库已经实现。

当前真实实现以 `README.md` 的 Status、`docs/architecture.md` 的 What exists today、`docs/audit-gap-matrix.md` 的证据和实际代码/测试为准。出现冲突时，按以下顺序判断：

1. 已提交代码、Schema、迁移和可执行测试。
2. `README.md` 与 `docs/architecture.md` 的当前状态。
3. 本 PRD 的目标要求。
4. 其他设计草案或历史说明。

截至 PRD v1.4：

1. `atf-core`、Intent Schema/Canonical Hash、基础 Cedar Policy、基础 Risk、Policy/Risk Decision Merge、Hash Chain Audit、Identity Library、CLI、`atf-store` 和 Shadow Gateway 已有真实代码与测试。
2. Gateway 已切换到 PostgreSQL 单一持久化路径：DS-016 Admission 在 Policy/Risk 前验证 Canonical `ATF_INTENT_V1` Envelope、当前组织作用域 Agent 与精确 Ed25519 Key，并原子提交 hashed Nonce、Idempotency Reservation、Intent、`IntentReceived` 与 `IdentityVerified -> IDENTITY_VERIFIED/v2`；Finalization 在行锁和预期版本检查后，原子提交 Evaluation、Decision、Policy/Risk/Simulation/Decision 四个阶段事件与 `DECIDED_*/v6`。重启或第二实例可读取并重放原始 Decision/Lifecycle；DS-028..DS-031 的重复购买、每日累计支出、首次目标地址与 REQUESTED 请求频率规则读取 Organization/Agent/Profile/Action、Evaluation Time 与 Repository Sequence 明确限界的持久化快照，而不再把完整 Audit Event 列表交给 Risk。
3. DS-006/DS-007 已定义并落地 22 个稳定 Lifecycle State、完整单向转换表；DS-015/DS-016/DS-018/DS-026/DS-027 将类型化 Audit Payload 扩展到 40 类（含 Agent/Key、Operator/Role 操作者事件与 `ReplayDetected`）。DS-008 已封闭 Intent Core Envelope，Schema 与 Rust 反序列化均拒绝未知核心字段和非 `1.0` 版本；扩展只能保留在参与 Canonical Hash 的对象型 `context`/`metadata` 中。DS-009 已实现所有 Action 共用的金额、时间、ULID、Identifier 与 Purpose 语义边界。DS-010 增加封闭 Profile Dispatch：当前只接受 `atf.agent-commerce.payment` v1.0（`payment/purchase_api_resource`），校验 typed resource、CAIP-2 Network、同链 CAIP-19 Asset 与 CAIP-10 Destination，并在 Durable Admission 与 Policy/Risk 前拒绝其他 Action 组合。DS-011 已统一业务错误为 `{code,message,request_id,details}`，为每个响应生成服务端 Request ID，且以 PostgreSQL 零记录证据锁定 Schema → Common Semantic → Profile → Authenticated Admission → Policy/Risk 顺序；原始输入、Schema/SQL/Policy/Key/Internal Error 不进入响应。DS-012/DS-013 已完成原子 Idempotency Reservation/Result、数据库时钟租约、续租/过期接管、单调 Generation Fencing、完成结果不可变和精确重试/Fail-Closed Recovery。DS-014/DS-015 已完成 Domain-separated Identity Envelope、持久化 Agent/Key 生命周期和仅公钥离线 CLI。DS-016 migration 0005 仅保存 Nonce/Envelope Hash 与精确绑定，拒绝/重放只提交组织作用域类型化证据，不得创建 Intent 或进入 Policy/Risk；精确重试不增加证据，冲突并发只能有一个有效绑定。DS-018 migration 0006 持久化外部 Subject Fingerprint、Operator 状态和显式 Organization Role，以类型化 Audit 绑定离线变更；Gateway 验证配置的 HTTPS Issuer/JWKS RFC 9068 Token，并以每请求重新加载的 `auditor`/`org_admin` 权限保护 Decision GET。DS-019 以闭合 Manifest、Cedar Schema、文件摘要、组织/环境作用域和激活窗口构造 Domain-separated Canonical Policy Bundle Hash；DS-020 migration 0007 进一步保存严格 Ed25519 发布者证明、不可变精确字节归档与单调 Active Pointer，安装/激活/回滚和 `PolicyChanged` 同事务提交，Gateway 每请求重载并验证当前签名版本，JWT Admin API 要求当前 `policy_author`/`org_admin`。DS-021 将 Risk 的 Engine/Rule Set Version、启用状态、Severity、Threshold、Missing-data Behavior、Deny List、History Window 与 Accounting Boundary 绑定为 Domain-separated Canonical Hash；每个 Risk Result 和当前 Gateway Risk Evidence 均携带精确 Version/Hash。DS-022 增加闭合、无 JSON Number 的 Provenance Evidence Envelope，将 Source/Kind/Source ID/Observation/Expiry/Value/Confidence 绑定为 Canonical Hash，并以精确 Allowlist、可选严格 Ed25519 Proof 和显式 Freshness 产生不可直接构造的 `VerifiedEvidence`；Risk 将 Agent Privileged Context 隔离，Vendor Median 只接受组织/资源/资产精确绑定的 `ATF_ENRICHED` Evidence，否则显式 Fail Closed。DS-023 migration 0008 在 Policy/Risk 前持久化不可变 Evaluation Context，将精确 Intent/Profile、同一次 Evaluation Time、Policy/Risk Artifact、Agent Context Hash、已验证 Evidence/Trust Policy、Audit History Prefix、外部 Snapshot 可用性和 Simulation `NOT_RUN` 绑定到 Domain-separated Canonical Hash，并以 `ContextEnriched` 和最终 Evaluation 外键验证；恢复路径复用已有 Context 或创建显式不可用 Context，仍只产生 `RECOVERY_REPLAY_NOT_IMPLEMENTED -> Decision(ERROR)`。DS-024 已使 Policy/Risk 只验证并消费该持久化 Context；DS-025 进一步以闭合 Decision v1 将 Intent/Profile、Policy/Risk、Context/Snapshot、Simulation、时间/到期时间和执行约束绑定到 Domain-separated Canonical Hash，并要求 Store 与 `DecisionRecorded` 使用相同绑定。DS-033 已加入闭合低基数 Prometheus Metrics、JSON Request Span、Request/Trace/Audit Event 关联及 Canary 脱敏测试；DS-034 已为所有 HTTP Route 加入有限 Body/Header、全请求与评估超时、直连来源及已验证主体限流，并以默认回环监听、非回环 TLS Proxy 声明和不信任转发 Header 明确入口边界。DS-035 将进程存活与安全服务就绪分离，`/readyz` 额外验证配置的签名活动 Policy，并以闭合标签统一 Database、Active Policy、History Snapshot、Audit 与 Lock 失败；任何未原子提交完整 Evidence 的新 Decision 都不会返回。`IDENTITY_UNVERIFIED`/`IdentityVerificationSkipped` 仅保留为历史兼容事实，当前 Gateway 不再产生或升级该分支。其他 Action Profile、后台恢复扫描和其他 Admin HTTP Role Matrix 仍未完成。
   DS-036 将迁移、Audit/Lifecycle、Idempotency、Nonce、Restart/Recovery 与依赖竞争收敛为同一个真实 PostgreSQL 本地/CI 套件；两个独立 Gateway 实例对相同 Intent 与冲突 Nonce 只产生一个可重启验证的权威 Decision/完整 Audit Chain。该竞争测试发现并关闭了 `READ COMMITTED` 下分离读取 Audit Head/Event 的 read-skew：现在一次 SQL 的 MVCC Snapshot 同时取得 Head 与有序 Events，合法并发追加不再被误判为持久状态损坏。真实 `55P03` Lock Timeout 和 `40P01` Deadlock 均在五秒外层期限内 Fail Closed；CI 连续运行两轮，测试专用 Compose 运行相同锁定命令。
   DS-037 将 Replay/Canonical/Binding 从实现细节提升为独立 CI 契约：固定纯向量锁定 Original/Counterfactual 的 Context Hash、Decision Hash、相同 Snapshot 与非权威新 Lineage；10 个 Proptest 属性把 Amount 锁定为无损 JSON String，并对每类派生 Decision Binding 做攻击者重算 Hash 后的替换验证；9 个 PostgreSQL Replay 场景继续验证动态 Audit Prefix 下的关系与稳定错误。独立 nightly/libFuzzer Workspace 从有效、Malformed、数字金额与未知核心字段种子 fuzz 公共 Intent Validator，CI 以 15 秒总时限和 10 分钟作业外限执行。
   DS-038 将依赖漏洞、Secret 与 Rust 静态分析变成每个 Pull Request 的阻断门禁：所有 GitHub Action 使用不可变 Commit，`cargo-audit 0.22.2` 检查 Root/Fuzz 两份 Lockfile，Gitleaks 8.30.1 检查完整 Git History 与当前 Source Tree，rustc/Clippy 1.95.0 在 `-D warnings` 之外禁止 First-party `unsafe_code`。Vulnerable Lock、Synthetic Secret 与 Unsafe Crate 安全夹具分别证明门禁确实失败；Advisory/Fingerprint 例外必须精确绑定 Owner、Reason 与不超过 90 天的 Expiry，且 Cargo Tree 一旦证明包可达即拒绝 Advisory 例外。
4. DS-026 migration 0009 按组织/环境归档不可变 Canonical Risk Rule Set，并以当前 Policy-change Role 与 `RiskRuleSetStored` 原子审计绑定安装。Original Replay 要求当前 `auditor`/`org_admin`，精确加载原 Intent、Evaluation Context、签名 Policy Bundle、Risk Rule Set 与 Context 指定的 Audit Prefix，重算并比较 typed module evidence 和完整 Decision bytes/hash；成功只追加 `OriginalReplayCompleted(authoritative=false)`，不新增或覆盖权威 Evaluation/Decision。缺失或篡改输入以稳定 Replay Code Fail Closed。
5. DS-027 migration 0010 将 Counterfactual Replay 存入独立不可变表：复用原 Intent、Snapshot、Evaluation Time、Evidence 与 Audit Prefix，显式选择精确 Policy/Risk Artifact，以新 Evaluation/Decision ID 产生 `authoritative=false` 的 lineage；原权威记录保持不变，typed Audit 绑定 Context/Evaluation/Decision Hash、版本与结果变化。
6. DS-028 migration 0011 为 `DecisionRecorded(PERMIT)` 增加组织/Agent/资源/时间索引；Store 在只读 Repeatable Read 中记录 Repository Boundary、精确 Query Input 与至多一条历史结果，Gateway 将其写入 Canonical Risk Evaluation/Audit Evidence，Original 与 Counterfactual Replay 按原 Sequence/Hash 重建相同输入。DENY、其他组织、当前 Intent 和 Evaluation Time 之后的事件均不计入。
7. DS-029 migration 0012 为 `DecisionRecorded(PERMIT)` 增加组织/Agent/时间/资产索引；Store 在同一 Repeatable Read Snapshot 中按绑定资产使用 PostgreSQL `NUMERIC` 聚合每日历史，限制 256 个资产组并记录缺失资产绑定。Risk 把当前 Intent 加入合计，只允许 Verified `ATF_ENRICHED` 直接 Quote 做精确固定点换算；缺失、歧义、Scope 错误、溢出或精度损失产生 High/Critical Finding。并发完成的两笔 Permit 会同时出现在下一 Snapshot。
8. DS-030 migration 0013 为 `DecisionRecorded(PERMIT)` 增加 Organization/Profile/目标地址/时间索引。Payment Profile 的版本化 EIP-155 Normalizer 不改写已签名 Intent，只把 legacy lowercase 或有效 EIP-55 checksum-case 地址派生为同一个 lowercase History Key；Store 在同一 Repeatable Read Snapshot 中返回至多一条先前 Permit，并重新验证 typed Event、Decision/Intent/Profile/Destination 绑定与 Normalizer 输出。先前 DENY、其他组织、无效 checksum 或不支持 namespace 均不能建立 familiarity。
9. DS-031 migration 0014 为 `IntentReceived` 增加 Organization/Agent/Profile/Action/时间索引。Rule Set v1.3.0 将 `AGENT` Subject、`PROFILE` Action Scope、Threshold、Window、`REQUESTED` Boundary 与 Missing-data Behavior 绑定进 Canonical Hash；Authenticated Admission 原子写入 Profile/Action Binding，Store 在 Context Sequence/Hash 边界统计闭区间内的匹配请求与未解析遗留事件。并发接受请求不能全部绕过同一阈值，完成态幂等重试不增加 `IntentReceived` 或业务频率计数。
10. DS-032 提供 `GET /v1/audit/events` 与 `GET /v1/audit/intents/{intent_id}`：Gateway JWT 与当前 `auditor`/`org_admin` Role 保护入口，Store 在只读 Repeatable Read 中再次授权并验证目标组织完整 Hash Chain 后才应用 Intent、Agent、Event Type 与闭区间时间过滤。响应默认 50、最多 100 条，按 Sequence 升序；Canonical Cursor 绑定 Organization、Filter Hash 与已验证 Chain Prefix，后续 Append 不改变当前遍历。跨组织、错 Role、Cursor 重绑及链损坏均 Fail Closed。
11. Simulator、Approval、Execution Adapter、Reconciliation、SDK 和生产部署仍是 Scaffold 或缺失。
12. 当前系统只能用于本地或受控环境下的 Shadow Evaluation；不得被描述为生产级、多租户或可控制真实资金的系统。
13. DS-040 已发布 `docs/release-candidate-checklist.md`，并把 §32.1/§32.2
    映射到测试和运行命令。复审发现的 `C4-GAP-001` 已按 Accepted ADR-0004
    整改：业务 Router/Listener 不再暴露 `/metrics`；独立回环 mTLS Operations
    Listener 以专用客户端 CA、批准的 SPKI 和受保护 Unix Socket 形成仅具
    `METRICS_READ` 的 typed `OperationsPrincipal`，不依赖 PostgreSQL/JWKS，且
    不能调用任何业务路由。缺失、错误 CA、过期、未来生效、错误 EKU 与未批准
    身份均被真实 TLS 演练拒绝；PostgreSQL 故障时授权抓取仍返回 process metrics
    与 `replay_metrics_available=0`。独立人工 ATF 维护者已于 2026-08-10 审核
    实现提交 `850477e`、接受文档列明的残余风险并批准 `C4-SIGNOFF-001`；
    Checkpoint C4 已通过，下一项为 RA-001。该批准不代表生产就绪、真实资金或
    执行权限获批。

当前版本已完成并通过 **Durable Shadow Mode** C4 审核：每个被接受的 Intent 和 Decision 都经过身份校验、持久化、可幂等返回、可确定性重放、可查询和可审计。下一近期目标是 Phase 3 的 RA-001 Simulator 结果契约；真实执行链仍未获授权。

---

## 1. 产品摘要

Agentic Transaction Firewall 是一个协议中立、钱包中立、交易场所中立的开源金融交易控制层。

它位于 AI Agent 与钱包、交易所、DeFi 协议、Treasury 系统、x402 服务和其他支付网络之间。所有不可逆或高风险金融行为在执行前，必须转换为统一的 Transaction Intent，经过身份验证、语义校验、Policy Evaluation、金融风险检查、交易模拟和必要审批，才能获得一次性执行授权。

ATF 不创建新钱包，不托管资产，不发明新支付协议，也不替代交易所、Fireblocks、Privy、Safe、Coinbase CDP 或 AWS AgentCore。ATF 的目标是为这些基础设施提供统一的上层控制语义：

Agent Intent
→ Canonical Transaction Intent
→ Identity & Semantic Validation
→ Versioned Evaluation Context
→ Policy Evaluation
→ Financial Risk Evaluation
→ Simulation
→ Bound Decision
→ Approval
→ Single-use Execution Grant
→ Execution Adapter
→ Settlement Verification
→ Immutable Audit

ATF 的核心价值不是“让 Agent 可以付款或交易”，而是回答以下问题：

1. 这个 Agent 是否有权执行该行为。
2. 该行为是否符合用户或组织授权的原始意图。
3. 该行为是否违反预算、仓位、杠杆、滑点、协议或资金安全限制。
4. 是否需要人工或多人审批。
5. 最终执行的交易是否与审批内容一致。
6. 执行结果是否完成结算和服务交付。
7. 出现异常后是否可以完整追踪责任链。
8. 同一份原始证据是否能够重放出相同 Decision。
9. 任意一次执行是否只能使用与 Intent、Decision、Approval 完全绑定的一次性授权。

---

## 2. 产品愿景

成为 AI Agent 金融行为控制与证据链的开源参考实现。

长期目标不是再造钱包或支付网络，而是在异构执行基础设施之上形成一组可组合、可验证的公共契约：

1. Agent Transaction Intent Specification。
2. Identity Envelope 与组织隔离模型。
3. Versioned Evaluation Context 与 Context Provenance。
4. Deterministic Policy/Risk/Simulation Decision。
5. Intent Lifecycle 与 Hash-chained Audit Evidence。
6. Approval 与 Single-use Execution Grant Binding。
7. Adapter、Settlement 和 Reconciliation Conformance。

ATF 希望成为自主金融系统中的 Policy Enforcement Point，类似于：

1. Kubernetes Admission Controller 对集群资源的控制。
2. Web Application Firewall 对网络请求的控制。
3. Cedar 或 OPA 对软件授权的控制。
4. Firewalls 和 SIEM 对企业安全行为的控制。

区别在于，ATF 专门理解金融交易语义，包括金额、资产、目的地址、Token Approval、杠杆、滑点、清算距离、资金费率、市场状态、任务预算和交易策略。

### 2.1 当前战略重点

近期产品不是“尽快接上真实钱包”，而是先证明控制层自身值得信任：

1. **Durable**：服务重启、并发请求和多实例运行不能丢失或分叉已接受的 Intent、Decision 与 Audit Evidence。
2. **Deterministic**：决定结果的时间、Policy、Risk Rules、Context 和外部证据全部版本化并可重放。
3. **Authenticated**：Agent 与组织身份在 Policy/Risk 之前验证，签名具备 Domain Separation、Audience、Environment、Nonce 和有效期。
4. **Provenance-aware**：Agent 不能自行提供价格、余额、仓位、历史支出或模拟结果并直接影响 Permit。
5. **Fail Closed**：缺失、过期、冲突或无法验证的数据不得静默转为 Permit。
6. **Execution-last**：在 Durable Shadow Mode 完成、通过验收并重新安全审计前，不实现真实资金执行。

### 2.2 产品成功形态

ATF 的最佳成功形态不是垂直产品垄断全部流程，而是成为钱包、Agent Framework、支付系统、交易基础设施和企业 Treasury 都可以复用的公共安全层。第三方可以替换 Policy、Risk 数据源或 Adapter，但不能绕过统一 Intent、绑定、生命周期和证据语义。

---

## 3. 背景与问题

现有 Agent 钱包和支付基础设施正在快速发展，但大部分系统仍主要解决以下能力：

1. 创建程序化钱包。
2. 保存或代理签名权限。
3. 设置静态金额限制。
4. 设置合约或地址白名单。
5. 完成链上支付或 API 付费。
6. 记录单笔交易日志。

这些能力不能完整解决企业或金融组织的自主 Agent 风险。

例如，一笔链上交易在钱包层可能只表现为：

向某地址转账 10,000 USDC。

但其真实业务语义可能是：

Treasury Agent 将 10,000 USDC 从运营钱包调往某个永续合约账户，为策略 quant-btc-03 补充保证金；该策略最大杠杆不得超过 3 倍，平台总敞口不得超过总资产的 20%，且只允许向组织登记的账户调拨。

钱包层只能判断地址、资产和金额。

ATF 需要进一步判断：

1. Agent 是否属于该组织。
2. Agent 是否被授权管理该策略。
3. 目标账户是否属于组织。
4. 当前策略是否处于启用状态。
5. 调拨后是否超过场所集中度。
6. 是否会使策略杠杆超过限额。
7. 当前市场数据是否足够新鲜。
8. 是否需要人工审批。
9. 签名交易是否与原始 Intent 完全一致。

---

## 4. 产品目标

### 4.1 长期核心目标

1. 定义统一的 Agent Transaction Intent Schema。
2. 提供确定性的 Policy-as-Code 执行内核。
3. 提供金融语义风险检查。
4. 支持 Shadow Mode、Review Mode 和 Enforce Mode。
5. 支持人工审批和多人审批。
6. 提供协议与钱包 Adapter SDK。
7. 保存完整、可验证、不可静默修改的审计记录。
8. 提供三个真实金融场景的参考实现。
9. 建立项目级威胁模型、测试标准和安全边界。
10. 形成可供第三方实现的 Conformance Test Suite。

### 4.2 当前版本目标：Durable Shadow Mode

1. PostgreSQL 持久化已接受的 Intent、Evaluation、Decision 和 Audit Event。
2. 建立明确的 Intent Lifecycle State Machine 与事务边界。
3. 对 `(organization_id, idempotency_key)` 实施并发安全、重启后仍有效的幂等语义。
4. 将 Domain-separated Agent Identity Envelope 接入 Gateway，并在 Policy/Risk 前 Fail Closed。
5. 引入版本化 `EvaluationContext`，消除决策路径对隐式当前时间和未记录环境状态的依赖。
6. 支持 Original Replay 与 Counterfactual Replay，且不得覆盖原 Decision。
7. 将决策输入分为 Agent、ATF、Oracle、Adapter、Admin 和 Signed External Evidence 来源，并执行新鲜度检查。
8. 为 Policy Bundle 和 Risk Rule Set 记录版本、Canonical Hash、Scope 和激活状态。
9. 提供组织隔离的 Audit Query API、Metrics 和安全可观测性。
10. 在上述能力完成并重新审计前，保持所有 Execution 路径不存在或默认关闭。

### 4.3 成功定义

当前阶段成功不以用户数、交易量、接入链数量或融资为核心指标，而以以下结果衡量：

1. 开发者能够在 30 分钟内运行本地 Demo。
2. Agent 可以通过统一 API 提交交易意图。
3. Cedar Policy、Risk 和 Decision Merge 对相同记录输入产生相同结果。
4. 风险引擎可以识别静态授权之外的金融风险。
5. Shadow Mode 可以在不接管签名权限的情况下生成风险报告。
6. 同一 Idempotency Key 的并发和重试不会重复评估或产生冲突 Decision。
7. 所有决策都能够从持久化 Snapshot 完整重放和审计。
8. 服务重启后 Intent、Decision、Audit Chain 和 Replay Protection 不丢失。
9. 核心模块通过单元、集成、并发、属性、模糊和依赖安全检查。
10. 文档明确区分 `IMPLEMENTED_AND_WIRED`、Partial、Scaffold 和 Missing，不夸大生产能力。

Adapter 数量、真实执行量和多链覆盖属于后续阶段指标，不作为 Durable Shadow Mode 的完成条件。

---

## 5. 非目标

ATF 明确不做以下事情：

1. 不托管用户资产。
2. 不保存生产私钥。
3. 不自建 MPC、HSM 或 KMS。
4. 不创建新公链。
5. 不开发新的稳定币或 Token。
6. 不创建新的支付协议。
7. 不运营交易所或流动性池。
8. 不替代 Safe、Privy、Fireblocks、Coinbase CDP 或交易所账户系统。
9. 不使用 LLM 作为最终 Permit 或 Deny 决策者。
10. 不承诺阻止所有金融损失。
11. 不承担资产赔付责任。
12. 不在 MVP 阶段提供完整企业 SaaS 控制台。
13. 不在 MVP 阶段覆盖所有链、交易所和 Agent 框架。
14. 不把低延迟高频交易作为初始目标。
15. 不发行项目 Token。
16. 不内置 AML/OFAC 制裁名单筛查。ATF 通过 Risk Rule 扩展点支持接入第三方合规数据源（见 12.4），但不自带合规数据或承担合规责任。
17. Durable Shadow Mode 不接入真实钱包、交易所执行权限或主网资金。
18. 当前版本不承诺互联网暴露、多租户隔离、HA、SLA 或任何生产就绪状态。
19. 不把“存在 Idempotency Key 字段”“存在 Hash”“存在 Audit Event”误称为已经实现幂等、不可篡改或可重放。

---

## 6. 目标用户

### 6.1 开源开发者

需求：

1. 为自己的 Agent 添加交易政策控制。
2. 快速接入钱包、Safe、交易所或 x402。
3. 使用统一 Schema，而不是重复设计交易上下文。
4. 在本地运行和调试 Policy。
5. 编写自定义 Adapter 和风险规则。

### 6.2 AI Agent 平台团队

需求：

1. 为多个 Agent 分配不同预算和权限。
2. 限制 Agent 可调用的金融工具。
3. 防止重复支付、错误支付和异常交易。
4. 提供人工审批和责任审计。
5. 保持跨钱包和支付协议的一致策略。

### 6.3 Crypto 量化与交易团队

需求：

1. 限制每个策略的资产、仓位和杠杆。
2. 管理多个 API Wallet 和交易账户。
3. 在日亏损、清算距离或市场数据异常时自动阻止新增风险。
4. 提供策略级 Kill Switch。
5. 记录交易意图与最终执行差异。

### 6.4 DAO 与企业 Treasury

需求：

1. 只允许向白名单地址或协议付款。
2. 控制每日累计支出。
3. 阻止无限 Token Approval。
4. 对首次地址或高风险合约要求人工审批。
5. 完成资金用途、发票和交易记录匹配。

### 6.5 钱包、支付与基础设施提供商

需求：

1. 复用 ATF 的统一 Transaction Intent。
2. 把 ATF Policy 编译或映射到自身权限模型。
3. 使用 ATF 作为独立的 Shadow Risk Layer。
4. 利用统一审计格式改善企业集成。

---

## 7. 产品模式

ATF 的目标形态支持三种运行模式，但三种模式不是可任意切换的配置项，而是按安全能力逐级开放：

1. 当前只开放 Shadow Mode。
2. Review Mode 必须在持久化、身份、幂等、Decision Binding 和 Approval Engine 完成后开放。
3. Enforce Mode 必须进一步具备 Simulator、Single-use Execution Grant、Adapter Conformance、Kill Switch、Settlement/Reconciliation 和故障恢复，并完成独立安全复审。

### 7.1 Shadow Mode

ATF 不阻止交易，也不掌握签名权限。

流程：

1. Agent 或应用复制 Transaction Intent 给 ATF。
2. ATF 执行当前已启用的 Identity、Semantic Validation、Policy、Risk 和 Simulation 阶段；未实现的阶段必须在结果中显式标记，不得伪造成功。
3. ATF 返回“如果启用 Enforcement，本次应 Permit、Deny 或 Review”。
4. 交易仍通过原有路径执行。
5. ATF 对比预测结果与实际结果。

用途：

1. 低风险接入。
2. 历史策略评估。
3. Policy 调试。
4. 风险误报与漏报分析。
5. 设计伙伴验证。

当前仓库的 Shadow Gateway 已实现 Intent/Profile Validation、Agent Identity、Durable Idempotency/Recovery、Policy、部分 Risk、强绑定 Decision、Audit Query、Original/Counterfactual Replay、DS-033 安全可观测性、DS-034 应用层 HTTP 安全边界、DS-035 Fail-Closed Dependency/Readiness 契约、DS-036 可重复的真实 PostgreSQL 多实例/竞争 CI 套件、DS-037 固定 Hash Replay/Binding Property/限时 Intent Fuzz、DS-038 固定版本的 Dependency/Secret/Rust SAST 阻断门禁，以及 DS-039 单机本地 TLS Compose、备份恢复、策略回滚和负载基线。Simulation、Approval、Adapter/Execution、后台 Recovery Scanner、共享生产入口、HA/故障切换与生产运维基线仍缺失，因此不等同于本节的完整目标态 Shadow Mode。

### 7.2 Review Mode

低风险交易自动通过，高风险交易进入审批。

流程：

1. ATF 生成决策。
2. Permit 直接传递到执行层。
3. Review 进入人工或多人审批。
4. Deny 被拒绝。
5. 审批结果和原因进入审计账本。

Review Mode 当前不可用。`REVIEW` Decision 只表示“需要额外控制”，不代表仓库已经存在可完成审批的路径。

### 7.3 Enforce Mode

所有受控交易必须经过 ATF。

要求：

1. Agent 不直接持有无限制签名权限。
2. 钱包、Safe Module、交易所 API 或签名服务只接受 ATF 授权请求。
3. ATF Decision 绑定 Transaction Hash 或 Canonical Request Hash。
4. 执行前再次验证请求未被修改。
5. 执行后验证实际结果。
6. 每次执行只接受一个未过期、未使用、与 Intent/Decision/Approval/Adapter/Request Hash 完全绑定的 Execution Grant。
7. Audit、Idempotency、Budget Reservation 或执行授权存储不可用时 Fail Closed。

---

## 8. 核心用户流程

本章描述目标端到端流程。当前 Gateway 在 `DecisionRecorded` 后停止，不调用 Simulator、Approval 或 Adapter，也不执行交易。

### 8.1 Agent 发起交易

1. Agent 生成一个金融行为计划。
2. Agent SDK 把计划转换为 Transaction Intent。
3. SDK 对请求进行身份签名。
4. Intent Gateway 验证 Agent 和组织身份。
5. Context Normalizer 将请求转换为统一格式。
6. Policy Kernel 执行 Cedar Policy。
7. Risk Engine 计算动态风险。
8. Simulator 对交易结果进行模拟。
9. Decision Engine 合并各类结果。
10. Permit、Review 或 Deny。
11. Permit 请求发送到 Adapter。
12. Review 请求发送到 Approval Service。
13. 执行后生成 Settlement Record。
14. Audit Ledger 保存完整证据链。

### 8.2 人工审批

审批者看到：

1. 原始用户或组织 Mandate。
2. Agent 身份与版本。
3. 交易目的。
4. 资产、金额和目标。
5. 命中的 Policy。
6. 风险评分。
7. 模拟后的资产变化。
8. 拒绝或警告原因。
9. 预计 Gas、滑点、杠杆或资金影响。
10. 审批有效时间。

审批动作：

1. Approve。
2. Reject。
3. Approve Once。
4. Approve with Modified Limits。
5. Escalate。
6. Pause Agent。
7. Trigger Kill Switch。

### 8.3 事故调查

1. 输入交易 ID、Agent ID 或时间范围。
2. 查询原始 Intent。
3. 查询 Policy 版本。
4. 查询决策输入 Context。
5. 查询模拟结果。
6. 查询审批人。
7. 查询执行请求。
8. 查询链上或交易所结果。
9. 查询服务交付结果。
10. 生成可导出的 Incident Report。

---

## 9. Transaction Intent Specification

当前 `atf-intent` 已实现封闭且相互校验的 JSON Schema/Rust Type、`spec_version: "1.0"` 支持集合、Canonical Serialization/Hash、通用 Semantic Validator 和封闭 Action Profile Dispatcher。未知核心字段会 Fail Closed；对象型 `context`/`metadata` 是当前仅有的开放扩展区并完整进入 Hash。当前唯一受支持的 Profile 是 `atf.agent-commerce.payment` v1.0；Schema 已列出的其他 Action Category 会返回 `UNSUPPORTED_INTENT_PROFILE`，不等于获得完整语义支持。

### 9.1 设计原则

1. 与具体钱包和协议解耦。
2. 支持链上交易、交易所订单、支付和 Treasury。
3. 保留原始业务目的。
4. 能够被确定性序列化和哈希。
5. 支持版本化。
6. 支持扩展字段，但禁止无约束修改核心字段。
7. 所有金额使用字符串或定点数，禁止浮点数。
8. 所有时间使用 RFC 3339。
9. 所有资产使用标准化 Asset ID。
10. 所有请求必须有 Idempotency Key。
11. JSON Schema 与 Rust 反序列化共同负责封闭结构和受支持版本；Rust Semantic Validator 必须负责金额、时间、ID 和 Action-specific 跨字段约束。
12. 核心 Envelope 不接受会被静默忽略的未知字段；扩展字段必须位于对象型 `context`/`metadata` 并进入 Canonical Hash。新增长期互操作扩展应使用版本化命名空间；现有 v1 非命名空间字段只作为兼容且不可信的证据保留。
13. Agent 提供的 `context` 默认不可信，不能覆盖 ATF Enricher、Oracle、Adapter 或持久化状态生成的权威字段。
14. Semantic Validation 失败必须返回稳定、机器可读的 Error Code，并在 Policy/Risk 前终止。

### 9.2 核心字段

```json
{
  "spec_version": "1.0",
  "intent_id": "01J...",
  "idempotency_key": "research-2026-07-18-001",
  "created_at": "2026-07-18T08:00:00Z",
  "expires_at": "2026-07-18T08:05:00Z",
  "principal": {
    "organization_id": "alpha-lab",
    "user_id": "user-001",
    "agent_id": "research-agent-01",
    "agent_version": "1.4.2",
    "strategy_id": null
  },
  "mandate": {
    "mandate_id": "mandate-001",
    "task_id": "research-task-001",
    "purpose": "purchase historical order-book data",
    "budget_id": "research-budget-july",
    "human_authorized": true
  },
  "action": {
    "category": "payment",
    "operation": "purchase_api_resource"
  },
  "resource": {
    "protocol": "x402",
    "venue": "market-data-provider",
    "resource_id": "btc-orderbook-2026-07-01",
    "resource_type": "dataset"
  },
  "transaction": {
    "network": "base",
    "asset": "eip155:8453/erc20:0x...",
    "amount": "12.50",
    "destination": "0x...",
    "contract": null,
    "calldata_hash": null,
    "max_fee": "0.25",
    "slippage_bps": null,
    "leverage": null
  },
  "context": {
    "data_classification": "public",
    "requested_by_tool": "mcp-market-data"
  },
  "metadata": {
    "labels": ["research", "market-data"]
  }
}
```

### 9.3 支持的 Action Category

MVP：

1. payment
2. transfer
3. token_approval
4. contract_call
5. exchange_order
6. treasury_rebalance

后续：

1. swap
2. borrow
3. lend
4. stake
5. bridge
6. prediction_market_order
7. subscription
8. recurring_payment
9. refund
10. withdrawal

Schema 中列出 Action Category 不代表当前实现已经能够安全评估或执行该类别。未具备对应 Profile Schema、Semantic Validator、Risk Rules 和 Adapter Capability 的 Action 必须 Fail Closed。

### 9.4 Budget 模型

Transaction Intent 中的 `mandate.budget_id` 引用一个独立的 Budget 对象，而非自由文本。Agent-provided `context.task_budget` 只能作为不可信提示，不能替代持久化 Budget 状态或直接产生 Permit。

Budget 层级：

1. Organization Budget：组织级总额度，周期性重置。
2. Agent Budget：单个 Agent 在组织额度内的分配上限。
3. Strategy Budget：量化策略级别的独立额度，绑定 `strategy_id`。
4. Task Budget：单个任务或会话级别的一次性或周期性额度，绑定 `task_id`。

核心字段：

```json
{
  "budget_id": "research-budget-july",
  "parent_budget_id": "org-budget-2026-07",
  "owner": {
    "organization_id": "alpha-lab",
    "agent_id": "research-agent-01"
  },
  "limit": "500.00",
  "period": "monthly",
  "period_start": "2026-07-01T00:00:00Z",
  "period_end": "2026-08-01T00:00:00Z",
  "consumed": "120.00",
  "reserved": "20.00",
  "status": "ACTIVE"
}
```

设计约束：

1. 扣减必须是原子操作（PostgreSQL 行级锁或 CAS），禁止先查询余额后扣减的竞态写法。
2. 每次 PERMIT 决策先 `reserve`（预留），执行确认后 `commit`，失败或过期后 `release`，防止并发请求超支。
3. 子 Budget 消耗必须同步反映到 `parent_budget_id`，父级超限时子级必须一并拒绝。
4. Budget 状态耗尽或过期时，关联 Intent 直接 DENY，不进入 REVIEW。
5. Budget 变更（额度调整）本身是审计事件，必须记录变更前后值与操作人。

### 9.5 Semantic Validation 与 Intent Profile

通用 Intent Envelope 保持跨协议稳定，具体金融行为通过 Profile 定义必填字段、标识规则和跨字段语义。目标 Profile 集合包括：

1. ATF Payment Intent Profile。
2. ATF EVM Transaction Profile。
3. ATF Exchange Order Profile。
4. ATF Treasury Intent Profile。
5. ATF Prediction Market Intent Profile。
6. ATF Agent Commerce Intent Profile。

当前实现将 Payment 与 Agent Commerce 的最小协议中立交集固定为
`atf.agent-commerce.payment` v1.0，Selector 必须同时满足
`spec_version = 1.0`、`action.category = payment`、
`action.operation = purchase_api_resource`。其完整契约见
`docs/intent-spec.md`；其他目标 Profile 仍未实现且必须 Fail Closed。

最低通用校验包括：

1. `amount > 0`，`max_fee >= 0`，存在 `leverage` 时必须 `> 0`。
2. `slippage_bps` 必须位于 `0..=10000`。
3. `created_at < expires_at`，且 Intent 生命周期不得超过 Profile 配置上限。
4. `intent_id` 必须是合法 ULID；Idempotency Key 和组织/Agent/Mandate ID 必须满足长度、字符和非空白约束。
5. `spec_version` 必须位于 Gateway 明确支持的版本集合；当前结构边界只接受 `1.0`，新增版本必须同步 Schema、Rust Parser、Fixture、Profile 与 Gateway。
6. Asset、Network、Contract、Destination 使用 Profile 声明的标准标识和校验器。
7. Transfer 必须有 Destination；Contract Call 必须有 Contract 与 Calldata Hash；Token Approval 必须有 Spender 与 Allowance；Exchange/Prediction Order 必须有完整订单语义。
8. `amount`、`max_fee`、`fee_asset` 的计价关系必须明确；跨资产手续费必须绑定可验证报价 Snapshot。
9. Metadata 或 Agent Context 中的未知字段可以作为证据进入 Hash，但在没有可信 Provenance 映射前不得影响最终 Permit。

DS-009 当前实现固定以下跨 Action 边界：Intent 生命周期上限为 24
小时；输入时间戳必须能以毫秒精度无损进入 Canonical Serialization；
通用 Identifier 不得为空白、不得超过 256 bytes，字符集限定为 ASCII
字母数字和 RFC 3986 的保留/非保留安全字符；`mandate.purpose` 不得为空白、
不得包含控制字符且不得超过 1024 bytes。校验不执行 trim、截断、金额取整
或时间精度降级。多个错误按固定规则顺序返回
`SemanticViolation { code, field }`；稳定代码包括
`AMOUNT_NOT_POSITIVE`、`MAX_FEE_NEGATIVE`、
`LEVERAGE_NOT_POSITIVE`、`SLIPPAGE_BPS_OUT_OF_RANGE`、
`TIMESTAMP_PRECISION_UNSUPPORTED`、`TIME_ORDER_INVALID`、
`TTL_EXCEEDS_LIMIT`、`INTENT_ID_INVALID`、`FIELD_BLANK`、
`FIELD_TOO_LONG` 与 `FIELD_INVALID_CHARACTERS`。

DS-010 已在上述通用语义之后增加版本化 Profile Dispatch。当前 Payment
Profile 要求 `resource.resource_type`，要求 `transaction.network` 为
CAIP-2、`transaction.asset` 为同链 CAIP-19、`transaction.destination` 为
同链 CAIP-10，并禁止 Contract、Calldata Hash、Slippage 与 Leverage 字段；
`max_fee` 按 `transaction.asset` 计价，v1 不允许扩展字段改变手续费资产。
Profile 校验不执行 trim、大小写折叠、Percent Decode 或 Canonicalization。
未实现的 Action/Profile 组合统一以 `UNSUPPORTED_INTENT_PROFILE` Fail
Closed；不得把“通过通用校验”解释为该金融动作已可安全评估或执行。

具体 Profile 在独立 Specification 中版本化；Profile 变更不得通过向通用 Envelope 随意添加可选字段完成。

---

## 10. 决策模型

ATF 对每个请求返回统一 Decision。

```json
{
  "decision_version": "1",
  "decision_id": "dec-001",
  "intent_id": "01J...",
  "intent_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "evaluation_id": "eval-001",
  "profile": {
    "id": "atf.agent-commerce.payment",
    "version": "1.0"
  },
  "policy": {
    "status": "AVAILABLE",
    "artifact_id": "payment-policy",
    "version": "2026-07-18.3",
    "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "risk": {
    "status": "AVAILABLE",
    "artifact_id": "atf-risk-engine-v1",
    "version": "1.0.0",
    "hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  "evaluation_context_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "context_snapshot_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "simulation": {
    "status": "NOT_RUN",
    "reason_code": "SIMULATOR_NOT_IMPLEMENTED"
  },
  "evaluation_time": "2026-07-18T08:00:01.000Z",
  "expires_at": "2026-07-18T08:03:00.000Z",
  "decision": "REVIEW",
  "reasons": [
    {
      "code": "VENDOR_PRICE_DEVIATION",
      "severity": "high",
      "message": "Vendor price exceeds 30-day median by 41%."
    },
    {
      "code": "FIRST_TIME_VENDOR",
      "severity": "medium",
      "message": "Vendor has not been used by this organization."
    }
  ],
  "required_approvals": [],
  "obligations": [],
  "execution_constraints": {
    "action_category": "payment",
    "action_operation": "purchase_api_resource",
    "resource_id": "dataset-001",
    "resource_protocol": "x402",
    "network": "eip155:8453",
    "asset": "eip155:8453/erc20:0x...",
    "max_amount": "12.50",
    "destination": "eip155:8453:0x...",
    "adapter_id": null
  },
  "decision_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}
```

上例是 DS-025 已实现的 Decision v1 Envelope。`decision_hash` 为
`SHA-256("ATF_DECISION_V1\\0" || Canonical JSON without decision_hash)`；
顶层与嵌套对象均拒绝未知字段。当前没有 Approval/Obligation/Adapter 或
Simulator，因此对应数组为空、`adapter_id` 为 `null`、Simulation 为显式
`NOT_RUN`，不得伪造为已执行或已授权。

### 10.1 Decision 合并算法

Policy Kernel、Risk Engine、Simulator 各自产出独立结果，Decision Engine 按以下固定优先级合并，禁止任何加权评分覆盖该顺序：

1. Simulator 报告"交易必定 Revert"或"无法完成模拟" → DENY 或 REVIEW（见 13.6），此结果不可被 Policy PERMIT 覆盖。
2. Policy Kernel 返回 Cedar `forbid` → DENY，终止合并，不再评估 Risk。
3. Risk Engine 命中任意 `severity: critical` 规则 → DENY。
4. Policy Kernel 返回 `permit` 且未命中 Review 条件，同时 Risk Engine 未命中 `high` 或以上规则 → PERMIT。
5. 以下任一条件成立 → REVIEW：
   - Policy Kernel 显式要求 Review。
   - Risk Engine 命中 `high` 或以上 severity 规则，但未达 `critical`。
   - Simulator 数据不完整或外部依赖超时。
6. 任一模块内部出错（非业务判定，如异常、超时、依赖不可用）→ ERROR，ERROR 在 Enforce Mode 下等价于 DENY，在 Shadow Mode 下记录但不影响原交易路径。

合并规则本身必须作为 Risk/Decision Rule Set 的一部分独立版本化和 Hash 绑定，且必须有对应属性测试（见 28.3）验证合并结果的确定性与幂等性。

### 10.2 Decision 类型

1. PERMIT
2. DENY
3. REVIEW
4. ERROR

ERROR 不得自动等同于 PERMIT。系统默认 Fail Closed。

### 10.3 Decision 强绑定

Decision 必须绑定产生它的全部决定性输入：

1. Canonical Intent Hash。
2. Policy Bundle Version 与 Hash。
3. Risk Rule Set Version 与 Hash。
4. Evaluation Context/Snapshot Hash。
5. Simulation Result Hash（未执行模拟时为显式 `null`/`not_run`，不得伪造成功）。
6. Evaluation Time、Decision Expiry 和 Execution Constraints。
7. Canonical Decision Hash。

DS-025 已实现上述当前可用输入的 v1 绑定：Policy/Risk 使用 Context 中的
精确 Artifact Reference，Simulation 以闭合 `NOT_RUN` Reference 表示，
Execution Constraints 从已验证 Intent 派生；未来新增 Simulator/Approval
语义必须发布新版本。Store 写入与读取均验证内嵌 Hash、Intent/Context 与
`DecisionRecorded.binding` 三者一致。

任何绑定字段变化都会产生新的 Evaluation 和 Decision；Original Decision 不得被覆盖。未来 Approval 和 Execution Grant 必须绑定 `intent_hash` 与 `decision_hash`，不能只引用可变数据库 ID。

---

## 11. Policy Kernel

当前实现通过 DS-019/DS-020 只加载已验证的签名 Policy Bundle：闭合 Manifest
绑定 Bundle ID/Version、Organization/Environment Scope、激活窗口、Cedar
Schema 与精确文件摘要，并生成 Domain-separated Canonical Bundle Hash；
Cedar Policy 与每个 Request 均按同一 Schema 验证，任何 Runtime Diagnostic
Fail Closed。Detached Ed25519 Proof 绑定发布者 Key ID 与 Bundle Hash；migration
0007 保存不可变归档和发布者公钥证据，Active Pointer 原子保留上一签名版本并写
`PolicyChanged`。Gateway 每次新评估在同一 Repeatable-read Snapshot 中加载并重验
当前版本。多 Bundle 合并/冲突管理仍未实现；当前单 Bundle 的精确版本与 Hash
已由 DS-025 绑定进 Decision v1。

### 11.1 技术选择

核心 Policy Engine 使用 Cedar。

原因：

1. Rust 原生生态。
2. 适合描述 Principal、Action、Resource 和 Context。
3. 适合确定性授权。
4. 可以进行 Policy Validation。
5. 便于与企业授权模型对接。
6. 避免从零发明 DSL。

### 11.2 Policy 职责

Cedar 负责：

1. Agent 是否允许执行某类 Action。
2. Agent 是否允许操作某个 Resource。
3. 组织、角色和策略关系。
4. 地址、资产、合约和场所白名单。
5. 时间窗口。
6. 静态金额上限。
7. 是否必须进入 Review。
8. 禁止操作列表。

Risk Engine 负责：

1. 动态仓位风险。
2. 杠杆。
3. 清算距离。
4. 资产和场所集中度。
5. 历史行为异常。
6. 价格偏离。
7. 资金费率。
8. 市场数据新鲜度。
9. 重复采购。
10. 组合日亏损。

### 11.3 Policy 组合与冲突处理

1. 沿用 Cedar 默认语义：存在任意匹配的 `forbid` 时结果为 DENY，`forbid` 优先于所有 `permit`。
2. 一个 Agent 可同时受多个 Policy Bundle 约束（组织级、策略级、Adapter 级）；多个 Bundle 独立求值后按"最严结果生效"合并（DENY > REVIEW > PERMIT）。
3. Policy Bundle 必须有唯一 `policy_version`，同一 Decision 中引用的所有 Bundle 版本必须记录在 Audit 中，禁止跨版本混用求值。
4. Policy 变更必须先在非生产环境通过 `atf policy test` 全量回归，再灰度发布；生产切换必须支持一键回滚到上一个签名版本。
5. 两个 Policy 之间若存在静态可检测的矛盾（例如同一 Principal/Action/Resource 同时被不同 Bundle 判定为 permit 与 forbid），`atf policy validate` 必须报错阻止发布，而非留给运行时合并规则兜底。

---

## 12. Financial Risk Engine

当前实现包含五条 Stateless MVP Rule，以及重复购买、每日累计支出、首次目标
地址和接受请求频率四条 History Rule。DS-021 的闭合
Rule Set Artifact 已将 Engine/Rule Set Version、启用状态、Severity、Threshold、
Missing-data Behavior、Deny List、History Window 和 `REQUESTED`/`PERMITTED`/
`EXECUTED`/`SETTLED` Accounting Boundary 绑定为 Canonical Hash；默认重复购买
边界为 `PERMITTED`。DS-022..DS-031 已将 Provenance、持久化 Artifact/Context、
Replay 与这四类 History Snapshot 连接到当前 Gateway；生产 Enricher 和其余规则仍缺失。

### 12.1 设计原则

1. 确定性优先。
2. 所有规则可版本化。
3. 每个规则返回标准化 Risk Finding。
4. 规则可组合。
5. 高风险规则可以直接 Deny。
6. 不允许 LLM 直接产生最终风险结果。
7. 支持同步规则和异步数据查询。
8. 数据不足时默认提升风险，而不是忽略。

### 12.2 MVP 风险规则

通用：

1. 单笔金额上限。
2. 每日累计支出。
3. 每个 Agent 预算。
4. 目的地址白名单。
5. 首次地址。
6. 资产白名单。
7. 合约白名单。
8. Token Approval 上限。
9. 禁止无限 Approval。
10. 请求过期。
11. 重放或重复请求。
12. 调用频率异常。
13. 价格偏离。
14. 数据陈旧。
15. 供应商信誉过低。
16. 服务重复购买。
17. Gas 或手续费比例过高。
18. 高风险网络或协议。

当前 Durable Shadow 的 DS-029 实现把“每日累计支出”严格定义为：同一
Organization + Agent 在 `[evaluation_time - window, evaluation_time]` 内，且不晚于
Evaluation Context 所绑定 Audit Sequence 的 `DecisionRecorded(PERMIT)` 金额，加上
当前 Intent 金额。历史查询显式记录 `PERMITTED` Accounting Boundary、估值资产、
窗口、当前 Intent 排除条件与 Repository Snapshot；PostgreSQL 只使用 `NUMERIC`
固定点按资产聚合，并限制最多 256 个资产组。跨资产仅接受同 Organization、精确
Base/Quote Scope、Fresh 且已验证的直接 `ATF_ENRICHED` `ASSET_QUOTE`；缺失、歧义、
遗留资产缺绑定、溢出或精度损失均产生 High/Critical Finding，不得 Permit。

DS-030 把“首次目标地址”严格定义为：在同一 Organization、同一 Payment Profile
ID/Version、同一 Normalizer ID/Version 下，截至 Evaluation Context 所绑定 Audit
Sequence 与 Evaluation Time，没有更早的 `DecisionRecorded(PERMIT)` 使用相同的
Normalized Destination。比较范围有意为 Organization-wide，而非单 Agent；版本 1
Normalizer 接受 `eip155:<decimal-chain-id>:0x<40 hex>` 的 legacy lowercase 或有效
EIP-55 checksum-case 写法，并派生 lowercase Key，但不改写签名 Intent。无历史 Permit
产生 `FIRST_TIME_DESTINATION`；无效 checksum、非规范 Chain Reference 或不支持
Namespace 产生 `FIRST_DESTINATION_NORMALIZATION_FAILED`。默认 High Finding 导致
Review；Critical 配置导致 Deny。先前 DENY 和其他 Organization 均不得建立 familiarity。

DS-031 把“接受请求频率”严格定义为：在
`[evaluation_time - window, evaluation_time]` 内、不晚于 Evaluation Context 所绑定
Audit Sequence、且具有同一 Organization + Agent + Profile ID/Version + Action
Category/Operation 的 `IntentReceived` 数量。它是 `REQUESTED` 业务生命周期规则，
不是 HTTP/IP 限流；默认 Rule Set v1.3.0 的闭合配置为 `AGENT` Subject、`PROFILE`
Action Scope、60 秒最多 10 次和 High Missing-data Finding。超过最大值产生
`REQUEST_FREQUENCY_EXCEEDED`；缺少可信 Profile/Action Binding 的遗留事件单独计数并
产生 `REQUEST_FREQUENCY_SCOPE_UNRESOLVED`，不得静默漏算。Admission 在认证成功的
同一事务写入 Binding；组织 Audit Head 的串行 Append 使并发接受请求在后续 Snapshot
中可见；完成态幂等重试直接返回原 Decision，不新增业务事件。

交易：

1. 最大名义仓位。
2. 最大杠杆。
3. 最大滑点。
4. 最大日亏损。
5. 只允许减仓。
6. 最大场所集中度。
7. 最大单资产敞口。
8. 最小清算距离。
9. 资金费率阈值。
10. 策略状态检查。
11. 账户状态检查。
12. 订单频率上限。

Treasury：

1. 每日资金调度上限。
2. 目标账户归属验证。
3. 资金用途验证。
4. 稳定币集中度。
5. 单一链集中度。
6. 新协议调拨审批。
7. 非工作时间审批。
8. 提现与交易权限隔离。

### 12.3 市场数据源与新鲜度

1. MVP 阶段价格与资金费率数据默认来自 Adapter 自带的场所行情接口（如 Hyperliquid 自身订单簿），不依赖第三方聚合 Oracle，降低 Oracle 操纵面。
2. 每条外部数据必须标注 `source`、`fetched_at`、`staleness_ms`；超过规则配置的新鲜度阈值时，规则按 12.1.8 默认提升风险而非跳过判断。
3. 如接入第三方价格源（Chainlink、Pyth 等），必须支持多源交叉校验，单一数据源不得单独触发 PERMIT。
4. Vendor 历史价格中位数（如 `historical_vendor_median`）由 Risk Engine 自身滚动计算并持久化，不依赖外部第三方评分服务。

### 12.4 自定义与合规扩展点

1. Risk Engine 提供规则插件接口，允许接入组织自定义规则，包括制裁名单筛查、内部黑名单、第三方合规服务。
2. 合规类规则与金融风险规则使用同一 Risk Finding 格式，可直接触发 REVIEW 或 DENY。
3. ATF 核心不内置任何合规数据源，相关数据源的准确性与时效性由接入方负责（对应非目标 5.16）。

### 12.5 Evaluation Context

任何影响 Decision 的代码不得直接读取系统当前时间、随机数、未版本化外部数据、未记录的环境变量或隐式数据库状态。Gateway 必须在评估开始时构建不可变 `EvaluationContext`，至少包含：

1. `evaluation_id`、`evaluation_time`、`environment`。
2. Policy Bundle Version/Hash。
3. Risk Rule Set Version/Hash。
4. Context Snapshot ID/Hash。
5. Market Data Snapshot ID、Simulation Block Number、Simulator/Adapter Version（适用时）。
6. External Evidence 引用与 Hash。

Risk Rules 只读取该 Context 和显式 Repository Snapshot。Original Replay 使用原版本和原 Snapshot；Counterfactual Replay 使用新版本创建新的 Evaluation，不能修改原记录。

### 12.6 Context Provenance

DS-022 已实现本节的类型与当前 Risk 消费边界：
`schemas/evidence.schema.json` 与 `atf-core::EvidenceEnvelope` 封闭 Source、
Kind、Source ID、Observed/Expires、无 JSON Number 的 Value、Confidence、
Canonical Hash 和可选 Ed25519 Proof；`EvidenceTrustPolicy` 以精确
Source/Source ID/Kind Allowlist 与同一次 Evaluation Time 计算 Freshness，只有
全部通过才产生 `VerifiedEvidence`。Agent Context 中的 Price、Balance、
Position、Leverage、Spend、Protocol Risk、Reputation、Freshness 与 Simulation
Key 均不构成权威输入；当前 Vendor Median 只接受精确 Scope 的
`ATF_ENRICHED` Evidence。DS-023 已在评估前持久化精确 Verified Evidence、
Trust Policy Identity、Agent Context Hash 与 Evaluation Time；DS-024 已让
Policy/Risk 只从该 Context 取得时间、可信 Evidence 与版本身份，并验证精确
Audit Prefix。启用 Vendor Rule 时缺失可信数据必须产生 Finding。生产 Enricher
仍属于后续工作。

Decision-affecting Context 分为 `AGENT_PROVIDED`、`ATF_ENRICHED`、`ORACLE_PROVIDED`、`ADAPTER_PROVIDED`、`ADMIN_PROVIDED` 和 `SIGNED_EXTERNAL_EVIDENCE`。每个值必须记录 `source`、`source_id`、`observed_at`、`expires_at`、`evidence_hash`、可选签名、置信度与 Freshness Status。

Agent 自己提交的价格、余额、仓位、杠杆、累计支出、协议风险、地址信誉、市场数据新鲜度或模拟结果不得直接影响最终 Permit。缺失、过期或来源不可信时只能产生 `DENY`、`REVIEW` 或 `INSUFFICIENT_DATA`，不得静默套用允许性的默认值。

---

## 13. Transaction Simulator

当前 `atf-simulator` 仅为 Scaffold；本章全部是 Phase 3 目标要求。

### 13.1 目标

在签名前预测交易的主要状态变化。

### 13.2 EVM 模拟

支持：

1. eth_call
2. estimateGas
3. Token Balance Diff
4. Allowance Diff
5. Internal Call 检查
6. Revert Reason
7. Value Transfer
8. 合约代码存在性
9. 可疑 Delegatecall 或代理升级提示

### 13.3 Safe 模拟

支持：

1. Safe Transaction 解析
2. Module 或 Guard 调用识别
3. 批量交易展开
4. Token Approval 检查
5. 交易失败预测
6. 目标合约风险提示

### 13.4 Hyperliquid 模拟

支持：

1. 订单名义价值。
2. 预估成交价格。
3. 预估滑点。
4. 仓位变化。
5. 预估杠杆。
6. 清算距离变化。
7. Reduce-only 验证。
8. 账户最大风险变化。

### 13.5 x402 模拟

支持：

1. 付款金额。
2. 网络与资产。
3. 资源 ID 绑定。
4. Nonce 和重放检查。
5. 请求与付款证明绑定。
6. 幂等键。
7. 服务交付验证要求。
8. 重复采购检查。

### 13.6 模拟失败与降级策略

1. Simulator 超时、依赖不可用或 Adapter 不支持该 Action 的模拟能力时，按 10.1 合并规则强制进入 REVIEW，禁止直接 PERMIT。
2. 若 Simulation 明确返回"必定 Revert"或"账户状态非法"，直接 DENY，不受 Policy PERMIT 结果影响。
3. Enforce Mode 下，若配置要求"必须模拟成功才可执行"（高风险 Adapter 默认开启），模拟不可用则整个请求 Fail Closed 为 DENY，而非降级为 Shadow 评估。
4. Shadow Mode 下模拟失败仅记录 `SimulationCompleted` 事件并标记 `status: unavailable`，不影响原交易路径。

---

## 14. Approval Engine

当前 `atf-approval` 和 Approval Service 仅为 Scaffold；`REVIEW` 尚无可完成审批的运行路径。

### 14.1 审批规则

1. 单人审批。
2. 多人审批。
3. 角色审批。
4. 金额阈值审批。
5. 首次地址审批。
6. 首次供应商审批。
7. 高风险协议审批。
8. 时间窗口审批。
9. 临时授权。
10. 一次性授权。

### 14.2 审批安全

1. 审批请求必须绑定 Intent Hash。
2. Intent 修改后原审批失效。
3. 审批有明确过期时间。
4. 审批者身份必须可验证。
5. 不允许同一主体同时发起和完成高风险双人审批。
6. 审批记录不可删除。
7. 审批不得直接包含生产私钥。

### 14.3 审批超时与默认行为

1. 审批请求过期后默认结果为 DENY，不自动转为 PERMIT，也不无限期悬挂。
2. 过期前可配置 Escalate 规则（如 30 分钟未处理自动升级给上一级角色），升级本身生成 Audit 事件。
3. 多人审批中，若已获得部分批准但未达到所需人数即过期，视为整体 DENY，不采纳部分批准。
4. Kill Switch 触发期间，所有待处理审批立即标记为 DENY 并记录触发原因，不允许在 Kill Switch 生效后继续 Approve。
5. 审批过期判定必须使用 ATF 服务端时钟，不信任审批请求中携带的客户端时间戳。

---

## 15. Adapter Framework

当前 Adapter SDK 与所有 Reference Adapter 仅为 Scaffold；不得据此接入真实钱包、交易所或 Secret。

### 15.1 Adapter 职责

每个 Adapter 必须实现：

1. normalize
2. validate
3. simulate
4. execute
5. reconcile
6. health_check
7. supported_actions
8. supported_assets
9. conformance_metadata

### 15.2 首批 Adapter

Hyperliquid Adapter：

1. 永续合约下单。
2. 撤单。
3. Reduce-only。
4. 账户状态查询。
5. 仓位查询。
6. 最大杠杆和清算距离检查。
7. API Wallet 身份绑定。
8. Shadow Mode 订单评估。

Safe Adapter：

1. Safe Transaction 解析。
2. Token 转账。
3. Token Approval。
4. 合约调用。
5. 批量交易展开。
6. Guard 或 Module 集成示例。
7. Shadow Mode。
8. Review Mode。

x402 Adapter：

1. 支付请求解析。
2. 资源与支付绑定。
3. 预算检查。
4. 重复采购检查。
5. 供应商检查。
6. 支付状态。
7. 服务交付记录。
8. Shadow Mode。

### 15.3 后续 Adapter

1. Privy
2. Coinbase CDP
3. Fireblocks
4. Binance
5. Solana Wallet
6. Stripe MPP
7. AWS AgentCore Payments
8. Polymarket
9. Aave
10. Uniswap
11. OpenAI Agents SDK Middleware
12. LangGraph Middleware
13. MCP Middleware

### 15.4 Adapter Manifest 字段

每个 Adapter 必须随代码发布一份 `adapter-manifest.json`（对应 schemas/adapter-manifest.schema.json），供 Conformance Tests 和 Admin API 读取：

```json
{
  "adapter_id": "hyperliquid",
  "adapter_version": "0.3.0",
  "atf_spec_version": "1.0",
  "supported_actions": ["exchange_order"],
  "supported_assets": ["eip155:*"],
  "supports_simulation": true,
  "supports_shadow_mode": true,
  "requires_simulation_before_execute": true,
  "secret_binding": "external_signer",
  "conformance_test_report": "conformance/adapter-tests/hyperliquid-0.3.0.json"
}
```

1. `requires_simulation_before_execute` 为 true 的 Adapter，在 13.6 的降级策略下不允许跳过模拟直接执行。
2. `secret_binding` 必须声明签名密钥的托管方式（如 `external_signer`、`kms_ref`），Adapter 自身不得声明持有明文密钥。
3. Manifest 版本与 Conformance Test 报告不匹配时，`atf adapter test` 必须拒绝将该 Adapter 标记为可用。

---

## 16. Audit Ledger

当前 Gateway 已将 `atf-store` 的 PostgreSQL Append-only Hash Chain 作为唯一 Decision/Audit 路径：每组织独立的 Audit Head/Event 表使用行锁串行 Append，重载时验证 Canonical Bytes/Hash、序列、前驱和 Head，且 Migration 禁止 UPDATE/DELETE/TRUNCATE。DS-006/DS-007 已实现 22 状态转换契约；DS-015/DS-016/DS-018/DS-026/DS-027 扩展到 40 类 `schema_version: 1` 类型化 Payload。Agent/Key 生命周期行指向同事务提交的操作者事件；hashed Nonce 行绑定精确 Key、Intent、Idempotency Reservation、`IdentityVerified` 事件及对应生命周期版本；Operator Subject/Status 与 Organization Role Grant/Revoke 同样绑定原子提交的类型化事件。当前新请求在 Authenticated Admission Transaction 中产生带可选兼容、当前必写 Profile/Action Binding 的 `IntentReceived` 与 `IdentityVerified`，Finalization 产生 `PolicyEvaluated`、`RiskEvaluated`、`SimulationCompleted` 和绑定的 `DecisionRecorded`。DS-028..DS-031 的 `RiskEvaluated` 还保留限界 Duplicate/Daily-spend/First-destination/Request-frequency History Query 及其结果，并要求其 Repository Boundary 与 Evaluation Context 一致。拒绝与冲突重放分别产生组织作用域 `IdentityRejected`/`ReplayDetected`，但不创建 Intent。DS-026 的 Risk 归档产生组织作用域 `RiskRuleSetStored`，成功 Original Replay 产生 Intent 作用域、引用原 Evaluation/Decision 的 `OriginalReplayCompleted`；DS-027 的独立非权威记录产生绑定新 lineage 和所有派生 Hash 的 `CounterfactualReplayCompleted`，三者均不得推动 Lifecycle。DS-012/DS-013 的 Lease/Fencing/Recovery 语义保持不变。DS-032 已实现 Auditor-authorized、Organization-scoped、完整链验证后的限界 Audit Query 与稳定 Cursor。Checkpoint、Retention、独立验证和后台 Recovery Scanner 仍未实现。

### 16.1 目标

保证每个金融行为都能够被追踪、解释和重放。

### 16.2 审计事件

1. IntentReceived
2. IdentityVerified
3. IdentityVerificationSkipped
4. IdentityRejected
5. ContextEnriched
6. PolicyEvaluated
7. RiskEvaluated
8. SimulationCompleted
9. DecisionRecorded
10. ApprovalRequested
11. ApprovalApproved
12. ApprovalRejected
13. ExecutionGrantIssued
14. ExecutionSubmitted
15. ExecutionConfirmed
16. ExecutionFailed
17. SettlementVerified
18. ServiceDelivered
19. ReconciliationFailed
20. BudgetReserved
21. BudgetCommitted
22. BudgetReleased
23. PolicyChanged
24. AgentPaused
25. KillSwitchEnabled
26. KillSwitchDisabled
27. IntentExpired
28. IntentCancelled
29. AgentRegistered
30. AgentStatusChanged
31. IdentityKeyRegistered
32. IdentityKeyRevoked
33. ReplayDetected
34. OperatorRegistered
35. OperatorStatusChanged
36. OperatorRoleGranted
37. OperatorRoleRevoked
38. RiskRuleSetStored
39. OriginalReplayCompleted
40. CounterfactualReplayCompleted

`DecisionRecorded` 必须包含 Canonical Intent Hash、Decision Kind、Decision ID/Hash、组织与 Agent 作用域，以及 Policy/Risk/Context/Simulation 版本引用。事件 Payload 在进入持久化前必须经过对应的版本化 Schema 校验。

### 16.2.1 Intent Lifecycle State Machine

Intent 生命周期至少支持以下状态，并只允许显式定义的单向转换：

```text
RECEIVED
  ├─> IDENTITY_REJECTED (terminal)
  └─> IDENTITY_VERIFIED | IDENTITY_UNVERIFIED
        -> POLICY_EVALUATED
        -> RISK_EVALUATED
        -> SIMULATION_COMPLETED
        -> DECIDED_PERMIT | DECIDED_REVIEW | DECIDED_DENY | DECIDED_ERROR

DECIDED_PERMIT -> APPROVAL_PENDING | EXECUTION_AUTHORIZED
DECIDED_REVIEW -> APPROVAL_PENDING
APPROVAL_PENDING -> APPROVED | REJECTED
APPROVED -> EXECUTION_AUTHORIZED
EXECUTION_AUTHORIZED -> EXECUTION_SUBMITTED
EXECUTION_SUBMITTED -> EXECUTION_CONFIRMED | EXECUTION_FAILED
EXECUTION_CONFIRMED -> SETTLEMENT_VERIFIED | RECONCILIATION_FAILED
```

`IDENTITY_REJECTED`、`DECIDED_DENY`、`DECIDED_ERROR`、`REJECTED`、`EXECUTION_FAILED`、`SETTLEMENT_VERIFIED`、`RECONCILIATION_FAILED`、`EXPIRED` 和 `CANCELLED` 是终止状态。`EXPIRED`/`CANCELLED` 只允许在 `EXECUTION_SUBMITTED` 之前由转换表列明的状态进入。

`NOT_RUN` 是 Risk/Simulation 等模块的带原因 Outcome，不是 Lifecycle State。未实现或因前序拒绝而未运行的模块必须显式记录 `NOT_RUN`，仍通过唯一的阶段事件进入下一状态；它不代表成功，不得绕过安全必需阶段产生执行授权。`IDENTITY_UNVERIFIED` 是历史 Shadow-only 兼容状态，不得被解释为 `IDENTITY_VERIFIED`，不得被当前 Gateway 新建或升级，也不得单独作为 Execution Grant 的依据。DS-016 后的新 Gateway Intent 必须从 `IntentReceived` 原子进入 `IdentityVerified`；身份失败不创建 Intent。权威事件映射、Payload 字段、持久化列、重放和全部转换见 `docs/audit-model.md`。

历史风险规则必须声明统计边界：`REQUESTED`、`PERMITTED`、`EXECUTED` 或 `SETTLED`。例如重复购买在当前 Shadow Mode 统计同组织的 `DecisionRecorded(PERMIT)`；未来可按业务配置升级为 `ExecutionConfirmed` 或 `SettlementVerified`，但不得继续以 `IntentReceived` 代替购买事实。

### 16.3 不可篡改设计

MVP：

1. PostgreSQL Append-only 表。
2. 每个事件包含前一事件 Hash。
3. 定期生成 Merkle Root 或审计检查点。
4. 审计日志只追加，不更新。
5. 管理员也不能静默删除。
6. 链作用域必须明确为每组织独立链或有严格组织索引的全局链；PostgreSQL Persistence 实施前必须通过 ADR 选择并发与恢复策略，禁止由表结构偶然决定。
7. 必须定义接收与完成两个原子事务边界：Intent 与 Idempotency Reservation 同步提交；最终 Decision、`DecisionRecorded` 和 Idempotency Result 同步提交。任何可查询 Decision 都必须有对应 Audit Evidence，不能依赖一个跨外部调用的长事务。DS-012 已实现这两个数据库事务边界及完成结果绑定；DS-013 已将完成态同 Hash 重试翻译为原始 Decision，并在请求到达时通过 Fencing 接管过期工作。后台扫描和可重放的 Context-based Recovery 仍属于后续能力。
8. Enforce Mode 下 Audit 写入失败必须 Fail Closed。当前 Durable Shadow Gateway 同样以 PostgreSQL 为唯一权威，数据库或 Audit 写入失败时返回失败，不得以进程内或本地缓冲伪装成已持久化 Decision；未来离线诊断缓冲只能保存非权威运维信号。

### 16.4 留存策略与合规边界

1. "不可篡改"约束的是事件内容和 Hash 链，不等于永久物理存储；ATF 支持按组织配置留存周期，到期数据整体归档并从 Hash 链中以"归档区块"形式摘要，而非逐条删除或篡改。
2. 涉及个人数据的字段（如审批人姓名、邮箱）应与不可变的交易事实字段分离存储，便于在合规删除请求下做字段级脱敏，同时保留交易 Hash 链完整性。
3. 归档、脱敏操作本身必须生成审计事件并由多人授权，不允许管理员单方面执行。
4. 生产部署必须明确写入自身的留存周期与脱敏策略，ATF 核心不代为承诺满足特定司法辖区的合规要求（对应非目标 5.16）。

---

## 17. Agent Identity

### 17.1 登记字段与状态

每个 Agent 必须登记：

1. agent_id
2. organization_id
3. owner_user_id
4. agent_type
5. model_provider
6. model_name
7. agent_version
8. code_hash
9. deployment_environment
10. allowed_tools
11. allowed_adapters
12. default_budget
13. risk_tier
14. status
15. created_at
16. expires_at

Agent 状态：

1. ACTIVE
2. SHADOW_ONLY
3. PAUSED
4. REVOKED
5. EXPIRED

### 17.2 身份签名机制

1. 每个 Agent 注册时绑定一对非对称密钥（默认 Ed25519），私钥由 Agent 运行环境持有，公钥登记到 `atf-identity`。
2. Agent SDK 对 Domain-separated Identity Envelope 的 Canonical Bytes 签名，而不是只签名无上下文的 Hash 字符串；Gateway 验证后才进入 Context Normalizer，失败直接拒绝且不进入 Policy/Risk。
3. Agent 私钥与执行签名私钥（钱包/交易所侧）必须是两套独立密钥：前者只用于证明"这是哪个 Agent 发起的请求"，后者由 Adapter/Fireblocks/Safe 等托管，ATF 核心进程不持有、不代理执行签名。
4. 支持 `key_id`、公钥激活/失效/撤销时间和有界轮换重叠窗口；轮换事件写入 Audit，过期或撤销 Key 立即失效。
5. 单个私钥泄露的爆炸半径由 `risk_tier`、`default_budget` 和 `allowed_adapters` 限定，即：身份签名验证通过只代表"请求来自该 Agent"，不代表跳过 Policy/Risk 评估。
6. Agent Record 的 `organization_id` 必须与 Envelope 和 Intent 完全一致，防止跨组织重放。
7. Envelope 的 Nonce 必须单次使用并持久化；Audience、Environment、Issued At 和 Expires At 必须由 Gateway 校验。
8. 所有 Identity 成功和失败都写入 Audit，失败原因使用稳定 Error Code 且不得泄露密钥材料。

Identity Envelope 的签名域至少包含：

```text
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
```

DS-014 已在 `atf-identity` Library 实现上述 Canonical Envelope、显式
Verification Time、五分钟窗口、Organization/Agent/Intent/Audience/Environment
绑定、精确 `key_id` 选择、严格 Ed25519 验证、稳定错误码与公开固定向量；不再
存在 Raw Intent Hash 或“尝试任意 Key”的回退。DS-015 已将 Agent Record 与精确
Ed25519 Public Key 的激活、过期、状态和不可逆撤销写入 PostgreSQL；Canonical
Record/Bytes/Hash、Lifecycle Version 与最后操作者 Audit Event 必须一致，变更在
同一事务提交。离线 `atf identity` 命令不接收、生成或输出私钥。DS-016 已要求
Gateway 从受信启动配置读取 Audience/Environment，以严格 detached Header 接收
Canonical Envelope 与签名，在同一短事务中重验当前 Agent/Key、消费 hashed Nonce、
绑定 Idempotency/Intent 并提交类型化 Identity Evidence。原始 Nonce、Envelope、
签名与私钥不得持久化或进入响应/日志；跨组织作用域、重启重放和篡改必须 Fail Closed。

### 17.3 Admin API 权限模型

1. `atf-admin-api` 自身的操作（注册/暂停 Agent、发布 Policy Bundle、调整 Budget、管理审批角色）需要独立的 RBAC，区别于 Agent 身份体系。
2. 最小角色集：`org_admin`（管理 Agent 与 Budget）、`policy_author`（发布 Policy，不能执行审批）、`approver`（仅可处理审批，不能改 Policy）、`auditor`（只读）。
3. 高风险 Admin 操作（发布生产 Policy、调整 Kill Switch、提升 Agent 权限）需要与 14.1 类似的多人审批，不允许单一 `org_admin` 账号直接生效。
4. 所有 Admin API 调用生成审计事件（对应 16.2 的 `PolicyChanged`、`AgentPaused` 等），且记录操作者角色与身份，不允许匿名或共享账号操作。

DS-017 已接受 ADR-0003，进一步收敛参考实现：Gateway 作为 OAuth Resource
Server，只接受一个由固定 HTTPS Issuer 签发、面向固定 ATF Audience、符合 RFC
9068 的短期非对称签名 JWT Access Token，并由 Gateway 自行验证；ID Token、Cookie、
静态 API Key、密码、Query Credential 与反向代理注入的身份 Header 均不构成操作者
认证。JWT 只证明外部 `(issuer, sub)`，PostgreSQL 必须在每次请求中把该 Subject 的
Fingerprint 映射到唯一内部 Operator，并重新加载当前 Organization/Role 绑定；Token
中的 Email、Group、Scope、Organization 或 Role Claim 均不能单独授予 ATF 权限。

Agent Principal 与 Operator Principal 为互斥类型：Agent Envelope 只能提交绑定的
Intent，Operator Token 只能进入明确的 Admin/Read Role Matrix，两者不得互相回退。
Accepted ADR-0004 另定义与二者均互斥的 `OperationsPrincipal`：它只可在独立
Unix-socket Metrics Router 上由可信 mTLS edge 的规范断言构造，唯一 Capability 为
`METRICS_READ`，不携带 Organization，也不能进入 Intent、Decision、Audit、Policy、
Bootstrap 或 Admin 路由。业务 Router 不识别 Operations 断言。
Organization Header/Path/Body 只是 Selector，必须同时匹配 Principal 的持久化 Role
Binding 与资源所属 Organization。跨组织、资源不存在、无读取角色的 Decision 查询
返回相同的非枚举 404。操作者停用或 Role 移除在下一次请求立即生效；外部 IdP 撤销
已签发自包含 Token 的窗口由短期 TTL 限制，事故处置必须同时支持 ATF 本地停用。

DS-018 已实现上述应用边界：migration 0006 与 `atf-store` 提供 Operator Subject
Fingerprint、状态和显式 Organization Role 的持久化/重验；离线 `atf operator`
命令提交类型化 Audit 且不保存原始 Subject；Gateway 只从配置的 HTTPS
Discovery/JWKS 验证短期非对称签名 `at+jwt`，并在每次 Decision/Audit GET 重新加载本地状态
与 `auditor`/`org_admin` Role。Agent 与 Operator Principal 类型互斥，跨组织、资源
不存在和无读取 Role 统一返回非枚举 404；本地停用/撤销在下一请求生效。

DS-020 增加首个 Admin Mutation 子集：Policy Activate/Rollback Route 使用同一 JWT/JWKS
边界，并要求当前 Organization 的 `policy_author` 或 `org_admin`；Store 在锁定 Mutation
Transaction 内重新验证 Operator/Role 与 Audit Chain，再把 Active Pointer 和完整
`PolicyChanged` 证据原子提交。Policy 安装仍是持有数据库管理凭据的离线部署操作；
生产 Policy 的多人审批尚未实现，因此本实现仍不满足第 3 条目标控制。

共享部署仍要求可信 HTTPS Ingress，Ingress 到 Gateway 的链路同样必须防窃听、注入和
重放；Gateway 不把 TLS 终止或代理 Header 当作身份委托。DS-034 仍负责具体入口、
通用 Header/Body/Timeout/Rate Limit 与部署测试。生产 Policy、Kill Switch、Approval
或 Enforce 权限开放前，还必须重新评估 mTLS/DPoP Sender-Constrained Token 与多人
审批边界。

---

## 18. 安全架构

### 18.1 安全原则

1. Fail Closed。
2. 最小权限。
3. Agent 与签名权限隔离。
4. Policy 与 Risk 决策可重放。
5. Intent 与执行请求强绑定。
6. 所有外部输入不可信。
7. 所有 Adapter 独立隔离。
8. 核心内核不依赖 LLM。
9. Secret 不写入日志。
10. 生产密钥不进入 ATF 核心进程。
11. 决策输入必须有来源、时间、版本和 Hash；无法证明来源的数据不能产生 Permit。
12. Idempotency Key、Nonce 和 Hash 字段本身不等于已经实现幂等、Replay Protection 或不可篡改。
13. Execution 是最后开放的能力；Durable Shadow Mode 未完成和复审前禁止接入真实资金。

### 18.2 威胁模型

必须覆盖：

1. Prompt Injection 导致 Agent 越权交易。
2. Agent 工具调用参数被篡改。
3. Intent 和最终交易不一致。
4. Policy Bypass。
5. Approval Replay。
6. Payment Proof Replay。
7. Nonce 重放。
8. TOCTOU。
9. 恶意 Adapter。
10. 供应链依赖攻击。
11. 管理员权限滥用。
12. 审计日志删除。
13. 价格 Oracle 操纵。
14. 交易所 API Key 泄露。
15. 无限 Token Approval。
16. 恶意合约调用。
17. 支付完成但服务未交付。
18. 重复采购。
19. 多 Agent 串谋绕过预算。
20. 高频小额拆单绕过单笔限额。

### 18.3 Secret 管理

ATF 只保存 Secret Reference，不保存明文 Secret。

支持：

1. AWS KMS
2. GCP KMS
3. HashiCorp Vault
4. Local Development Keystore
5. Fireblocks 或 Privy 签名接口
6. Safe 多签

---

## 19. 技术架构

### 19.1 目标核心技术栈

语言：

1. Rust stable
2. TypeScript SDK
3. Python SDK

Rust 主要组件：

1. Tokio
2. Axum
3. Serde
4. Cedar Policy
5. SQLx
6. Tracing
7. OpenTelemetry
8. Reqwest
9. Rustls
10. Thiserror / anyhow
11. Tower
12. Proptest
13. Cargo Fuzz

基础设施：

1. PostgreSQL
2. Redis，可选
3. NATS JetStream，可选
4. OpenTelemetry Collector
5. Prometheus
6. Grafana
7. Docker Compose

### 19.2 目标架构组件

1. atf-gateway
2. atf-identity
3. atf-intent
4. atf-policy
5. atf-risk
6. atf-simulator
7. atf-approval
8. atf-adapters
9. atf-audit
10. atf-reconciliation
11. atf-cli
12. atf-admin-api

### 19.3 高可用与容灾

1. §26 要求"Audit 写入失败时阻止 Enforce Mode 执行"，这意味着 Audit 存储（PostgreSQL）是 Enforce Mode 的可用性瓶颈，必须显式设计而非默认单实例。
2. 生产参考部署建议 PostgreSQL 采用主从复制（如 Patroni/RDS Multi-AZ），Gateway 侧对 Audit 写入使用同步提交到主节点，只有主节点确认写入后才返回 Decision。
3. Shadow Mode 不接管签名权限，但 Durable Shadow 的可查询 Decision/Audit 仍必须以 PostgreSQL 成功提交为前提；写入失败时可以继续计算非权威诊断结果，但 API 必须 Fail Closed，且不得把内存/本地缓冲结果标记为已持久化 Decision。
4. 单机部署（30.2）明确不提供 HA 保证，需在文档中标注"仅适合个人/小团队，无 Audit 高可用"。
5. 备份策略：PostgreSQL 定期快照 + WAL 归档，Merkle 检查点（16.3）额外冗余存储于对象存储，用于在数据库损坏后独立验证审计链完整性。

### 19.4 当前实现边界

PRD v1.4 不再把目标目录结构等同于完成状态。当前模块分类如下：

1. `IMPLEMENTED_AND_WIRED`：`atf-core` 基础原语、DS-022 Provenance Evidence、DS-023 Immutable Evaluation Context、DS-028..DS-031 四类闭合 Risk History Snapshot、DS-032 Verified Audit Query、DS-033 Metrics/Tracing/Redaction、ADR-0004 的独立 mTLS Operations Principal 与 UDS Metrics Router、Policy Conformance Harness、DS-014..DS-016 的 Agent Identity Admission 子集、DS-018 的 Operator Decision-read RBAC、DS-019/DS-020 的签名 Policy Bundle 身份与持久化激活/回滚，以及 DS-021 的 Versioned Risk Rule Set；Gateway 在 Policy/Risk 前使用当前持久化精确 Key 验证 Envelope 并原子消费 hashed Nonce，每次评估重新加载签名 Active Policy Pointer，并在独立短事务持久化同一次 Evaluation Time、Policy/Risk Identity、Evidence/Trust、Agent Context Hash、Audit History Prefix 与显式不可用输入；Risk 不再把 Agent Vendor Median 当作可信输入，Decision GET、Audit GET 与 Policy Admin Route 均验证配置的 JWT/JWKS 后重新加载持久化 Operator/Role。
2. `PARTIALLY_IMPLEMENTED`：`atf-intent`、`atf-policy`、`atf-risk`、`atf-audit`、`atf-decision`、CLI、Gateway；各自的已实现/缺失边界见 `docs/architecture.md`。
3. `PARTIALLY_IMPLEMENTED`：`atf-store` 的 Schema、Migration 0001..0014、Audit Append/Restart Verification 与 DS-032 Verified Query、Admission/Context/Finalization Repository、事务 Lifecycle State/Version/Event Pointer、类型化事件重放、原子 Idempotency Reservation/Result、Evaluator Lease/Renew/Reclaim、Generation Fencing、Agent/Key Lifecycle、Operator/Role Lifecycle、签名 Policy/Risk Archive、不可变 Evaluation Context、四类限界 Risk History Query 与 Original/Counterfactual Replay 已接入 Gateway/CLI；Agent/Key 与 Operator/Role 生命周期、Policy/Risk 安装仍由离线 CLI 预配，但 Gateway 已在每次对应请求中重验。后台 Recovery Scanner、Audit Checkpoint/Retention 尚未实现。
4. `IMPLEMENTED_AND_WIRED`：ADR-0003 的 Operator JWT/JWKS、持久化 Organization Role、typed Principal、即时本地撤销与非枚举 Decision-read 边界已由 DS-018 实现；DS-020 增加 `policy_author`/`org_admin` 激活与回滚路由，并在 Store 事务内二次授权；DS-032 以同一原则保护两个 Audit GET，并在 Store 快照中重验 `auditor`/`org_admin`。共享网络 TLS/Proxy/Rate Limit 部署基线仍归 DS-034，其他 Admin 路由仍需单独能力矩阵。
5. `SCAFFOLD_ONLY`：Simulator、Approval、Reconciliation、Adapters 及对应服务/Conformance/Deploy/Fuzz 目录。
6. `MISSING`：除 Policy 激活/回滚外的 Admin API、SDK、生产 Enricher，以及除已落地 `intent-spec.md`/`identity-envelope.md`/`api.md`/`policy-model.md`/`risk-rule-sets.md`/`context-provenance.md`/`evaluation-context.md`/`operations.md` 外的大部分独立 Specification。

详细证据以 `docs/architecture.md` 与 `docs/audit-gap-matrix.md` 为准。任何功能只有在 Workspace Membership、真实调用路径、测试和文档状态同时成立时才能标记为 Implemented and Wired。

---

## 20. 目标 Rust Workspace 目录

```text
agentic-transaction-firewall/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── LICENSE
├── NOTICE
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── CHANGELOG.md
├── deny.toml
├── .editorconfig
├── .gitignore
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── security.yml
│   │   ├── release.yml
│   │   └── docs.yml
│   ├── ISSUE_TEMPLATE/
│   └── pull_request_template.md
├── crates/
│   ├── atf-core/
│   ├── atf-intent/
│   ├── atf-identity/
│   ├── atf-policy/
│   ├── atf-risk/
│   ├── atf-decision/
│   ├── atf-audit/
│   ├── atf-simulator/
│   ├── atf-approval/
│   ├── atf-reconciliation/
│   ├── atf-adapter-sdk/
│   ├── atf-adapter-evm/
│   ├── atf-adapter-safe/
│   ├── atf-adapter-x402/
│   └── atf-adapter-hyperliquid/
├── services/
│   ├── gateway/
│   ├── policy-server/
│   ├── approval-server/
│   ├── audit-server/
│   └── reconciliation-worker/
├── cli/
│   └── atf-cli/
├── sdk/
│   ├── typescript/
│   └── python/
├── schemas/
│   ├── transaction-intent.schema.json
│   ├── decision.schema.json
│   ├── audit-event.schema.json
│   └── adapter-manifest.schema.json
├── policies/
│   ├── examples/
│   ├── trading/
│   ├── treasury/
│   └── agent-payments/
├── examples/
│   ├── hyperliquid-trading-agent/
│   ├── safe-treasury-agent/
│   └── x402-research-agent/
├── conformance/
│   ├── adapter-tests/
│   ├── policy-tests/
│   └── replay-tests/
├── fuzz/
├── migrations/
├── deploy/
│   ├── docker/
│   ├── docker-compose.yml
│   ├── kubernetes/
│   └── helm/
├── docs/
│   ├── PRD.md
│   ├── architecture.md
│   ├── threat-model.md
│   ├── policy-model.md
│   ├── intent-spec.md
│   ├── adapter-spec.md
│   ├── audit-model.md
│   ├── quickstart.md
│   └── roadmap.md
└── rfcs/
    ├── 0001-transaction-intent.md
    ├── 0002-decision-model.md
    └── 0003-adapter-interface.md
```

---

## 21. CLI 需求

```bash
atf init
atf serve
atf validate-intent intent.json
atf evaluate intent.json
atf simulate intent.json
atf shadow intent.json
atf policy validate policies/
atf policy test
atf adapter list
atf adapter test hyperliquid
atf audit show <intent-id>
atf replay <intent-id>
atf kill-switch enable
atf kill-switch disable
```

当前已实现 `validate-intent`、`evaluate`、`policy test/install/activate/rollback`、离线 Identity/Operator 生命周期命令、`risk install` 和 `replay original`。其余命令是目标接口，必须在对应持久化/Simulator/Audit/Replay/Kill Switch 能力真实存在后才加入，不能返回伪成功。

MVP 必须实现：

1. init
2. serve
3. validate-intent
4. evaluate
5. shadow
6. policy validate
7. policy test
8. audit show
9. replay

---

## 22. API 需求

当前已实现：

1. POST /v1/intents
2. GET /v1/intents/{intent_id}/decision
3. GET /v1/audit/events
4. GET /v1/audit/intents/{intent_id}
5. POST /v1/policy-bundles/{bundle_id}/activate
6. POST /v1/policy-bundles/{bundle_id}/rollback
7. GET /metrics（仅独立 mTLS Operations Surface；业务 Listener 返回 404）
8. GET /healthz
9. GET /readyz

当前实现要求启动前设置 `DATABASE_URL`、执行 Migration 并显式 Provision
Organization、Operator/Role，并配置可信 HTTPS Operator Issuer、Discovery、JWKS、
Audience 和非对称 Algorithm Allowlist。GET Decision 必须携带一个 RFC 9068 Bearer
Token 与规范 `X-ATF-Organization-ID` Selector；Gateway 自行验证 Token 后，以外部
Subject Fingerprint 加载当前内部 Operator，并要求所选 Organization 的 `auditor` 或
`org_admin` Role。Token 中的 Organization/Role/Email Claim 和 Selector 本身不授权。

除 `/healthz`、`/readyz` 外，每个请求必须在其物理隔离的 Surface 上恰好形成
Agent Principal、Operator Principal 或 Metrics-only Operations Principal：POST 只接受 Agent Envelope，Decision/Audit GET 与 Policy Mutation 只接受 Operator Token，`GET /metrics` 只接受独立 mTLS edge 在受保护 Unix Socket 上形成的 `OperationsPrincipal(METRICS_READ)`，类型错配
返回统一安全 401。缺失、无效、未映射或已停用 Credential 不暴露细节；资源不存在、
跨租户或无读取角色统一返回对应路由的非枚举 404。原始 Token、Subject、IdP
Diagnostic、外部 PII 与 Role Membership 不得进入 Error、Log、Metric、Trace 或 Audit
Payload。`/healthz` 仅表达进程存活；`/readyz` 同时要求数据库 Schema、配置的签名活动 Policy 与 JWKS 新鲜可用。DS-034 已为每条
Route 加入有限 Body/Header、全请求/评估超时与来源/已验证主体限流；默认只监听回环，
非回环监听必须显式声明可信 Proxy 已终止 TLS，且转发 Header 不构成来源或权限。
共享网络部署仍须由入口完成 TLS、直连端口隔离、Header 解析/握手超时和跨实例限流。

DS-011 当前错误契约：业务 Handler、未知路由、Method Not Allowed 和 Store
失败统一返回顶层 `{code,message,request_id,details}` JSON；`details` 永远是
数组，只能包含服务端固定的 Semantic/Profile Code 与 Field。每个响应携带
服务端生成的 `X-ATF-Request-ID`，调用方同名 Header 不被信任。错误响应不得
复制原始请求、JSON Schema Diagnostics、SQL/Database URL、Policy 文本、Key
Material 或内部错误字符串。`/healthz` 与 `/readyz` 为编排系统保留最小文本
Body，但仍返回 Request ID。稳定 Code/Status 和 Validation Ordering 的规范见
`docs/api.md`。

DS-012/DS-013 当前幂等错误契约：同组织、同 Idempotency Key 绑定不同 Canonical
Intent Hash 返回 `409 IDEMPOTENCY_CONFLICT`；同 Hash 且 Reservation 仍为
`IN_PROGRESS` 且租约仍活动（原 Evaluator 或 Recovery Evaluator）时返回
`409 IDEMPOTENCY_IN_PROGRESS`。不同 Hash 与活动租约都必须在 Policy/Risk 前
终止。完成态同 Hash 请求读取完整验证后的原 Decision，且不得新增
Evaluation/Decision/Audit；过期租约由数据库条件更新接管，在 Context Snapshot
缺失时只允许产生 `Decision(ERROR)`。该恢复由重试请求触发，不代表后台扫描。

Durable Shadow Mode 必须补充：

1. POST /v1/shadow/evaluate
2. POST /v1/replays
3. GET /v1/replays/{evaluation_id}
4. GET /metrics（已由独立 mTLS Operations Surface 实现；不属于业务 Router）

后续 Review/Enforce Mode 目标接口：

1. POST /v1/approvals
2. POST /v1/approvals/{approval_id}/approve
3. POST /v1/approvals/{approval_id}/reject
4. POST /v1/intents/{intent_id}/execute

执行接口不仅默认关闭，而且在 Phase 4 Gate 前不得编译或注册到生产 Router。所有业务接口必须具备 Authentication、Organization Isolation、RBAC、Rate Limit、Request Size Limit、Timeout、Idempotency、Structured Error Code、Correlation/Trace ID、Audit 和 Safe Logging。

---

## 23. SDK 需求

TypeScript 与 Python SDK 当前尚未实现；目标 SDK 提供：

1. ATF Client。
2. Transaction Intent Builder。
3. Agent Identity Header。
4. Idempotency Key。
5. Shadow Evaluation。
6. Approval Polling。
7. Decision Error 类型。
8. Middleware 接口。
9. MCP 示例。
10. Agent Framework 示例。

SDK 不包含生产私钥。

---

## 24. 三个参考场景

### 24.1 Hyperliquid Trading Agent

Policy：

1. 只能交易 BTC 和 ETH。
2. 最大杠杆 3 倍。
3. 单笔名义金额不超过 50,000 USDC。
4. 最大滑点 20 bps。
5. 日亏损超过 3% 后只允许减仓。
6. 不允许提现。
7. 市场数据超过 5 秒未更新时禁止新增仓位。
8. Agent 被暂停后拒绝全部订单。

### 24.2 Safe Treasury Agent

Policy：

1. 只允许向白名单供应商付款。
2. 首次地址付款必须审批。
3. 每日累计支出不超过 25,000 USDC。
4. 禁止无限 Token Approval。
5. 未登记合约调用必须审批。
6. 10,000 USDC 以上需要双人审批。
7. 非工作时间付款需要审批。

### 24.3 x402 Research Agent

Policy：

1. 每个任务预算不超过 20 USDC。
2. 同一数据集 24 小时内不得重复购买。
3. 单供应商占任务预算不超过 50%。
4. 价格超过 30 日中位数 30% 时审批。
5. 新供应商首次付款需要审批。
6. 支付成功但服务未交付时进入异常记录。
7. 请求必须绑定 resource_id 和 task_id。

---

## 25. 可观测性

DS-033 已将 Gateway 日志切换为 JSON Request Span，并增加 Prometheus `/metrics`。当前实现使用闭合 Route Template、Method、Status Class、Decision/Module Outcome、Severity、Idempotency/Freshness/Audit Operation 标签；不使用 Organization、Request、Intent、Policy/Rule ID、Raw URL、Error Text、Credential、Signature 或 Payload 作为标签。Server Request ID 同时出现在 API Response 与 Span，allowlisted Completion Event 在同一 Span 中记录对应 Durable Audit Event ID。Replay 由离线 CLI 执行，因此计数从不可变 typed Replay Audit Evidence 聚合，而不是使用错误的 Gateway 进程本地计数。详细脱敏和运维契约见 `docs/operations.md`。

Durable Shadow Mode 目标指标如下：

1. 请求总数。
2. PERMIT、DENY、REVIEW 比例。
3. Policy Evaluation 延迟。
4. Risk Evaluation 延迟。
5. Simulation 延迟。
6. Adapter 错误率。
7. 审批等待时间。
8. Shadow Mode 发现数量。
9. 重放和重复请求数量。
10. Policy 命中次数。
11. Risk Rule 命中次数。
12. Kill Switch 状态。
13. Reconciliation 失败率。
14. 数据新鲜度。
15. Audit 写入失败。

当前已覆盖 1–4、8–11、14–15，其中 8 以 Risk/Shadow Finding Severity、10 以不暴露 Policy ID 的 Match Count、11 以不暴露 Rule ID/Message 的 Risk Finding Count 表达。DS-035 另提供闭合 `DATABASE`、`ACTIVE_POLICY`、`HISTORY_SNAPSHOT`、`AUDIT`、`LOCK` 依赖失败计数。5–7、12–13 对应的 Simulator、Adapter、Approval、Kill Switch、Reconciliation 组件尚不存在，不输出伪造的零值指标。当前 `/metrics` 只存在于 Accepted ADR-0004 的独立 mTLS Operations Surface，经受保护 UDS 形成 `OperationsPrincipal(METRICS_READ)`；业务 Listener 返回 404。DS-039 已记录单机本地基线和仅用于回归的阈值；生产 SLO/告警仍必须在目标拓扑重新测量。

---

## 26. 性能目标

以下是目标 SLO，不是当前测量结果。MVP 不以高频交易为目标。

目标：

1. 无外部 Simulation 时，P95 决策延迟低于 50 ms。
2. 包含普通外部查询时，P95 低于 500 ms。
3. 包含链上 Simulation 时，按 Adapter 单独报告。
4. 支持每秒至少 100 个 Shadow Evaluation。
5. 单节点可处理至少 1,000 个活跃 Agent 的低频请求。
6. 所有请求幂等。
7. 服务重启后不丢失已接受 Intent。
8. Audit 写入失败时阻止 Enforce Mode 执行。

DS-039 的实测结果与上述目标分开保存于
`conformance/load/ds039-local-baseline.json`：Docker Desktop 单机、Durable
Shadow HTTP、无外部 Simulation、50 个测量请求、并发 4，成功 50、失败
0，P50/P95/P99 分别为 137/178/187 ms，吞吐 28.328 evaluations/s。因此目标
1 和目标 4 **均未达到**。该结果只用于本地回归，不覆盖 1,000 个活跃
Agent、多实例、HA PostgreSQL、共享 Ingress、外部查询、Simulation、Adapter、
Approval、执行或结算。

---

## 27. 开源治理

1. 许可：Apache License 2.0。
2. 贡献：Issue、RFC、Pull Request、Adapter Proposal、Policy Pack、Security Report。
3. 重大变更必须先提交 RFC。
4. Adapter 必须通过 Conformance Tests。
5. Adapter 不得保存明文 Secret。
6. Adapter 必须提供 Mock Server 和 Shadow Mode。
7. 核心规范变更必须保持版本兼容或提供迁移方案。

---

## 28. 测试策略

### 28.1 单元测试

覆盖：

1. Schema Validation。
2. Canonical Serialization。
3. Hash Binding。
4. Policy Evaluation。
5. Risk Rule。
6. Decision Merge。
7. Approval Expiry。
8. Audit Hash Chain。

### 28.2 集成测试

覆盖：

1. Gateway 到 Policy。
2. Policy 到 Risk。
3. Risk 到 Adapter。
4. Approval 流程。
5. Shadow Mode。
6. Enforce Mode。
7. Restart Recovery。
8. Reconciliation。

### 28.3 属性测试

使用 Proptest 检查：

1. 金额不能因序列化变化。
2. Hash 对字段变化敏感。
3. 同一 Intent 的 Canonical Hash 稳定。
4. Policy 结果可重复。
5. 审批不能用于修改后的 Intent。
6. 累计限额不会被拆单绕过。

当前 DS-037 已将第 1 项和 Decision v1 的完整派生 Binding 变化纳入
Proptest：每个替换值都重新计算合法的 `ATF_DECISION_V1` Hash，再要求
权威 Intent/Context 校验拒绝。Intent Canonical Hash 稳定和同 Context
Policy/Risk 可重复性已有普通/Replay 测试；Approval 与更广泛累计限额属性
随对应组件扩展，不能由当前测试代替。

### 28.4 模糊测试

使用 cargo-fuzz：

1. JSON Parser。
2. Intent Normalizer。
3. Adapter Input。
4. Policy Context。
5. Calldata Decoder。
6. Audit Event Parser。

当前 DS-037 已实现第 1 项公共边界并覆盖 Common Semantic/Profile Validation
与 Canonical typed round trip；无效 UTF-8/JSON/Schema/Semantic/Profile 输入
必须返回拒绝而不是 Panic。Intent Normalizer 的当前 typed round trip 只覆盖
已支持 Payment Profile；Adapter、Policy Context、Calldata 与 Audit 独立目标
仍由对应阶段负责。

---

## 29. CI/CD

当前每个 Pull Request 的强制门禁：

1. cargo fmt --check
2. cargo clippy --all-targets --all-features -- -D warnings
3. cargo test
4. cargo deny check -D warnings
5. 已加入 Workspace 的 Schema Tests 与 Policy Tests
6. 两轮真实 PostgreSQL Persistence/Restart/Multi-instance/Contention Suite
7. 固定 Hash Replay、Decision Binding Property 与真实 PostgreSQL Replay Conformance
8. 日期固定 nightly 下的 15 秒 Intent cargo-fuzz Smoke（作业外限 10 分钟）
9. Root/Fuzz `cargo audit`、完整 History/当前 Tree Secret Scan，以及禁止 First-party Unsafe Code 的 Rust SAST；工具与 Action 固定版本，例外必须精确、Owner-bound 且在 90 天内过期

Durable Shadow Mode 完成前必须补充：

1. 受支持的 Docker Compose End-to-end、Backup/Restore 与 Rollback 演练。

对应模块落地后再启用 Adapter Conformance、TypeScript/Python SDK、Container Scanning、SBOM 和 Artifact Signing Gate。PRD 不得声称尚未出现在 Workflow 中的检查已经启用。

Release：

1. Signed Git Tag。
2. Changelog。
3. Container Image。
4. SBOM。
5. Checksums。
6. GitHub Release。

---

## 30. 部署方式

本章描述目标部署拓扑。DS-039 已提供受支持的单机本地 Durable Shadow
Compose，但仍没有 Helm、Kubernetes 或生产部署；本地能力不得外推为
互联网暴露、多租户 HA 或真实资金就绪。

### 30.1 Local Development

Docker Compose：

当前已实现：

1. digest-pinned PostgreSQL 17.10 持久卷与一次性前向 Migration；
2. 锁定 Workspace 构建的非 root ATF Gateway；
3. loopback-only Caddy TLS Edge，数据库和 Gateway 不发布 Host Port；
4. 本地 OIDC Discovery/JWKS、生成的 Agent Key、组织/Operator/Role、两个已签名 Policy 版本和 Risk Rule Set 的幂等 Bootstrap；
5. Submit/Restart/Readiness/Original Replay、Backup/Isolated Restore/Audit Chain、Policy Rollback/Forward 与 bounded Load 脚本。

运行方法和明确的非生产边界见 `docs/quickstart.md`。目标拓扑中的独立
Policy/Approval/Audit Server、Mock Adapter、Prometheus 和 Grafana 尚未实现。

### 30.2 单机部署

适合个人和小团队：

1. 单一 Rust Binary 或少量服务。
2. PostgreSQL。
3. 本地 Policy Bundle。
4. 外部 KMS 或钱包。

### 30.3 Kubernetes

后续支持：

1. Helm Chart。
2. 独立 Adapter Workers。
3. Horizontal Scaling。
4. Network Policy。
5. Pod Security。
6. Secret Store CSI。
7. OpenTelemetry。

---

## 31. 分阶段路线图与 Release Gate

### Phase 0：Repository Foundation（完成）

Workspace、基础 CI、许可证、贡献与安全文档、PRD/Architecture/Threat Model 初稿和目录骨架已建立。

### Phase 1：Intent、Policy 与基础 Decision（完成）

Canonical Intent/Hash、基础 Cedar Policy、Policy Conformance、基础 Risk、Policy/Risk Decision Merge、内存 Audit Hash Chain、Identity Library、CLI 和 Shadow Gateway 已实现。部分模块仍不完整，完成状态以第 0 章和 Architecture 为准。

### Phase 2：Durable Shadow Mode（当前）

按以下顺序一次交付一个可验证的垂直功能：

1. **P0.1 PostgreSQL Persistence（基础能力已完成）**：持久化 Intent、Evaluation、Decision、Audit，已证明 Final Decision 的 Restart/Second-instance Recovery 与并发 Append；DS-013 已让重试请求以 Fencing 接管未完成 Evaluation 并记录限制性 `Decision(ERROR)`，基于持久化 Evaluation Context 的确定性重算恢复仍属于后续工作。
2. **P0.2 Lifecycle State Machine（已完成当前 Shadow 边界）**：DS-006/DS-007 已定义并穷举验证合法状态转换与类型化事件，完成 PostgreSQL 事务持久化、预期版本并发控制、事件指针和读取重放；DS-016 已让当前 Gateway 新请求只通过可验证 `IDENTITY_VERIFIED` 分支，`IDENTITY_UNVERIFIED` 仅保留为不可升级的历史兼容事实。
3. **P0.3 DecisionRecorded（已完成当前 Decision v1 边界）**：已完成事件、
   `PERMIT` 历史语义及 DS-025 的闭合 Schema/完整 Binding；未来 Simulator/
   Approval 扩展必须发布新版本，不得弱化 v1。
4. **P0.4 Idempotency & Replay Protection（已完成）**：DS-012/DS-013 已实现不同 Hash 的稳定 409、同 Hash 活动请求的稳定 409、单 Evaluator 租约/阶段 Heartbeat/接管/Fencing、完成 Result 与 Decision/Audit 的原子绑定和不可变约束、完成态精确重试，以及请求驱动的 Fail-Closed Recovery；DS-016 进一步加入 PostgreSQL 权威 hashed Nonce 原子消费、精确重试、冲突并发单赢家和 `ReplayDetected`。
5. **P0.5 Identity Gateway Wiring（已完成）**：DS-014/DS-015 的 Canonical Domain-separated Envelope、精确 Key 选择、Key Lifecycle 与离线预配已由 DS-016 接入 Policy/Risk 前 Gateway Admission；拒绝/replay 有类型化证据且不能创建 Intent。
   **Operator Read RBAC（已完成）**：DS-017 接受 ADR-0003，DS-018 以 migration 0006、离线 Operator/Role Lifecycle、配置的 JWT/JWKS 验证、typed Principal 和每请求持久化 Role 重验保护 Decision GET；DS-032 把同一边界扩展到 Audit GET，并在 Store Snapshot 中二次授权。跨组织、缺失资源和无读取角色统一使用对应路由的非枚举 404。
   **Risk Rule Set Versioning（已完成）**：DS-021 以闭合 Artifact 与
   Public Schema 绑定 Engine Compatibility、所有决策配置、Missing-data
   Behavior 和 Lifecycle Accounting Boundary，Risk Result/Evidence 返回精确
   Version/Hash。
6. **P0.6 EvaluationContext（已完成）**：DS-023 已在 Policy/Risk 前将时间、版本、Snapshot、Evidence/Trust、History 与显式不可用状态写入不可变 Canonical Context，并由 `ContextEnriched` 与最终 Evaluation Hash 绑定；DS-024 已移除 Evaluator 的 Wall-clock 与独立特权输入入口，校验 Intent/Profile/Artifact/History 绑定并保证相同 Snapshot 的模块输出字节一致。
7. **P0.7 Deterministic Replay（已完成当前组件边界）**：DS-026/DS-027
   实现 Original 与 Counterfactual Replay；DS-037 以固定 Context/Decision
   Hash、Lineage、攻击者重算 Hash 的全 Binding 属性和真实 PostgreSQL
   Conformance 将它们作为 CI 契约。未来 Simulator/Adapter/Approval 输入
   必须在自身版本落地时扩展同一门禁。
8. **P0.8 Context Provenance（类型、防火墙与持久化已完成）**：DS-022 已实现可信来源、Freshness、签名/Hash 校验和 Agent 不可覆盖规则；DS-023 已持久化精确 Evidence/Trust Snapshot，生产 Enricher 仍属于后续工作。
9. **P0.9 Policy Bundle Versioning（已完成）**：DS-019 落地 Manifest、
   Hash、Scope 与 Cedar Schema；DS-020 落地签名证明、不可变持久化、
   RBAC 激活和原子回滚；DS-025 已将当前单 Bundle 精确绑定到 Decision v1。
   多 Bundle 解析仍是后续能力。
10. **P0.10 Metrics & Audit Query API（当前组件范围已完成）**：DS-032 已完成组织隔离、完整链验证、限界稳定分页的 Audit Query；DS-033 已完成请求、Decision、Policy/Risk、Replay、Idempotency、Freshness、Audit Failure 的低基数 Metrics，以及 Request/Trace/Audit Event Correlation 和 Captured-log Redaction。Accepted ADR-0004 进一步以独立 mTLS Operations Surface、typed `METRICS_READ` Principal 与受保护 UDS 关闭匿名抓取，同时保留数据库故障期可观测性。未实现组件的指标不伪造；Checkpoint/Retention 继续作为生产残余审计项。
11. **Local Operations & Recovery Evidence（单机本地范围已完成）**：DS-039 提供 digest-pinned、loopback-only TLS 的 PostgreSQL/Gateway Compose，执行前向 Migration 和幂等 Provisioning；clean E2E 已验证 Submit/Restart/Replay，Backup/隔离 Restore 后 Audit Head 与计数一致，Policy Rollback/Forward 后 Replay 不变。实测 P95 178 ms、28.328 evaluations/s 未达到 §26 目标；共享 Ingress、HA/故障切换、生产 Backup Retention、后台 Recovery Scanner 和生产容量仍是生产部署阻断项，不由 C4 批准关闭。

**Phase 2 Gate（已通过）：** 第 32.1/32.2 验收全部通过、Gap Matrix 中与 Durable Shadow 当前范围相关的 CRITICAL/HIGH 缺口已有可执行处置，DS-040 技术复审及 §32.2.2 Metrics 访问边界整改已完成；独立人工 ATF 维护者于 2026-08-10 对提交 `850477e` 批准 `C4-SIGNOFF-001`。Checkpoint C4 允许启动 RA-001，但不批准生产部署、真实 Adapter 执行或任何资金权限。

### Phase 3：Reference Simulation 与 Adapter

1. Mock Simulator。
2. Mock Adapter 与 Adapter SDK/Manifest。
3. Adapter Conformance Test Suite。
4. x402、Safe、Hyperliquid Reference Adapter，全部先支持 Shadow Mode。
5. 三个可重放、无生产 Secret 的 Reference Scenario。

**Phase 3 Gate：** Simulation/Adapter 的能力、版本、请求 Hash、Timeout、Retry Safety、Partial/Unknown Execution 全部通过 Conformance；仍不默认启用真实执行。

### Phase 4：Approval、Execution Authorization 与 Reconciliation

1. Approval Engine 与多人/角色/过期语义。
2. Decision/Approval Hash Binding。
3. Single-use Execution Grant。
4. Kill Switch 与 Enforce Mode Feature Flag。
5. Settlement Verification 与 Reconciliation Worker。
6. 故障恢复、未知执行状态和安全复审。

### Phase 5：Community 与 Ecosystem

TypeScript/Python SDK、MCP Middleware、文档站、RFC 流程、Adapter 开发指南和外部 Policy/Adapter 贡献。

---

## 32. Release 验收标准

### 32.1 Durable Shadow Mode 功能验收

1. Schema 与 Rust Semantic Validator 在 Policy/Risk 前拒绝非法 Intent，并返回稳定 Error Code。
2. Agent Identity Envelope 在 Policy/Risk 前验证组织、Key、Nonce、Audience、Environment 和有效期；失败写入 Audit。
3. 每个接受的 Intent、Evaluation、Decision 和 Audit Event 按显式生命周期事务持久化；任一状态转换对 Decision、Audit 和 Idempotency Result 保持原子可见，服务重启和第二实例可读取。
4. `(organization_id, idempotency_key)` 同 Hash 返回原 Decision，不重新评估；不同 Hash 返回 `IDEMPOTENCY_CONFLICT`；并发只有一个请求进入评估。
5. 每个 Decision 绑定 Intent、Policy、Risk、Context 和 Simulation（适用时）的版本/Hash、Evaluation Time 与 Expiry。
6. Original Replay 使用原 Snapshot/版本得到相同 Decision Hash；Counterfactual Replay 创建独立 Evaluation 且不覆盖原记录。
7. Agent-provided Context 不能直接覆盖价格、余额、仓位、累计支出、风险信誉或模拟结果；缺失/过期数据不产生 Permit。
8. Audit 支持按 Organization、Intent、Agent、Event Type 和时间查询，Hash Chain 可在重启后验证。
9. Metrics/Tracing 覆盖请求、Decision、Policy/Risk、Replay、Idempotency、数据新鲜度和 Audit 写入失败，不记录 Secret 或完整敏感 Payload。
10. 当前所有执行接口不存在或默认关闭，仓库明确标记为 Shadow-only、非生产就绪。

### 32.2 Durable Shadow Mode 安全验收

1. 仓库不存在明文生产 Secret，核心路径不调用 LLM，金融金额不使用浮点数。
2. 非健康检查 API 全部具备 Authentication、Organization Isolation、最小 RBAC、Request Size Limit、Timeout、Rate Limit 和结构化 Error Code。
3. Policy Bundle、Risk Rule Set、Context Snapshot 和外部证据有版本与 Hash；无法加载或验证时 Fail Closed。
4. Restart、并发、数据库故障、锁冲突和多实例场景有集成测试，不会丢失或分叉已接受状态。
5. CI 运行 fmt、clippy、test、deny、依赖/Secret/SAST Gate、Persistence/Replay/Concurrent Idempotency Tests 和至少基础 Fuzz Smoke。
6. `docs/audit-gap-matrix.md` 中指向 Durable Shadow Mode 的 CRITICAL/HIGH 项有代码、测试和文档证据，不允许仅修改状态文字。

### 32.3 Enforce Mode 前置验收

1. Simulator、Adapter、Approval、Execution Grant、Kill Switch、Settlement 和 Reconciliation 均有独立类型、持久化和 Conformance Test。
2. 修改 Intent、Decision、Approval、Adapter Version 或 Execution Request 任一字段都会使 Execution Grant 失效。
3. Approval、Execution Grant 和 Payment Proof Nonce 均为持久化单次使用，并通过并发 Replay Test。
4. Adapter 错误、Timeout、Partial Execution 或 Unknown State 不得被解释为成功或自动安全重试。
5. Enforce Mode 默认关闭，并完成独立 Threat Model 更新、安全复审、故障演练和回滚方案。

### 32.4 文档验收

1. README Status、Architecture、Threat Model、Roadmap、Gap Matrix、Changelog 与代码/路由/Workspace 一致。
2. Intent、Policy、Audit、Identity Envelope、Adapter 和 Replay Specification 可供第三方实现。
3. Quickstart 和所有示例请求可在当前 Schema/Policy/CLI/Gateway 上真实运行。
4. 每个目标态能力明确标注 `Implemented`、`Partial`、`Scaffold` 或 `Missing`，不把设计稿描述成现状。

---

## 33. 项目指标

开源指标：

1. GitHub Stars。
2. Forks。
3. 外部 Contributors。
4. Issue 数量与质量。
5. 外部 Adapter。
6. Policy Pack。
7. 文档访问。
8. 真实集成项目。

产品指标：

1. Shadow Evaluations。
2. Risk Findings。
3. Original Replay Decision Hash 一致率（目标 100%）。
4. Idempotent Retry 命中和 Conflict 数量。
5. Restart Recovery 与 Audit Chain 验证成功率（目标 100%）。
6. Identity/Nonce/Organization Isolation 拒绝数量。
7. Context Missing/Stale/Untrusted 比例。
8. Policy/Risk Rule 命中、误报和版本分布。
9. 平均与 P95 决策延迟。
10. Audit 写入失败和本地缓冲深度。

Review 转化、Adapter 稳定性、Reconciliation 成功率和真实执行量只在对应后续阶段启用后统计。

---

## 34. 商业化边界

开源：

1. Transaction Intent Specification。
2. Policy Kernel。
3. Risk Rule Framework。
4. Adapter SDK。
5. 基础 Adapter。
6. Shadow Mode。
7. Audit Format。
8. CLI。
9. Conformance Tests。

未来可商业化：

1. 托管控制面。
2. 企业管理后台。
3. SSO 与多组织。
4. 私有部署。
5. 高级审计与合规。
6. 商业风险情报。
7. 供应商信誉数据库。
8. SLA。
9. 企业支持。
10. 专有金融场景插件。

---

## 35. 当前开发原则

1. 每次只完成一个具有 Acceptance Criteria 的可验证垂直功能，不把多个安全边界混入同一提交。
2. 每个 crate 必须有单一职责。
3. 核心类型优先稳定，再开发 Adapter。
4. Schema 和 RFC 优先于前端。
5. Durable Shadow Mode 完成并复审前不开发真实执行链。
6. Mock Adapter 优先于生产 Adapter。
7. 所有错误使用明确类型。
8. 禁止在核心域模型中使用浮点数。
9. 禁止 Agent 或 LLM 直接接触生产 Secret。
10. 禁止在没有 Threat Model 的情况下启用生产执行。
11. 所有 API 默认关闭执行能力。
12. 所有高风险功能使用 Feature Flag。
13. 所有外部数据必须标记时间和来源。
14. 所有决策必须可解释、可重放、可审计。
15. 任何不确定错误默认拒绝执行。
16. 不得使用 `Timestamp::now()`、随机数、未记录环境变量或隐式外部状态直接决定结果；统一通过 EvaluationContext 注入。
17. 文档中的完成状态必须由 Workspace、真实调用路径和可执行测试共同证明。
18. 所有运行时功能完成后必须执行 fmt、clippy、workspace tests、deny 和真实进程烟测，并同步 README、Architecture、Threat Model、Roadmap 与 Changelog。

---

## 36. 需求、架构与状态治理

1. 本 PRD 定义产品目标与 Release Gate；`docs/architecture.md` 定义当前/目标架构；`README.md` 定义最新实现状态；`docs/audit-gap-matrix.md` 定义带证据的安全缺口；`docs/roadmap.md` 定义交付顺序。
2. 重大公共 Schema、Identity、Decision、Persistence、Approval 或 Execution 设计变更必须先写 RFC 或 ADR，记录上下文、备选方案和后果。
3. 规范版本变化必须说明向后兼容、迁移方式和旧版本拒绝策略；不得静默改变 Canonical Hash 或签名语义。
4. 一个功能只有在代码、Schema/迁移、单元/集成测试、真实运行验证和文档均完成后才可标记为 Done。
5. 历史 ADR 不删除；决策变化通过新的 ADR 标记 Superseded，保留事故调查和 Replay 所需上下文。
6. 每次 Release 前重新核对 Threat Model 与 Gap Matrix；没有证据关闭的 CRITICAL/HIGH Gap 不得因排期压力降级为“已接受”。
7. 当前关键架构决策见 `docs/decisions/0001-durable-shadow-before-enforce.md`。

---

## 37. 最终产品定义

Agentic Transaction Firewall 是面向自主 Agent 的开源金融行为控制与证据层。

它不负责替 Agent 作出投资决策，也不负责替用户保管资产。

它负责确保：

1. Agent 的金融行为有明确授权。
2. 金融行为符合用户和组织意图。
3. 交易满足确定性 Policy。
4. 交易满足动态金融风险限制。
5. 高风险行为得到正确审批。
6. 执行请求未被篡改。
7. 结算与服务交付可以验证。
8. 所有行为拥有完整责任链。
9. 原始 Decision 可以从持久化版本和 Snapshot 确定性重放。
10. 任意真实执行只能消费一次与完整授权链绑定的 Execution Grant。

ATF 的长期技术资产不是某一个 Adapter，而是：

1. Agent Transaction Intent 标准。
2. 金融 Policy 模型。
3. 金融 Risk Rule 体系。
4. Adapter Conformance 标准。
5. Agent 交易威胁模型。
6. 可重放的审计格式。
7. 真实金融 Agent 风险案例库。
8. Identity、Decision、Approval 与 Execution Binding 规范。

项目的最佳成功形态不是成为另一个钱包，也不是比 Agent 更聪明地做金融决策，而是成为钱包、Agent、支付系统和交易基础设施都可以复用、验证和替换实现的公共安全层。
