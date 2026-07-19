# Agentic Transaction Firewall 产品需求文档

项目名称：Agentic Transaction Firewall
项目简称：ATF
仓库建议：agentic-transaction-firewall
产品类型：开源基础设施
核心语言：Rust
开源许可：Apache License 2.0
文档版本：PRD v1.1
项目阶段：初始化与 MVP 设计
目标定位：面向 AI Agent 的金融交易意图、权限、风险、审批、执行与审计控制层

---

## 1. 产品摘要

Agentic Transaction Firewall 是一个协议中立、钱包中立、交易场所中立的开源金融交易控制层。

它位于 AI Agent 与钱包、交易所、DeFi 协议、Treasury 系统、x402 服务和其他支付网络之间。所有不可逆或高风险金融行为在执行前，必须转换为统一的 Transaction Intent，经过身份验证、Policy Evaluation、金融风险检查、交易模拟和审批流程，才能被允许执行。

ATF 不创建新钱包，不托管资产，不发明新支付协议，也不替代交易所、Fireblocks、Privy、Safe、Coinbase CDP 或 AWS AgentCore。ATF 的目标是为这些基础设施提供统一的上层控制语义：

Agent Intent
→ Canonical Transaction Intent
→ Policy Evaluation
→ Financial Risk Evaluation
→ Simulation
→ Approval
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

---

## 2. 产品愿景

成为 AI Agent 金融行为控制的开源参考实现。

长期目标是形成一套被 Agent 框架、钱包、支付平台、交易系统和企业 Treasury 接受的统一标准：

Agent Transaction Intent Specification

ATF 希望成为自主金融系统中的 Policy Enforcement Point，类似于：

1. Kubernetes Admission Controller 对集群资源的控制。
2. Web Application Firewall 对网络请求的控制。
3. Cedar 或 OPA 对软件授权的控制。
4. Firewalls 和 SIEM 对企业安全行为的控制。

区别在于，ATF 专门理解金融交易语义，包括金额、资产、目的地址、Token Approval、杠杆、滑点、清算距离、资金费率、市场状态、任务预算和交易策略。

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

### 4.1 核心目标

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

### 4.2 成功定义

第一阶段成功不以用户数、交易量或融资为核心指标，而以以下结果衡量：

1. 开发者能够在 30 分钟内运行本地 Demo。
2. Agent 可以通过统一 API 提交交易意图。
3. Cedar Policy 可以对交易进行 Permit、Deny 或 Review 判定。
4. 风险引擎可以识别静态授权之外的金融风险。
5. Shadow Mode 可以在不接管签名权限的情况下生成风险报告。
6. 至少三个 Adapter 能通过统一 Conformance Tests。
7. 所有决策都能够被完整重放和审计。
8. 核心模块通过单元测试、属性测试、模糊测试和依赖安全检查。
9. 开源文档足够清晰，外部开发者可以编写新的 Adapter。
10. 至少获得一批真实开发者的 Issue、PR 或集成反馈。

---

## 5. 非目标

ATF 第一阶段明确不做以下事情：

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

ATF 支持三种运行模式。

### 7.1 Shadow Mode

ATF 不阻止交易，也不掌握签名权限。

流程：

1. Agent 或应用复制 Transaction Intent 给 ATF。
2. ATF 执行 Policy、Risk 和 Simulation。
3. ATF 返回“如果启用 Enforcement，本次应 Permit、Deny 或 Review”。
4. 交易仍通过原有路径执行。
5. ATF 对比预测结果与实际结果。

用途：

1. 低风险接入。
2. 历史策略评估。
3. Policy 调试。
4. 风险误报与漏报分析。
5. 设计伙伴验证。

### 7.2 Review Mode

低风险交易自动通过，高风险交易进入审批。

流程：

1. ATF 生成决策。
2. Permit 直接传递到执行层。
3. Review 进入人工或多人审批。
4. Deny 被拒绝。
5. 审批结果和原因进入审计账本。

### 7.3 Enforce Mode

所有受控交易必须经过 ATF。

要求：

1. Agent 不直接持有无限制签名权限。
2. 钱包、Safe Module、交易所 API 或签名服务只接受 ATF 授权请求。
3. ATF Decision 绑定 Transaction Hash 或 Canonical Request Hash。
4. 执行前再次验证请求未被修改。
5. 执行后验证实际结果。

---

## 8. 核心用户流程

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
    "task_budget": "20.00",
    "historical_vendor_median": "8.50",
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

### 9.4 Budget 模型

Transaction Intent 中的 `budget_id` 与 `context.task_budget` 引用一个独立的 Budget 对象，而非自由文本。

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

---

## 10. 决策模型

ATF 对每个请求返回统一 Decision。

```json
{
  "decision_id": "dec-001",
  "intent_id": "01J...",
  "decision": "REVIEW",
  "risk_score": 72,
  "policy_version": "policy-bundle-2026-07-18.3",
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
  "required_approvals": [
    {
      "role": "treasury-approver",
      "count": 1
    }
  ],
  "obligations": [
    {
      "type": "bind_execution_hash"
    },
    {
      "type": "verify_service_delivery"
    }
  ],
  "expires_at": "2026-07-18T08:03:00Z"
}
```

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

合并规则本身必须版本化（随 `policy_version` 一起声明），且必须有对应属性测试（见 28.3）验证合并结果的确定性与幂等性。

### 10.2 Decision 类型

1. PERMIT
2. DENY
3. REVIEW
4. ERROR

ERROR 不得自动等同于 PERMIT。系统默认 Fail Closed。

---

## 11. Policy Kernel

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

---

## 13. Transaction Simulator

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

### 16.1 目标

保证每个金融行为都能够被追踪、解释和重放。

### 16.2 审计事件

1. IntentReceived
2. IdentityVerified
3. PolicyEvaluated
4. RiskEvaluated
5. SimulationCompleted
6. ApprovalRequested
7. ApprovalGranted
8. ApprovalRejected
9. ExecutionRequested
10. ExecutionSubmitted
11. ExecutionConfirmed
12. SettlementVerified
13. ServiceDelivered
14. ReconciliationFailed
15. KillSwitchTriggered
16. PolicyChanged
17. AgentPaused

### 16.3 不可篡改设计

MVP：

1. PostgreSQL Append-only 表。
2. 每个事件包含前一事件 Hash。
3. 定期生成 Merkle Root 或审计检查点。
4. 审计日志只追加，不更新。
5. 管理员也不能静默删除。

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
2. Agent SDK 对每个 Transaction Intent 的 Canonical Hash 进行签名，Gateway 验证签名后才进入 Context Normalizer；签名失败直接 DENY，不进入 Policy/Risk 评估。
3. Agent 私钥与执行签名私钥（钱包/交易所侧）必须是两套独立密钥：前者只用于证明"这是哪个 Agent 发起的请求"，后者由 Adapter/Fireblocks/Safe 等托管，ATF 核心进程不持有、不代理执行签名。
4. 支持密钥轮换：注册新公钥、设置旧公钥失效窗口、轮换事件写入 Audit；轮换期间允许双公钥并行验证，避免请求中断。
5. 单个私钥泄露的爆炸半径由 `risk_tier`、`default_budget` 和 `allowed_adapters` 限定，即：身份签名验证通过只代表"请求来自该 Agent"，不代表跳过 Policy/Risk 评估。

### 17.3 Admin API 权限模型

1. `atf-admin-api` 自身的操作（注册/暂停 Agent、发布 Policy Bundle、调整 Budget、管理审批角色）需要独立的 RBAC，区别于 Agent 身份体系。
2. 最小角色集：`org_admin`（管理 Agent 与 Budget）、`policy_author`（发布 Policy，不能执行审批）、`approver`（仅可处理审批，不能改 Policy）、`auditor`（只读）。
3. 高风险 Admin 操作（发布生产 Policy、调整 Kill Switch、提升 Agent 权限）需要与 14.1 类似的多人审批，不允许单一 `org_admin` 账号直接生效。
4. 所有 Admin API 调用生成审计事件（对应 16.2 的 `PolicyChanged`、`AgentPaused` 等），且记录操作者角色与身份，不允许匿名或共享账号操作。

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

### 19.1 核心技术栈

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

### 19.2 架构组件

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
3. Shadow Mode 不受此约束：Audit 写入失败时降级为本地缓冲 + 异步重试，不阻塞交易评估，因为 Shadow Mode 本身不接管签名权限。
4. 单机部署（30.2）明确不提供 HA 保证，需在文档中标注"仅适合个人/小团队，无 Audit 高可用"。
5. 备份策略：PostgreSQL 定期快照 + WAL 归档，Merkle 检查点（16.3）额外冗余存储于对象存储，用于在数据库损坏后独立验证审计链完整性。

---

## 20. Rust Workspace 目录

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

1. POST /v1/intents
2. GET /v1/intents/{intent_id}/decision
3. POST /v1/shadow/evaluate
4. POST /v1/approvals
5. POST /v1/approvals/{approval_id}/approve
6. POST /v1/approvals/{approval_id}/reject
7. POST /v1/intents/{intent_id}/execute
8. GET /v1/audit/intents/{intent_id}
9. GET /healthz
10. GET /readyz
11. GET /metrics

MVP 中执行接口默认关闭，必须通过显式配置启用。

---

## 23. SDK 需求

TypeScript 与 Python SDK 提供：

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

必须记录：

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

---

## 26. 性能目标

MVP 不以高频交易为目标。

目标：

1. 无外部 Simulation 时，P95 决策延迟低于 50 ms。
2. 包含普通外部查询时，P95 低于 500 ms。
3. 包含链上 Simulation 时，按 Adapter 单独报告。
4. 支持每秒至少 100 个 Shadow Evaluation。
5. 单节点可处理至少 1,000 个活跃 Agent 的低频请求。
6. 所有请求幂等。
7. 服务重启后不丢失已接受 Intent。
8. Audit 写入失败时阻止 Enforce Mode 执行。

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

### 28.4 模糊测试

使用 cargo-fuzz：

1. JSON Parser。
2. Intent Normalizer。
3. Adapter Input。
4. Policy Context。
5. Calldata Decoder。
6. Audit Event Parser。

---

## 29. CI/CD

每个 Pull Request 执行：

1. cargo fmt --check
2. cargo clippy --all-targets --all-features -- -D warnings
3. cargo test
4. cargo nextest run
5. cargo deny check
6. cargo audit
7. Schema Tests
8. Policy Tests
9. Adapter Conformance Tests
10. TypeScript SDK Tests
11. Python SDK Tests

Release：

1. Signed Git Tag。
2. Changelog。
3. Container Image。
4. SBOM。
5. Checksums。
6. GitHub Release。

---

## 30. 部署方式

### 30.1 Local Development

Docker Compose：

1. PostgreSQL。
2. ATF Gateway。
3. Policy Server。
4. Approval Server。
5. Audit Server。
6. Mock Adapters。
7. Prometheus。
8. Grafana。

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

## 31. MVP 路线图

### Phase 0：仓库初始化

1. Workspace。
2. CI。
3. LICENSE。
4. README。
5. SECURITY。
6. PRD。
7. Architecture。
8. Threat Model 初稿。
9. Intent Schema 草案。
10. RFC 模板。

### Phase 1：Intent 与 Policy Kernel

1. atf-intent。
2. Canonical Serialization。
3. Cedar Policy Integration。
4. atf-decision。
5. CLI evaluate。
6. Policy Examples。
7. Policy Tests。
8. Audit Hash Chain。

### Phase 2：Shadow Mode

1. Gateway。
2. Agent Identity。
3. Risk Rule Framework。
4. Shadow API。
5. PostgreSQL Audit。
6. Replay。
7. Metrics。

### Phase 3：三个参考 Adapter

1. x402 Adapter。
2. Safe Adapter。
3. Hyperliquid Adapter。
4. Adapter SDK。
5. Conformance Tests。
6. Mock Servers。
7. 三个完整 Demo。

### Phase 4：Approval 与 Enforce Mode

1. Approval Engine。
2. Review Mode。
3. Execution Hash Binding。
4. Kill Switch。
5. Reconciliation。
6. Enforce Mode Feature Flag。
7. 故障恢复。

### Phase 5：社区化

1. TypeScript SDK。
2. Python SDK。
3. MCP Middleware。
4. RFC 流程。
5. 文档站。
6. Adapter 开发指南。
7. 首个外部 Adapter PR。

---

## 32. MVP 验收标准

### 32.1 功能验收

1. 可以提交符合 Schema 的 Transaction Intent。
2. 非法 Intent 被拒绝。
3. Cedar Policy 返回确定性结果。
4. Risk Engine 至少支持 15 条规则。
5. Shadow Mode 保存完整结果。
6. 同一 Intent 可重放并得到一致决策。
7. 修改 Intent 后旧审批失效。
8. 三个 Demo 均可本地运行。
9. Audit Hash Chain 可验证。
10. Kill Switch 可以阻止 Enforce Mode 请求。
11. Decision 合并算法（10.1）对同一输入始终产出相同结果，且有属性测试覆盖 Policy/Risk/Simulation 三者冲突场景。
12. Budget 并发扣减不出现超支（12.1 数据不足提升风险原则 + 9.4 原子扣减一致）。
13. 审批过期后默认 DENY，不存在无限悬挂的审批请求（14.3）。

### 32.2 安全验收

1. 仓库不存在明文生产 Secret。
2. 核心路径不调用 LLM。
3. 所有金额不使用浮点数。
4. 所有执行请求绑定 Intent Hash。
5. 重放请求被拒绝或幂等返回。
6. Audit 写入失败时 Enforce Mode Fail Closed。
7. Adapter 错误不会被解释为 Permit。
8. 无限 Approval 可以被识别。
9. Policy Bundle 支持签名或 Hash 校验。
10. CI 包含依赖和许可证检查。
11. Agent 身份签名（17.2）验证失败的请求在进入 Policy/Risk 之前即被拒绝。
12. Admin API 高风险操作（发布 Policy、调整 Kill Switch）需要多人授权，单账号无法直接生效（17.3）。

### 32.3 文档验收

1. Quickstart。
2. Architecture。
3. Threat Model。
4. Intent Specification。
5. Policy Model。
6. Adapter Specification。
7. 三个 Demo 指南。
8. Security Disclosure。
9. Contribution Guide。
10. Roadmap。

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
3. 阻止的高风险请求。
4. Review 转化率。
5. Policy 误报率。
6. Reconciliation 成功率。
7. Adapter 稳定性。
8. 平均决策延迟。
9. 重放攻击拦截。
10. 审计完整率。

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

## 35. 初始化时的开发原则

1. 第一阶段只创建骨架，不一次实现所有模块。
2. 每个 crate 必须有单一职责。
3. 核心类型优先稳定，再开发 Adapter。
4. Schema 和 RFC 优先于前端。
5. Shadow Mode 优先于 Enforce Mode。
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

---

## 36. 首次项目初始化输出要求

使用 Claude 客户端初始化项目时，第一轮只完成以下内容：

1. 创建 Rust Workspace。
2. 创建完整目录结构。
3. 创建根 Cargo.toml。
4. 创建 rust-toolchain.toml。
5. 创建 README、LICENSE、SECURITY、CONTRIBUTING。
6. 创建 docs/PRD.md。
7. 创建 docs/architecture.md 初稿。
8. 创建 docs/threat-model.md 初稿。
9. 创建 RFC 0001、0002、0003。
10. 创建 atf-core、atf-intent、atf-policy、atf-decision、atf-cli。
11. 实现最小 Transaction Intent 类型。
12. 实现 JSON Schema Validation。
13. 实现 Canonical Hash。
14. 接入 Cedar 的最小 Policy Evaluation。
15. 实现 CLI validate-intent 和 evaluate。
16. 创建示例 Policy。
17. 创建单元测试。
18. 创建 GitHub Actions CI。
19. 确保 cargo fmt、clippy 和 test 全部通过。
20. 不接入真实钱包、交易所或 Secret。

第一轮完成后，再进入 Shadow Mode 和 Adapter 开发。

---

## 37. 最终产品定义

Agentic Transaction Firewall 是面向自主 Agent 的开源金融行为控制层。

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

ATF 的长期技术资产不是某一个 Adapter，而是：

1. Agent Transaction Intent 标准。
2. 金融 Policy 模型。
3. 金融 Risk Rule 体系。
4. Adapter Conformance 标准。
5. Agent 交易威胁模型。
6. 可重放的审计格式。
7. 真实金融 Agent 风险案例库。

项目的最佳成功形态不是成为另一个钱包，而是成为钱包、Agent、支付系统和交易基础设施都可以复用的公共安全层。
