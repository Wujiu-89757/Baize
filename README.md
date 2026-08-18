# 白泽流量分析平台 v0.1

## 快速开始

**方式一：双击运行（推荐）**

```text
双击「启动.bat」→ 自动检查依赖并启动 → 浏览器自动打开
cmd 窗口常驻服务；关闭命令行窗口即自动退出（无需其他关闭脚本）
```

**方式二：命令行**

```bash
cd traffic-analysis
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- 前端页面：<http://127.0.0.1:8000/>（本地免登录模式）
- OpenAPI 文档：<http://127.0.0.1:8000/docs>
- 数据目录：`data/`（SQLite + 上传文件存储；删除该目录即重置数据）

## 功能总览

| 模块 | 实现 |
|---|---|
| 上传与文件管理 | 拖拽上传、扩展名 + magic number 双重校验、SHA-256、哈希去重（重复上传标记 deduplicated，不污染原记录）、大小限制（默认 512 MB，可配置）、路径穿越清洗、软删除、下载 |
| 策略库 | YAML/JSON 策略（纯数据，不执行代码）；统一字段注册表 + JSON Schema 双重校验（含正则 DoS 静态检查）；草稿/发布/启停生命周期、版本化、导入导出；启停只以 `strategies.enabled` 元数据为准 |
| 分析引擎 | scapy 解析适配层（pcap/pcapng、Ethernet 链路（及 SLL/SLL2/RAW 尽力解析）、TCP/UDP/ICMP/ARP/DNS/HTTP/TLS 元数据）；双向五元组会话聚合（TCP 握手状态机、DNS 事务配对）；窗口分组特征；条件树求值；同实体同窗口多窗口重叠才择强，跨时间桶/跨包不合并 |
| 评分 | `hit_score = weight × confidence × severity_multiplier × context_multiplier`；单策略封顶 100 → 任务原始分封顶 200 → **归一化 0~100** 与五级风险 |
| 告警与证据 | 命中字段/实际值/期望、代表帧号（可在 Wireshark 对照）、统计证据（结构化写入 `alert_evidence` 并关联告警）、MITRE 标签、人工标记（确认/疑似/误报/忽略，不覆盖原始结果） |
| 任务 | 异步执行、进度/阶段、取消（解析与各策略求值期间均可响应）、失败原因、重试（上限 2 次）、回收站/还原/彻底删除、重启后遗留活动任务标记失败 |
| 报告 | JSON / 告警 CSV / 包 CSV / HTML，均含文件哈希、引擎版本、策略版本快照；HTML 默认转义用户可控字段 |
| 安全 | 本地免登录：无账号体系（审计主体固定为"本地"）；上传隔离目录、格式双校验、正则 DoS 防护、错误响应不泄露内部异常（调试模式除外） |
| 前端 | 原生 JS（无构建）：暗/亮双主题、线框 SVG 图标、仪表盘（全库聚合统计）、相对时间、一键复制、空态引导、动态标题、全局唯一轮询器（离开页面自动停止） |

## 内置策略

- **扫描 / 异常连接**：`scan.tcp_syn_scan`（Nmap -sS 行为：多窗口 1/10/60/300s、SYN≥100、端口≥50、纯 SYN≥0.9、握手完成率≤0.2、载荷≈0）、`scan.unusual_ports`、`http.request_burst_same_target`
- **DNS 异常**：`dns.nxdomain_burst`（NXDOMAIN 突增，归因到发起查询的客户端）、`dns.tunnel.high_entropy`（高熵长域名隧道）、`dns.exfil.dnslog_platform`
- **HTTP 恶意特征**：`http.malicious_download`（可执行/脚本下载）、`http.suspicious_user_agent`、`http.sql_injection_attempt`
- **WebShell**：`http.webshell.antsword` / `behinder` / `cknife` / `godzilla`
- **凭证攻击**：`auth.ssh_bruteforce`（22 端口批量短连接）
- **外连 / 信标**：`outbound.beacon_periodicity`（间隔均值/标准差、周期分）
- **可疑 TLS 元数据**：`tls.suspicious_metadata`（ClientHello 无 SNI；不解密）
- **明文协议暴露**：`protocol.telnet_cleartext`

策略全部可编辑/停用/发布新版本，见 `strategies/builtin/*.yaml` 与 `strategies/schemas/strategy.schema.json`。

## 评分说明

- 每条告警原始分 = `weight × confidence × severity_multiplier × context_multiplier`；
- 同一策略告警原始分合计超过 100 时按比例缩放（单策略封顶）；
- 任务原始分 = 各策略封顶后合计，再按 `min(raw, 200) / 200 × 100` 归一化到 **0~100**；
- 风险等级：0~19 信息 / 20~39 低 / 40~69 中 / 70~89 高 / 90~100 严重。

## 项目结构

```
app/
├─ api/            # REST 接口（files/strategies/analysis/audit；本地免登录无 auth）
├─ core/           # 配置、JSON 日志（request_id/task_id 串联）、错误
├─ models/         # SQLAlchemy：files/strategies/strategy_versions/analysis_tasks/
│                  #   packets/sessions/alerts/alert_evidence/audit_logs
├─ schemas/        # Pydantic DTO（含输入边界校验）
├─ services/       # 文件、策略、任务调度（线程池）、查询、报告、审计
├─ analysis/       # 解析适配层 / 特征 / 字段注册表 / 算子 / 评分 / 引擎
├─ static/         # 前端（原生 JS，无构建）
└─ main.py
strategies/        # builtin YAML + JSON Schema
tests/             # pytest：unit + integration（合成流量夹具，见 tests/fixtures/gen.py）
scripts/           # smoke_parse / live_analyze
data/              # 运行时：SQLite、上传临时区、存储（不可变原始文件）
```

## 开发交接说明

每次变更应说明：变更模块、数据库迁移、策略版本、测试命令、性能影响、已知限制。
任何将"疑似"升级为"确认恶意"的逻辑，必须基于明确证据与可配置阈值。
