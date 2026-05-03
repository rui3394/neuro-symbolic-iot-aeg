# 阶段性技术报告 v0.1

## 1. 项目名称

面向 IoT CGI 固件二进制的 Ghidra 辅助神经符号危险路径验证与触发输入合成系统。

英文定位：

```text
Ghidra-Assisted Neuro-Symbolic Dangerous-Path Verification and Input Synthesis for IoT CGI Binaries
```

## 2. 研究背景与问题定义

IoT 固件中的 Web 管理接口通常由 CGI 二进制实现。这类二进制常见输入来源包括 HTTP 参数、环境变量、`argv` 参数以及配置文件内容，危险操作则可能表现为 `system`、`popen`、格式化函数、文件操作或网络操作等 sink。实际分析中，研究人员通常需要在 Ghidra 中手工完成以下工作：

- 定位危险函数调用点。
- 区分 external symbol 地址与真实 callsite 地址。
- 查找 caller function 和 caller entry。
- 追踪输入来源是否进入危险函数参数。
- 判断某条 source-to-sink 路径是否可达。
- 组织可复现证据供评审或论文展示。

这些步骤成本高、容易出错，而且人工 Ghidra 分析结果很难直接被 symbolic verifier 或 planner 复用。项目当前阶段要解决的问题是：如何把 Ghidra 中的静态事实转化为结构化验证任务，并通过 planner-verifier 闭环生成非武器化、可复现的 source-to-sink symbolic evidence。

## 3. 系统总体思路

当前系统采用以下总体思路：

```text
Ghidra 静态事实抽取
  -> Dangerous Path Task 抽象
  -> Planner candidate 生成
  -> angr symbolic verifier
  -> Evidence report / Planner summary
```

核心思想是把人工 Ghidra 分析中的关键事实结构化，包括 binary、function、import、dangerous sink、callsite、caller、source、expected oracle 和 benign marker。随后，系统把这些事实合成为 `dangerous_path_task.json`，作为 planner 和 verifier 的统一接口。

Planner 负责生成 benign candidate inputs。Verifier 负责在不具体执行目标二进制、不执行 `system/popen` 的前提下，使用 symbolic execution 检查 source 是否能到达 sink，并尝试观察 benign marker 是否进入 sink 参数。最后，报告模块将机器可读 JSON 转换为面向人工审阅的 Markdown 证据。

## 4. 系统架构

### 4.1 Ghidra Facts Exporter

模块位置：

- `ns_aeg/ghidra/export_facts.py`
- `ns_aeg/ghidra/sink_catalog.py`

功能：

- 通过 PyGhidra/Ghidra Headless 风格接口对 binary 做静态分析。
- 导出 binary 信息、架构、函数、imports、externals、字符串、危险 sinks。
- 对 imported sinks 提取 callsite、caller、caller entry。
- best-effort 导出 caller 函数的 decompiled snippet。

当前 toy_01 real facts 结果：

- functions：18
- imports：5
- externals：5
- dangerous sinks：2
- callsites：2
- strings：81
- decompiled snippets：1

关键 sink：

- `snprintf`：callsite `0x4011ea`，caller `main`，caller entry `0x401176`
- `system`：callsite `0x4011f9`，caller `main`，caller entry `0x401176`

### 4.2 Dangerous Path Task Builder

模块位置：

- `ns_aeg/tasks/builder.py`
- `ns_aeg/tasks/loader.py`

功能：

- 读取 Ghidra facts JSON 和 YAML target。
- 合成 Dangerous Path Task。
- 将二进制、source、sink、entry、evidence、expected oracle、provenance 组织为统一 JSON。

该 task 是后续 rule planner、API LLM planner、dry-run verifier、symbolic verifier 和 batch pipeline 的共同输入。

### 4.3 Rule Planner / API LLM Planner

模块位置：

- `ns_aeg/planner/rule_planner.py`
- `ns_aeg/planner/api_planner.py`
- `ns_aeg/planner/providers.py`

Rule planner：

- 确定性 baseline。
- 从 task source 和 benign marker 生成固定 benign probes。
- 当前 toy_01 生成 4 个 candidates。

API LLM planner：

- 使用 OpenAI-compatible Chat Completions provider。
- 支持小米 MiMo Token Plan。
- 默认不联网测试；支持 `--offline-example`。
- 生成 candidate 后执行本地 validation，检查 source 覆盖、marker、长度、危险字符和 `weaponized=false`。

Planner 输出不是 exploit payload，而是 benign source-to-sink verification inputs。

### 4.4 Task-driven Symbolic Verifier

模块位置：

- `ns_aeg/verifier/task_adapter.py`
- `ns_aeg/verifier/candidate_verifier.py`
- `ns_aeg/verifier/symbolic_task_runner.py`

功能：

- 将 Dangerous Path Task 转成 verifier 内部配置。
- 支持 dry-run adapter mode。
- 支持 toy_01 的 angr symbolic mode。
- 选择 command execution sink，例如 `system @ 0x4011f9`。
- 构造 argv-based symbolic state。
- 探索到 sink callsite。
- 检查 source symbolic variable 和 benign marker 是否出现在 sink 参数附近。

当前 verifier 输出明确记录：

- `executed=false`
- `backend=angr`
- `sink_reached`
- `source_bound`
- `marker_observed`
- `selected_sink`
- `constraints_summary`
- `limitations`

### 4.5 Evidence Report

模块位置：

- `ns_aeg/reports/evidence_report.py`

功能：

- 将单个 verification JSON 转成 Markdown。
- 面向人工审阅展示 task、candidate、binary、sources、sinks、symbolic evidence、reason、limitations 和 safety note。

该报告强调当前结果是 source-to-sink symbolic evidence，不是完整 exploit verification。

### 4.6 Planner Summary Report

模块位置：

- `ns_aeg/pipeline/run_planner_verifier.py`
- `ns_aeg/reports/planner_summary_report.py`

功能：

- 对 planner 生成的一批 candidates 执行 batch verification。
- 汇总 `status_counts`、`best_candidate_id`、sink/source/marker 观察计数。
- 对 LLM planner 记录 provider、model、max_tokens、temperature、validation pass/fail 统计。
- 生成 Markdown summary，方便比较 rule planner 和 LLM planner。

## 5. 核心创新点

### 5.1 Ghidra-derived Verification Task Abstraction

系统不是直接把 Ghidra 输出交给 verifier，而是引入 Dangerous Path Task 抽象。该抽象把 binary、entry、sources、sinks、expected oracle 和 evidence 组织为统一接口，从而解耦静态分析、candidate planning 和 symbolic verification。

### 5.2 Source/Sink/Callsite 结构化

系统明确区分：

- external symbol address，例如 `system=0x3`
- real callsite address，例如 `system @ 0x4011f9`
- caller function，例如 `main`
- caller entry，例如 `0x401176`

这避免 verifier 错把 external symbol 地址当成真实探索目标。

### 5.3 Benign Marker-based Source-to-Sink Evidence

系统使用 benign marker，例如 `__NS_AEG_MARKER__`，作为 source-to-sink evidence 的观察标记。Verifier 不生成武器化 payload，而是验证 benign input 是否能传播到危险 sink 参数。

### 5.4 Planner-Verifier Closed Loop

系统支持：

```text
Dangerous Path Task -> Planner -> Candidate Set -> Symbolic Verifier -> Summary
```

Rule planner 提供确定性 baseline，API LLM planner 提供模型驱动 candidate generation，二者都复用同一个 verifier 和 summary report。

### 5.5 非武器化 Evidence Report

报告模块明确写出：

- No target binary was concretely executed.
- No system/popen command was executed.
- No weaponized exploit was generated.
- This is source-to-sink symbolic evidence, not full exploit verification.

这使系统输出适合研究验证和安全评审，而不是 exploit 生成。

## 6. 当前实现结果

### 6.1 toy_01 Ghidra Real Facts

当前 `examples/ghidra_exports/toy_01_facts.real.json` 显示：

- functions：18
- imports：5
- externals：5
- dangerous sinks：2
- xrefs/callsites：2
- strings：81
- decompiled snippets：1

重要危险路径事实：

- `snprintf @ 0x4011ea`
- `system @ 0x4011f9`
- caller：`main`
- caller entry：`0x401176`

### 6.2 toy_01 Symbolic Verifier

当前 `reports/evidence/toy_01_verification.symbolic.json` 的核心结果：

- `status=sat`
- `mode=symbolic_task`
- `backend=angr`
- `selected_sink=system @ 0x4011f9`
- `selected_entry=main @ 0x401176`
- `sink_reached=true`
- `source_bound=true`
- `marker_observed=true`

解释：

- symbolic exploration 能到达 `system` callsite。
- candidate source 与 sink 参数存在绑定证据。
- benign marker 可在 sink 参数中观察到。

### 6.3 Rule Planner Batch Result

当前 `reports/planner_runs/toy_01_rule_symbolic/summary.json` 显示：

- planner：`rule_based_planner`
- candidates：4
- status_counts：`{"sat": 4}`
- best_candidate_id：`toy_01_rule_001`
- selected_sink：`system @ 0x4011f9`

说明 rule planner 生成的 4 个 benign candidates 都能在 toy_01 symbolic mode 下得到 sat。

### 6.4 API LLM Planner Result

当前 API LLM planner 已能通过小米 MiMo Token Plan 生成 benign candidates。示例 LLM pipeline summary 显示：

- planner：`api_llm_planner`
- provider：`openai_compatible`
- model：`mimo-v2.5-pro`
- candidates：3
- status_counts：`{"sat": 3}`
- best_candidate_id：`c1`
- selected_sink：`system @ 0x4011f9`

说明 LLM planner 生成的 benign candidates 也能进入同一 symbolic verification pipeline。

## 7. 当前安全边界

当前系统明确遵守以下边界：

- 不执行目标二进制。
- 不执行 `system` / `popen`。
- 不生成 weaponized exploit。
- 不输出命令注入 payload。
- candidate 仅作为 benign source-to-sink verification input。
- 当前结果是 source-to-sink symbolic evidence，不是完整 exploit verification。
- 报告中保留 safety note，避免误读为攻击利用证明。

## 8. 当前限制

当前系统仍处于 toy demo 和方法验证阶段，主要限制包括：

- 当前 symbolic backend 主要支持 toy_01。
- 当前 source binding 主要覆盖 argv-based CGI 输入。
- 当前 sink argument inspection 主要支持 AMD64 `rdi` 首参数。
- `snprintf` 目前是最小 SimProcedure，用于 toy source propagation。
- 尚未完成 toy_02/toy_03 的 symbolic path 支持。
- 尚未进行真实固件评估。
- LLM planner 已可生成 candidates，但仍需更多任务评估稳定性、有效性和与 rule planner 的差异。
- 当前没有完整 taint engine，也没有完整 exploitability proof。

## 9. 后续计划

短期计划：

- 扩展 toy_02/toy_03 symbolic support。
- 增强 sanitizer-aware planner，让 planner 理解过滤字符、长度限制和分支条件。
- 增强 sink argument inspection，支持更多架构、更多参数位置和更多 sink 类型。

中期计划：

- 开展 MiMo-V2.5-Pro vs MiMo-V2.5 的 model comparison。
- 建立 rule planner vs LLM planner 的 cross-task evaluation。
- 生成 cross-model planner summary report。
- 为 LLM candidate set 增加正式 schema。

长期计划：

- 引入真实 IoT 固件 case study。
- 构建 dataset、baseline 和 ablation 实验。
- 完善论文评估指标，包括 candidate validity、sink reachability、source binding、marker observation、timeout/unsupported rate。
- 保持非武器化安全边界，输出可审阅 evidence 而非 exploit。

## 10. 阶段性结论

当前 v0.1 系统已经形成一条可运行的 Ghidra-assisted neuro-symbolic pipeline。它可以从 toy_01 binary 中抽取 Ghidra facts，构造 Dangerous Path Task，使用 rule planner 或 API LLM planner 生成 benign candidates，并通过 angr symbolic verifier 生成 source-to-sink evidence，最后输出机器可读 JSON 和人工可读 Markdown 报告。

当前结果说明该方法在 toy_01 上具备端到端可行性：`system @ 0x4011f9` 可被 symbolic exploration 到达，source 和 benign marker 可被观察到进入 sink 参数。但该结果仍应被理解为受控 toy binary 上的 source-to-sink symbolic evidence，而不是完整 exploit verification 或真实固件漏洞证明。

