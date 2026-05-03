# 当前输出 Artifacts 解释与手动验收

本文面向开发者和研究者，解释当前 toy_01 Ghidra-assisted dangerous-path verification pipeline 中每个 JSON/Markdown 输出文件的意义、来源、关键字段、证据强度和手动验收方法。

## 1. 当前完整 Pipeline

```text
Ghidra facts
  -> Dangerous Path Task
  -> Planner Candidates
  -> Verifier Result
  -> Evidence Report
  -> Planner Summary
```

对应到当前文件：

```text
examples/ghidra_exports/toy_01_facts.real.json
  -> examples/dangerous_tasks/toy_01_task.real.json
  -> examples/candidates/toy_01_candidates.rule.generated.json
  -> examples/candidates/toy_01_candidates.llm.generated.json
  -> reports/evidence/toy_01_verification.symbolic.json
  -> reports/evidence/toy_01_evidence.symbolic.md
  -> reports/planner_runs/toy_01_rule_symbolic/summary.json
  -> reports/planner_runs/toy_01_rule_symbolic/summary.md
  -> reports/planner_runs/toy_01_llm_symbolic/summary.json
  -> reports/planner_runs/toy_01_llm_symbolic/summary.md
```

## 2. 证据强度分层

- `Ghidra facts`：静态事实。来自 Ghidra/PyGhidra 对二进制的静态分析，包括函数、imports、危险 sink、callsite、caller、字符串和反编译片段。
- `Dangerous Path Task`：验证任务抽象。把 Ghidra facts 和 YAML target 信息合成为 verifier/planner 可以消费的统一任务。
- `Candidate set`：候选输入集合。来自 rule planner 或 API LLM planner，表示用于 benign source-to-sink 验证的输入建议。
- `Verification JSON`：机器可读 symbolic evidence。记录 angr symbolic runner 是否到达 sink、是否绑定 source、是否观察到 benign marker。
- `Evidence Markdown`：面向人工审阅的单个验证结果报告。解释一个 candidate/task 的验证状态和安全边界。
- `Planner Summary`：批量级评估结果。聚合一批 planner candidates 的 verifier 结果，适合比较 rule planner 和 LLM planner。

证据强度从“静态事实”逐步增强到“symbolic source-to-sink evidence”。但当前仍不是完整 exploit verification。

## 3. 文件逐项解释

### 3.1 `examples/ghidra_exports/toy_01_facts.real.json`

这个文件是什么：

- toy_01 二进制的真实 Ghidra/PyGhidra 静态事实导出。
- 它是当前 pipeline 的静态事实起点。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --binary datasets/toy_cgi/build/toy_01 \
  --out examples/ghidra_exports/toy_01_facts.real.json
```

依赖哪些输入：

- `datasets/toy_cgi/build/toy_01`
- `GHIDRA_INSTALL_DIR`
- PyGhidra/Ghidra 环境
- `ns_aeg/ghidra/sink_catalog.py`

下一步谁使用它：

- `ns_aeg.tasks.builder` 使用它构造 `toy_01_task.real.json`。

关键字段含义：

- `binary.path/name/arch`：二进制路径、名称、架构。
- `functions`：函数名和入口地址。
- `imports` / `externals`：外部导入符号。
- `sinks`：危险函数匹配结果，如 `system`、`snprintf`。
- `sinks[].external_address`：Ghidra external symbol 地址，例如 `0x3`、`0x4`，不是真实 callsite。
- `sinks[].address`：优先为 callsite 地址，例如 `system @ 0x4011f9`。
- `sinks[].callsites`：调用点地址、caller 名称、caller entry。
- `evidence.strings`：字符串字面量。
- `evidence.decompiled_snippets`：best-effort 反编译片段。

它能证明什么：

- 证明 Ghidra 静态分析识别到了危险 sink 和调用位置。
- 对 toy_01，关键事实是 `system` callsite 位于 `0x4011f9`，caller 是 `main`。

它不能证明什么：

- 不能证明输入可达 sink。
- 不能证明 source 数据进入 sink 参数。
- 不能证明漏洞可利用。

常见异常如何判断：

- `sinks[].address` 只有 `0x3` 或 `0x4`：说明只有 external symbol 地址，没有提取到 callsite。
- `callsites=[]`：xref/caller extraction 未成功。
- `decompiled_snippets=[]`：反编译 best-effort 失败，不一定影响后续 task。

### 3.2 `examples/dangerous_tasks/toy_01_task.real.json`

这个文件是什么：

- Dangerous Path Task，是 planner/verifier 的统一输入接口。
- 它把 Ghidra facts 和 YAML target 信息合并成任务抽象。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_01_facts.real.json \
  --target configs/toy_01.yaml \
  --out examples/dangerous_tasks/toy_01_task.real.json
```

依赖哪些输入：

- `examples/ghidra_exports/toy_01_facts.real.json`
- `configs/toy_01.yaml`

下一步谁使用它：

- `ns_aeg.planner.rule_planner`
- `ns_aeg.planner.api_planner`
- `ns_aeg.pipeline.run_planner_verifier`
- `ns_aeg.verifier.candidate_verifier`

关键字段含义：

- `task_id`：任务唯一标识。
- `binary`：验证目标二进制信息。
- `entry`：入口函数/地址，toy_01 当前是 `main @ 0x401176`。
- `sources`：输入源，例如 `ip`、`argv[1]`、`sym_ip`、`max_len`。
- `sinks`：危险 sink，例如 `system @ 0x4011f9`。
- `expected.oracle`：默认 `source_reaches_sink`。
- `expected.benign_marker`：默认 `__NS_AEG_MARKER__`。
- `evidence`：从 facts 继承的 strings/decompiled snippets。

它能证明什么：

- 证明当前系统已经把静态事实整理为 verifier/planner 可消费任务。

它不能证明什么：

- 任务本身不执行 symbolic verification。
- 任务本身不说明 candidate 是否可达 sink。

常见异常如何判断：

- `sources=[]`：target YAML source 信息缺失，planner 无法生成 candidate。
- `sinks=[]`：Ghidra facts 没识别到危险 sink，verifier 无法选择目标。
- `sink.address` 是 external address：后续 symbolic reachability 可能无法定位真实 callsite。

### 3.3 `examples/candidates/toy_01_candidates.rule.generated.json`

这个文件是什么：

- rule-based planner 生成的 benign candidate set。
- 它是 deterministic baseline，不依赖 LLM。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.planner.rule_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.rule.generated.json
```

依赖哪些输入：

- `examples/dangerous_tasks/toy_01_task.real.json`

下一步谁使用它：

- 可被 pipeline 间接生成和验证。
- 可作为 rule planner 输出样例。

关键字段含义：

- `planner.name=rule_based_planner`：说明来源是规则基线。
- `candidates[]`：候选输入列表。
- `candidate_id`：候选输入 ID。
- `strategy`：生成策略，如 `benign_marker_direct`。
- `inputs.ip`：传给 source `ip` 的 benign 输入。
- `safety.weaponized=false`：明确不是武器化 payload。

它能证明什么：

- 证明 rule planner 可以从 task 自动生成符合安全约束的 benign probes。

它不能证明什么：

- 不能证明 candidate 能到达 sink。
- 不能证明 candidate 比 LLM candidate 更好。

常见异常如何判断：

- candidate 为空：source 缺失或 `max_len` 太小。
- 输入不包含 marker：不适合当前 source-to-sink marker 观察。
- 含 `; & |` 等字符：应视为安全校验失败。

### 3.4 `examples/candidates/toy_01_candidates.llm.generated.json`

这个文件是什么：

- API-based LLM planner 生成的 candidate set。
- 当前用户已用 MiMo Token Plan 成功生成。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.llm.generated.json \
  --debug-response
```

依赖哪些输入：

- `examples/dangerous_tasks/toy_01_task.real.json`
- `NS_AEG_LLM_PROVIDER`
- `NS_AEG_LLM_BASE_URL`
- `NS_AEG_LLM_API_KEY`
- `NS_AEG_LLM_MODEL`
- 可选 `NS_AEG_LLM_MAX_TOKENS`

下一步谁使用它：

- `ns_aeg.pipeline.run_planner_verifier --planner llm --candidates ...`

关键字段含义：

- `planner.name=api_llm_planner`：说明来自 API LLM planner。
- `planner.provider`：例如 `openai_compatible`。
- `planner.model`：例如 `mimo-v2.5-pro`。
- `planner.base_url_host`：只记录 host，不记录 API key。
- `planner.max_tokens/temperature`：生成配置。
- `validation`：本地校验报告，记录 candidate 是否覆盖 source、包含 marker、不超长、无危险字符、`weaponized=false`。
- `candidates[]`：LLM 生成的 benign candidates。

它能证明什么：

- 证明 LLM planner 可以生成结构化 benign candidate JSON。
- 若 `validation_failed_count=0`，说明候选通过本地安全/结构校验。

它不能证明什么：

- 不能证明 LLM candidate 有真实 reachability。
- 不能证明 LLM candidate 是最优。
- 不能证明模型没有隐藏推理错误。

常见异常如何判断：

- `finish_reason=length`：模型输出被截断，应提高 `NS_AEG_LLM_MAX_TOKENS`。
- JSON parse 失败：content 不是完整 JSON。
- `validation_failed_count>0`：candidate 不应进入 verifier。
- 缺少 `planner.base_url_host/max_tokens/temperature`：可能是旧版 candidate 文件，pipeline 仍可校验和验证。

### 3.5 `reports/evidence/toy_01_verification.symbolic.json`

这个文件是什么：

- 单个 candidate/task 的机器可读 symbolic verification result。
- 当前是 Step 34/35 的 symbolic result 示例。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.verifier.candidate_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --candidate examples/candidates/toy_01_candidate.example.json \
  --mode symbolic \
  --out reports/evidence/toy_01_verification.symbolic.json
```

依赖哪些输入：

- `examples/dangerous_tasks/toy_01_task.real.json`
- candidate JSON
- angr/claripy
- toy_01 binary

下一步谁使用它：

- `ns_aeg.reports.evidence_report`

关键字段含义：

- `status`：`sat/unsat/timeout/unknown/unsupported`。
- `mode=symbolic_task`：说明是 task-driven symbolic mode。
- `backend=angr`：使用 angr。
- `executed=false`：未具体执行目标二进制。
- `selected_sink`：选中的 sink，toy_01 是 `system @ 0x4011f9`。
- `selected_entry`：入口，toy_01 是 `main @ 0x401176`。
- `sink_reached`：symbolic exploration 是否到达 sink callsite。
- `source_bound`：source symbolic variable 是否出现在 sink 参数中。
- `marker_observed`：sink 参数中是否观察到 benign marker。
- `constraints_summary`：约束摘要。
- `limitations`：当前 backend 限制。

它能证明什么：

- 对 toy_01，当 `status=sat` 且 `sink_reached/source_bound/marker_observed=true`，说明存在 source-to-sink symbolic evidence。

它不能证明什么：

- 不是完整 exploit verification。
- 不证明真实设备/固件可利用。
- 不执行 `system` 或目标命令。

常见异常如何判断：

- `status=unsupported`：angr 不可用、binary 不存在、carrier 不支持或 task 信息不足。
- `sink_reached=false`：未到达目标 callsite。
- `marker_observed=false/unknown`：到达 sink 但未证明 marker 进入参数。

### 3.6 `reports/evidence/toy_01_evidence.symbolic.md`

这个文件是什么：

- `toy_01_verification.symbolic.json` 的人工可读 Markdown 证据报告。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.reports.evidence_report \
  --verification reports/evidence/toy_01_verification.symbolic.json \
  --out reports/evidence/toy_01_evidence.symbolic.md
```

依赖哪些输入：

- `reports/evidence/toy_01_verification.symbolic.json`

下一步谁使用它：

- 人工评审、论文/报告截图、demo 解读。

关键字段含义：

- `Verification status`：验证状态。
- `Symbolic Evidence`：backend、path_status、selected_sink、sink_reached、source_bound、marker_observed。
- `Safety Note`：未执行目标二进制、未执行 system/popen、未生成 weaponized exploit。

它能证明什么：

- 以人类可读方式解释 symbolic evidence。

它不能证明什么：

- 不新增机器证明，只是 JSON 的报告视图。
- 不替代原始 JSON。

常见异常如何判断：

- 字段显示 `not available`：输入 verification JSON 缺字段或来自旧 dry-run。
- 没有 `Symbolic Evidence` 小节：说明不是 `symbolic_task` mode。

### 3.7 `reports/planner_runs/toy_01_rule_symbolic/summary.json`

这个文件是什么：

- rule planner batch verification 的机器可读 summary。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner rule \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_rule_symbolic
```

依赖哪些输入：

- `examples/dangerous_tasks/toy_01_task.real.json`
- rule planner
- symbolic verifier

下一步谁使用它：

- `ns_aeg.reports.planner_summary_report`
- 后续模型/策略对比脚本

关键字段含义：

- `planner.name=rule_based_planner`：规则基线。
- `total_candidates`：candidate 数。
- `status_counts`：批量 verifier 状态统计。
- `sat_count/timeout_count/unsupported_count`：常用计数。
- `best_candidate_id`：按 sat、sink_reached、marker_observed 优先级选择。
- `selected_sink`：本批次验证的主要 sink。
- `sink_reached_count/source_bound_count/marker_observed_count`：symbolic evidence 聚合。

它能证明什么：

- 证明 rule planner 生成的一批 candidates 在 toy_01 上的 symbolic outcome。
- 当前 toy_01 rule pipeline 通常显示 `sat: 4`。

它不能证明什么：

- 不比较 LLM。
- 不证明 rule planner 对其他 binary 泛化。

常见异常如何判断：

- `unsupported_count>0`：有 candidate 或 backend 不支持。
- `best_candidate_id=null`：没有 sat/reached/marker 证据。
- `status_counts` 全是 `unknown`：可能运行的是 dry-run mode。

### 3.8 `reports/planner_runs/toy_01_rule_symbolic/summary.md`

这个文件是什么：

- rule planner batch summary 的 Markdown 报告。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.reports.planner_summary_report \
  --summary reports/planner_runs/toy_01_rule_symbolic/summary.json \
  --out reports/planner_runs/toy_01_rule_symbolic/summary.md
```

依赖哪些输入：

- `reports/planner_runs/toy_01_rule_symbolic/summary.json`

下一步谁使用它：

- 人工评审和 demo 展示。

关键字段含义：

- `Planner`：planner 名称。
- `Status Counts`：sat/unknown/unsupported 等统计。
- `Evidence Counts`：sink/source/marker 证据计数。
- `Selected Sink`：批量目标 sink。
- `Safety Note`：安全边界。

它能证明什么：

- 以人类可读方式总结 rule planner batch 结果。

它不能证明什么：

- 不提供每条 candidate 的详细路径约束。
- 详细证据仍应看 `verifications/*.json` 或 evidence report。

常见异常如何判断：

- `not available`：summary JSON 缺字段或来自旧版本。
- `sat` 为 0：需要检查 individual verification JSON。

### 3.9 `reports/planner_runs/toy_01_llm_symbolic/summary.json`

这个文件是什么：

- LLM planner candidates 的 batch symbolic summary。
- 如果目录不存在，说明尚未运行 LLM pipeline。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --candidates examples/candidates/toy_01_candidates.llm.generated.json \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_symbolic
```

依赖哪些输入：

- `examples/dangerous_tasks/toy_01_task.real.json`
- `examples/candidates/toy_01_candidates.llm.generated.json`
- symbolic verifier

下一步谁使用它：

- `ns_aeg.reports.planner_summary_report`
- 后续 Step 43 模型对比。

关键字段含义：

- `planner.name=api_llm_planner`：API LLM planner。
- `planner.provider`：例如 `openai_compatible`。
- `planner.model`：例如 `mimo-v2.5-pro`。
- `candidate_source`：使用的 candidate 文件路径。
- `validation_passed_count/validation_failed_count`：本地 candidate validation 结果。
- `status_counts`：symbolic verifier 统计。
- `best_candidate_id`：最佳 candidate。

它能证明什么：

- 证明某次 LLM 生成的 candidates 在 toy_01 上的 symbolic batch outcome。
- 当前示例中 LLM candidates 可得到 `sat: 3`。

它不能证明什么：

- 不说明模型在更多任务上的优劣。
- 不足以做严肃模型对比，至少还需要更多任务和重复运行。

常见异常如何判断：

- `validation_failed_count>0`：LLM 输出不应进入 verifier。
- `provider/model` 缺失：candidate 文件可能来自旧版本或手工构造。
- `sat_count=0`：查看 `verifications/*.json` 的 reason。

### 3.10 `reports/planner_runs/toy_01_llm_symbolic/summary.md`

这个文件是什么：

- LLM planner batch summary 的 Markdown 报告。

谁生成它：

```bash
.venv/bin/python -m ns_aeg.reports.planner_summary_report \
  --summary reports/planner_runs/toy_01_llm_symbolic/summary.json \
  --out reports/planner_runs/toy_01_llm_symbolic/summary.md
```

依赖哪些输入：

- `reports/planner_runs/toy_01_llm_symbolic/summary.json`

下一步谁使用它：

- 人工评审。
- 后续模型对比报告的输入参考。

关键字段含义：

- `Planner provider/model`：LLM provider 和模型。
- `Candidate Validation`：candidate 是否通过本地校验。
- `Status Counts`：symbolic 结果统计。
- `Best candidate`：当前批次最佳 candidate。
- `Safety Note`：安全边界。

它能证明什么：

- 以人类可读方式总结 LLM planner batch 结果。

它不能证明什么：

- 不证明 LLM 比 rule planner 更好。
- 不证明对其他 toy 或真实固件有效。

常见异常如何判断：

- `Validation failed` 非 0：优先看 candidate set。
- `Best candidate=not available`：没有 sat/reached/marker 证据。
- `Model=not available`：candidate 文件缺 planner metadata。

## 4. 手动验收流程

从零手动跑 toy_01：

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC
```

导出 Ghidra facts：

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --binary datasets/toy_cgi/build/toy_01 \
  --out examples/ghidra_exports/toy_01_facts.real.json
```

构建 Dangerous Path Task：

```bash
.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_01_facts.real.json \
  --target configs/toy_01.yaml \
  --out examples/dangerous_tasks/toy_01_task.real.json
```

运行 rule planner symbolic pipeline：

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner rule \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_rule_symbolic
```

生成 rule summary Markdown：

```bash
.venv/bin/python -m ns_aeg.reports.planner_summary_report \
  --summary reports/planner_runs/toy_01_rule_symbolic/summary.json \
  --out reports/planner_runs/toy_01_rule_symbolic/summary.md
```

如果有 LLM API 环境变量，生成 LLM candidates：

```bash
export NS_AEG_LLM_PROVIDER=openai_compatible
export NS_AEG_LLM_BASE_URL=https://token-plan-cn.xiaomimimo.com/v1
export NS_AEG_LLM_API_KEY=<your-token>
export NS_AEG_LLM_MODEL=mimo-v2.5-pro
export NS_AEG_LLM_MAX_TOKENS=12000

.venv/bin/python -m ns_aeg.planner.api_planner \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --out examples/candidates/toy_01_candidates.llm.generated.json \
  --debug-response
```

使用已有 LLM candidates 离线跑 symbolic pipeline，避免重复联网：

```bash
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_01_task.real.json \
  --planner llm \
  --candidates examples/candidates/toy_01_candidates.llm.generated.json \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_01_llm_symbolic
```

生成 LLM summary Markdown：

```bash
.venv/bin/python -m ns_aeg.reports.planner_summary_report \
  --summary reports/planner_runs/toy_01_llm_symbolic/summary.json \
  --out reports/planner_runs/toy_01_llm_symbolic/summary.md
```

验收时检查：

- `toy_01_facts.real.json` 中 `system` 是否有 callsite `0x4011f9`。
- `toy_01_task.real.json` 中 `sources` 和 `sinks` 是否非空。
- rule summary 中 `status_counts.sat` 是否大于 0。
- LLM candidate set 中 `validation_failed_count` 是否为 0，或 summary 中 `validation_failed_count=0`。
- LLM summary 中 `status_counts.sat` 是否大于 0。
- Markdown 报告是否保留 safety note。

## 5. 当前能力边界

- 当前主要验证 toy_01 argv-based CGI。
- symbolic backend 当前主要支持 AMD64 `rdi` 首参数检查。
- `snprintf` 是最小 SimProcedure，用于 toy source propagation。
- 当前是 source-to-sink symbolic evidence，不是完整 exploit verification。
- 不执行目标二进制。
- 不执行 `system` / `popen`。
- 不生成 weaponized exploit。
- 真实固件评估尚未开始。

## 6. 什么时候才适合做模型对比 Step 43

暂停模型对比是合理的，适合恢复 Step 43 的条件是：

- rule pipeline 和 LLM pipeline 都能稳定生成 summary。
- 用户能解释 `summary.json` / `summary.md` 的关键字段。
- 至少 toy_01、toy_02、toy_03 有多个可运行任务。
- 每个任务都有 rule baseline 和 LLM candidate set。
- 再做 MiMo-V2.5-Pro vs MiMo-V2.5 的 cross-model report。

在此之前，优先保证 artifacts 含义清晰、验收流程可重复、证据强度不被误读。

