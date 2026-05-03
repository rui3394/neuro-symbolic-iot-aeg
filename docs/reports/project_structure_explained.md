# 项目目录与文件说明

本文面向开发者和研究者，解释当前仓库的目录结构、核心文件职责、schema 作用、generated artifacts 含义，以及新开发者推荐阅读顺序。

## 1. 项目定位

当前项目定位为：

```text
Ghidra-Assisted Neuro-Symbolic Dangerous-Path Verification and Input Synthesis for IoT CGI Binaries
```

当前重点不是生成 exploit，而是围绕 IoT CGI toy binaries 建立一条可复现的 benign verification pipeline：从 Ghidra 静态事实抽取，到 dangerous path task，再到 rule/LLM planner candidate，再到 symbolic source-to-sink verification 和 evidence report。

## 2. 总体 Pipeline

```text
Ghidra facts
  -> Dangerous Path Task
  -> Planner Candidates
  -> Verifier
  -> Evidence Report
  -> Planner Summary
```

主要命令链路：

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts ...
.venv/bin/python -m ns_aeg.tasks.builder ...
.venv/bin/python -m ns_aeg.planner.rule_planner ...
.venv/bin/python -m ns_aeg.planner.api_planner ...
.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier ...
.venv/bin/python -m ns_aeg.reports.evidence_report ...
.venv/bin/python -m ns_aeg.reports.planner_summary_report ...
```

## 3. 按目录解释

### `ns_aeg/`

项目主 Python package。包含旧 demo pipeline 的基础模块，也包含新 Ghidra-assisted task/planner/verifier/report pipeline。

重要历史模块包括：

- `config.py`：读取 YAML target 配置。
- `sink_finder.py`：旧 sink locating 逻辑。
- `source_model.py`：HTTP/source modeling。
- `reachability.py`、`symbolic_verifier.py`：旧 symbolic source-to-sink verification 基础。
- `candidate_contract.py`：旧 candidate contract 支持。
- `demo_runner.py`、`dataset_runner.py`、`batch_reporting.py`：旧 demo/batch/reporting 流程。

这些文件仍然是项目基础，不应随意删除，因为旧测试和 demo pipeline 仍依赖它们。

### `ns_aeg/ghidra/`

Ghidra/PyGhidra 静态事实导出模块。

- 输入：二进制文件。
- 输出：Ghidra facts JSON。
- Pipeline 步骤：`Ghidra facts`。

### `ns_aeg/tasks/`

Dangerous Path Task 构建与加载模块。

- 输入：Ghidra facts JSON 和 YAML target。
- 输出：dangerous_path_task JSON。
- Pipeline 步骤：`Dangerous Path Task`。

### `ns_aeg/verifier/`

task-driven verifier adapter 和 symbolic task runner。

- 输入：dangerous_path_task JSON、candidate JSON。
- 输出：verification result JSON。
- Pipeline 步骤：`Verifier`。

### `ns_aeg/planner/`

candidate planner 模块。

- `rule_planner.py`：确定性 rule-based baseline。
- `api_planner.py`：API-based LLM planner interface。
- `providers.py`：OpenAI-compatible provider 封装。

Pipeline 步骤：`Planner Candidates`。

### `ns_aeg/pipeline/`

planner -> verifier 的批量闭环 runner。

- 输入：task、planner 选择、可选 candidate set。
- 输出：batch verifications、summary、best candidate。
- Pipeline 步骤：`Planner Candidates -> Verifier -> Planner Summary`。

### `ns_aeg/reports/`

Markdown 报告生成模块。

- `evidence_report.py`：单个 verifier result 的 evidence Markdown。
- `planner_summary_report.py`：planner batch summary Markdown。

Pipeline 步骤：`Evidence Report` 和 `Planner Summary`。

### `schemas/`

JSON Schema 目录。定义跨模块交互文件格式。

这些 schema 的重要性在于：pipeline 中不同阶段通过 JSON 文件解耦，schema 是防止字段漂移、下游误读和测试回归的契约。

### `configs/`

toy target YAML 配置目录。

- `toy_01.yaml` 到 `toy_05.yaml` 描述 toy CGI binary 的 target/source/sink 预期。
- `toy_01.yaml` 当前用于 real Ghidra facts -> task builder。

### `datasets/`

toy CGI C 源码和编译产物。

- `datasets/toy_cgi/*.c`：toy cases 源码。
- `datasets/toy_cgi/build/toy_*`：编译后的 ELF binaries。
- `datasets/toy_cgi/Makefile`：构建 toy binaries。

当前 symbolic task runner 主要验证 `toy_01`。

### `examples/`

示例输入/输出目录。用于测试、文档和手动演示。

### `examples/ghidra_exports/`

Ghidra facts 示例输出。

- `toy_01_facts.example.json`：mock/example facts。
- `toy_01_facts.real.json`：真实 Ghidra/PyGhidra 导出的 toy_01 facts。

### `examples/dangerous_tasks/`

Dangerous Path Task 示例输出。

- `toy_01_task.example.json`：示例 task。
- `toy_01_task.real.json`：由 real facts 和 target YAML 生成的 task。

### `examples/candidates/`

candidate 示例和生成结果。

- `toy_01_candidate.example.json`：单个 candidate 示例。
- `toy_01_candidates.rule.generated.json`：rule planner 输出。
- `toy_01_candidates.llm.generated.json`：API LLM planner 输出。
- `toy_01_candidates.llm.example.json`：offline-example LLM-style 输出。

### `reports/`

运行报告和输出目录。

- 旧 demo reports 位于 `reports/*.json`、`reports/*.md`。
- 新 task-driven reports 位于 `reports/evidence/` 和 `reports/planner_runs/`。

### `reports/evidence/`

单个 verification result 和 evidence Markdown。

- `toy_01_verification.symbolic.json`
- `toy_01_evidence.symbolic.md`

### `reports/planner_runs/`

planner batch runs 输出目录。

典型结构：

```text
reports/planner_runs/toy_01_rule_symbolic/
  candidates.json
  verifications/*.json
  summary.json
  summary.md
  best_candidate.json
```

### `docs/design/`

设计文档目录。记录每个 Step 的设计动机、当前实现范围和限制。

适合查看某个模块“为什么这样设计”。

### `docs/reports/`

系统总结、输出解释和项目结构解释文档。

适合给新开发者、研究合作者、评审人员阅读。

### `tests/`

pytest 测试目录。覆盖旧 demo pipeline、新 Ghidra facts exporter、task builder、verifier adapter、symbolic runner、planner、pipeline 和 reports。

默认测试不要求真实 Ghidra 或真实 LLM API；相关 live tests 是 opt-in。

## 4. 核心文件说明

### `ns_aeg/ghidra/export_facts.py`

- 文件作用：从 Ghidra/PyGhidra 或 example mode 导出二进制静态事实。
- 输入：`--binary` 指向 ELF binary；可选 `--example`；环境变量 `GHIDRA_INSTALL_DIR`。
- 输出：Ghidra facts JSON，例如 `examples/ghidra_exports/toy_01_facts.real.json`。
- 被谁调用：手动 CLI、测试、task builder 的上游流程。
- Pipeline 步骤：`Ghidra facts`。
- 是否建议手动修改：不建议为单个实验临时改逻辑；如需扩展 xref/decompiler 支持，应配套测试和 schema。

### `ns_aeg/ghidra/sink_catalog.py`

- 文件作用：定义危险 sink catalog，如 `system`、`snprintf` 等函数的类型和参数语义。
- 输入：函数名/import symbol。
- 输出：sink metadata。
- 被谁调用：`export_facts.py`。
- Pipeline 步骤：`Ghidra facts`。
- 是否建议手动修改：可以扩展新的 sink，但必须保持 benign verification 边界，并更新测试。

### `ns_aeg/tasks/builder.py`

- 文件作用：把 Ghidra facts JSON 和 YAML target 合成为 Dangerous Path Task。
- 输入：`--facts`、`--target`。
- 输出：`dangerous_path_task.json`，例如 `examples/dangerous_tasks/toy_01_task.real.json`。
- 被谁调用：手动 CLI、tests、后续 planner/verifier。
- Pipeline 步骤：`Dangerous Path Task`。
- 是否建议手动修改：不建议手工改核心映射逻辑；如果 task schema 变化，应同步 schema、example 和 tests。

### `ns_aeg/tasks/loader.py`

- 文件作用：加载并基础校验 dangerous_path_task JSON。
- 输入：task JSON path。
- 输出：Python dict task；错误时抛出清晰异常。
- 被谁调用：verifier、planner、pipeline。
- Pipeline 步骤：`Dangerous Path Task` 下游入口。
- 是否建议手动修改：一般不需要；字段校验变化时再改。

### `ns_aeg/verifier/candidate_verifier.py`

- 文件作用：task-driven candidate verifier CLI。
- 输入：`--task`、`--candidate`、`--mode dry-run|symbolic`、`--out`。
- 输出：verification result JSON。
- 被谁调用：手动 CLI；pipeline 内部复用 lower-level 函数而非 shell 调用。
- Pipeline 步骤：`Verifier`。
- 是否建议手动修改：不建议大改；新增 backend 时应通过 adapter/runner 扩展。

### `ns_aeg/verifier/symbolic_task_runner.py`

- 文件作用：task mode 下的 angr symbolic reachability runner。
- 输入：task adapter config、candidate。
- 输出：symbolic verification dict。
- 被谁调用：`candidate_verifier.py`、`run_planner_verifier.py`、tests。
- Pipeline 步骤：`Verifier`。
- 是否建议手动修改：这是当前 symbolic 核心，修改需谨慎。扩展 toy_02/toy_03 或更多 arch/sink 参数时应加测试。

### `ns_aeg/verifier/task_adapter.py`

- 文件作用：把 dangerous_path_task 和 candidate 转成 verifier 内部配置；提供 dry-run adapter verification。
- 输入：task dict/path、candidate dict/path。
- 输出：`VerifierTaskConfig` 或 dry-run verification result。
- 被谁调用：`candidate_verifier.py`、`symbolic_task_runner.py`、pipeline。
- Pipeline 步骤：`Verifier` adapter 层。
- 是否建议手动修改：可扩展字段映射，但不要破坏旧 task/candidate 兼容。

### `ns_aeg/planner/rule_planner.py`

- 文件作用：确定性 rule-based planner baseline。
- 输入：dangerous_path_task JSON。
- 输出：candidate set JSON，例如 `toy_01_candidates.rule.generated.json`。
- 被谁调用：手动 CLI、pipeline `--planner rule`、tests。
- Pipeline 步骤：`Planner Candidates`。
- 是否建议手动修改：可以增加 benign strategies，但不得生成 weaponized payload。

### `ns_aeg/planner/api_planner.py`

- 文件作用：API-based LLM planner interface；支持 OpenAI-compatible Chat Completions、offline-example、ping、debug response。
- 输入：dangerous_path_task JSON、LLM 环境变量或 `--offline-example`。
- 输出：LLM candidate set JSON，例如 `toy_01_candidates.llm.generated.json`。
- 被谁调用：手动 CLI、pipeline `--planner llm`、tests。
- Pipeline 步骤：`Planner Candidates`。
- 是否建议手动修改：provider/prompt/validation 改动要谨慎；不得记录 API key；不得放宽 weaponized 校验。

### `ns_aeg/planner/providers.py`

- 文件作用：OpenAI-compatible `/chat/completions` provider 封装。
- 输入：base URL、API key、model、messages。
- 输出：message content 字符串；可写 redacted debug。
- 被谁调用：`api_planner.py`。
- Pipeline 步骤：`Planner Candidates` 的 provider 层。
- 是否建议手动修改：可以添加 provider 兼容逻辑，但不得输出 secret。

### `ns_aeg/pipeline/run_planner_verifier.py`

- 文件作用：planner -> verifier 自动闭环 runner。
- 输入：`--task`、`--planner rule|llm`、`--mode dry-run|symbolic`、可选 `--candidates`。
- 输出：batch candidates、每个 candidate 的 verification JSON、summary.json、summary.md 的输入、best_candidate.json。
- 被谁调用：手动 CLI、tests。
- Pipeline 步骤：`Planner Candidates -> Verifier -> Planner Summary`。
- 是否建议手动修改：可以扩展 batch orchestration，但不要重复实现 verifier 逻辑。

### `ns_aeg/reports/evidence_report.py`

- 文件作用：把单个 verification JSON 转成 evidence Markdown。
- 输入：verification JSON。
- 输出：evidence Markdown。
- 被谁调用：手动 CLI、tests。
- Pipeline 步骤：`Evidence Report`。
- 是否建议手动修改：可改报告展示，不应改变 verification 结论。

### `ns_aeg/reports/planner_summary_report.py`

- 文件作用：把 planner batch summary JSON 转成 Markdown。
- 输入：summary.json。
- 输出：summary.md。
- 被谁调用：手动 CLI、tests。
- Pipeline 步骤：`Planner Summary`。
- 是否建议手动修改：可扩展展示字段，如模型对比字段；不应修改 summary JSON 语义。

## 5. Schema 文件说明

### `schemas/ghidra_facts.schema.json`

- 作用：定义 Ghidra facts JSON 的结构。
- 重要字段：binary、functions、imports/externals、sinks、external_address、callsites、strings、decompiled snippets。
- 为什么重要：task builder 依赖这些字段把静态事实转为 task；schema 防止 facts exporter 输出漂移。

### `schemas/dangerous_path_task.schema.json`

- 作用：定义 Dangerous Path Task 结构。
- 重要字段：task_id、binary、entry、sources、sinks、evidence、expected、provenance。
- 为什么重要：这是 planner/verifier 的统一接口，是新 pipeline 的核心契约。

### `schemas/candidate.schema.json`

- 作用：旧 candidate contract 的 schema。
- 为什么重要：保留旧 demo/candidate 兼容；新 planner candidate set 当前由 planner tests 和 validation report 约束。
- 注意：不要随意替换为 LLM candidate set schema，否则可能破坏旧测试。

### 其他 schema

- `planner_input.schema.json`、`planner_output.schema.json`：旧 planner schema。
- `verifier_request.schema.json`、`verifier_result.schema.json`：旧 verifier schema。

它们仍服务旧 demo pipeline，应保持兼容。

## 6. Generated Artifacts 说明

### `examples/ghidra_exports/toy_01_facts.real.json`

- 类型：Ghidra real facts。
- 来源：`ns_aeg.ghidra.export_facts`。
- 用途：task builder 上游输入。
- 关键检查：`sinks` 中 `system` 是否有 callsite `0x4011f9`。
- 手动修改：不建议。应重新运行 exporter。

### `examples/dangerous_tasks/toy_01_task.real.json`

- 类型：Dangerous Path Task。
- 来源：`ns_aeg.tasks.builder`。
- 用途：planner/verifier/pipeline 统一输入。
- 关键检查：`sources`、`sinks` 非空；`binary.path` 指向现有 toy_01 binary。
- 手动修改：不建议。应重新运行 builder。

### `examples/candidates/toy_01_candidates.rule.generated.json`

- 类型：rule planner candidate set。
- 来源：`ns_aeg.planner.rule_planner`。
- 用途：rule baseline 的候选输入。
- 关键检查：candidate 输入包含 benign marker；`weaponized=false`。
- 手动修改：一般不建议；需要实验时应另存新文件。

### `examples/candidates/toy_01_candidates.llm.generated.json`

- 类型：API LLM planner candidate set。
- 来源：`ns_aeg.planner.api_planner`。
- 用途：LLM planner pipeline 输入。
- 关键检查：`planner.model`、`validation_failed_count` 或 pipeline summary validation 字段。
- 手动修改：不建议修改原始生成结果；如需对比，生成不同模型的独立文件。

### `reports/evidence/toy_01_verification.symbolic.json`

- 类型：单 candidate symbolic verification result。
- 来源：`ns_aeg.verifier.candidate_verifier --mode symbolic`。
- 用途：机器可读 evidence；evidence Markdown 输入。
- 关键检查：`status=sat`、`sink_reached=true`、`source_bound=true`、`marker_observed=true`。
- 手动修改：不要修改。

### `reports/evidence/toy_01_evidence.symbolic.md`

- 类型：单 candidate evidence Markdown。
- 来源：`ns_aeg.reports.evidence_report`。
- 用途：人工审阅。
- 关键检查：包含 symbolic evidence 和 safety note。
- 手动修改：可阅读，不建议改生成结果。

### `reports/planner_runs/*/summary.json`

- 类型：planner batch summary。
- 来源：`ns_aeg.pipeline.run_planner_verifier`。
- 用途：批量机器可读评估结果；summary Markdown 输入。
- 关键检查：`status_counts`、`best_candidate_id`、`validation_failed_count`、`selected_sink`。
- 手动修改：不要修改。

### `reports/planner_runs/*/summary.md`

- 类型：planner batch summary Markdown。
- 来源：`ns_aeg.reports.planner_summary_report`。
- 用途：人工审阅和 demo 展示。
- 关键检查：planner/model、validation、status counts、safety note。
- 手动修改：可阅读，不建议改生成结果。

## 7. 不要手动修改的文件

- `reports/evidence/*.json`：verification 机器结果，应由 verifier 生成。
- `reports/planner_runs/*/summary.json`：batch 机器结果，应由 pipeline 生成。
- `reports/planner_runs/*/verifications/*.json`：每个 candidate 的 verifier 输出。
- `examples/ghidra_exports/*real.json`：真实 Ghidra facts，应由 exporter 生成。
- `examples/dangerous_tasks/*real.json`：task，应由 builder 生成。
- `schemas/*.json`：除非正在做 schema migration，否则不要临时修改。
- `datasets/toy_cgi/build/*`：编译产物，应由 Makefile 生成。
- `__pycache__/`：Python 运行缓存，不应提交或编辑。

## 8. 可以手动查看/调试的文件

- `docs/user_guide.md`：使用入口。
- `docs/reports/output_artifacts_explained.md`：输出 artifacts 解释。
- `docs/reports/project_structure_explained.md`：本文。
- `reports/llm_debug/last_response.redacted.json`：LLM provider redacted debug。
- `reports/planner_runs/*/summary.md`：planner batch 人工报告。
- `reports/evidence/*.md`：单 verification 人工报告。
- `examples/candidates/*.json`：candidate 内容可读，但不建议原地编辑。
- `configs/toy_*.yaml`：toy target 配置，可作为新增 target 的模板。
- `datasets/toy_cgi/*.c`：toy binary 源码，可用于理解 expected paths。

## 9. 新开发者推荐阅读顺序

1. `docs/user_guide.md`：先了解如何运行项目。
2. `docs/quickstart_ghidra_assisted_pipeline.md`：复制命令跑 toy_01。
3. `docs/reports/output_artifacts_explained.md`：理解每个输出 artifact 的证据含义。
4. `docs/reports/project_structure_explained.md`：理解目录和核心文件职责。
5. `docs/design/ghidra_facts_exporter.md` 和 `docs/design/ghidra_xref_extraction.md`：理解 Ghidra facts。
6. `ns_aeg/ghidra/export_facts.py`：看 facts exporter 实现。
7. `ns_aeg/tasks/builder.py`：看 facts + YAML 如何合成 task。
8. `ns_aeg/planner/rule_planner.py` 和 `ns_aeg/planner/api_planner.py`：看 candidate 生成。
9. `ns_aeg/verifier/task_adapter.py` 和 `ns_aeg/verifier/symbolic_task_runner.py`：看 verifier adapter 与 symbolic runner。
10. `ns_aeg/pipeline/run_planner_verifier.py`：看 planner-verifier 批量闭环。
11. `tests/test_*`：最后用测试确认行为边界。

## 10. 后续最值得扩展的方向

- 扩展 symbolic backend 到 toy_02/toy_03，覆盖过滤字符和长度约束。
- 增强 sink argument inspection，不只支持 AMD64 `rdi`。
- 增强 sanitizer-aware planning，让 planner 理解过滤/长度/分支约束。
- 增加 LLM vs rule planner 的 cross-model/cross-task comparison report。
- 把 real firmware case study 纳入 pipeline，但仍保持不执行危险命令的安全边界。
- 为 LLM candidate set 增加正式 JSON schema，和旧 `candidate.schema.json` 解耦。

