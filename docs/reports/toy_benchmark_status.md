# toy_01-toy_11 Benchmark Status

本文记录当前最小多任务 benchmark 的状态。范围仅限 toy CGI binaries，不包含真实固件评估。

## 总览

```text
Ghidra facts -> Dangerous Path Task -> Rule Candidates -> Symbolic Verifier -> Summary/Evidence
```

## 结果表

| Toy | Facts | Task | Rule Candidates | Rejected | Symbolic Status Counts | Best Candidate | 当前解释 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| toy_01 | 成功 | 成功 | 4 | 0 | `sat: 4` | `toy_01_rule_001` | 基础 argv-based command path，source/marker 可达 `system` |
| toy_02 | 成功 | 成功 | 4 | 0 | `sat: 4` | `toy_02_rule_001` | 分号 blacklist sanitizer；rule candidates 不含分号，因此可达 |
| toy_03 | 成功 | 成功 | 0 | 4 | `{}` | `null` | sanitizer-aware planner 识别 marker/window 不兼容，拒绝生成必然不兼容的 candidates |
| toy_04 | 成功 | 成功 | 4 | 0 | `unsat: 4` | `null` | branch-negative：benign candidates 不满足 `AB` branch guard，不应 `sat` |
| toy_05 | 成功 | 成功 | 4 | 0 | `unsat: 4` | `null` | safe-negative：sink 可达但 system(arg0) policy 证明 source/marker 不进入 sink 参数 |
| toy_06 | 成功 | 成功 | 4 | 0 | `sat: 4` | `toy_06_rule_001` | format-flow positive：source/marker 经 snprintf 写入 command buffer，再进入 system(arg0) |
| toy_07 | 成功 | 成功 | 4 | 0 | `unsat: 4` | `null` | format-flow safe-negative：source/marker 进入 format/log buffer，但没有进入 system(arg0) |
| toy_08 | 成功 | 成功 | 4 | 0 | `unknown: 4` | `toy_08_rule_001` | snprintf truncation negative：marker 被 `size` 截断，不得判定为 `sat` |
| toy_09 | 成功 | 成功 | 4 | 0 | `sat: 4` | `toy_09_rule_001` | snprintf truncation positive：buffer 足够，marker 完整到达 system(arg0) |
| toy_10 | 成功 | 成功 | 4 | 0 | `sat: 4` | `toy_10_rule_001` | memcpy-flow positive：memcpy 长度足够，marker 到达 system(arg0) |
| toy_11 | 成功 | 成功 | 4 | 0 | `unknown: 4` | `toy_11_rule_001` | memcpy truncation negative：memcpy 长度不足，marker 被截断，不得判定为 `sat` |

## Cross-Arch 回归状态

Step 60 后，cross-arch manifest 覆盖 `toy_01` 到 `toy_11` 的 x86_64、ARM32、AArch64、MIPSEL、MIPS 构建项，共 55 个 case。

### toy_01/toy_02 full-init 回归

预期：

- `full-init` 模式下 toy_01/toy_02 共 10 个 case 全部 `sat`。
- `full_startup_proof_count=10`。
- x86_64 sink argument 为 `register:rdi`。
- AArch64 sink argument 为 `register:x0`。
- ARM32 sink argument 为 `register:r0`。
- MIPS/MIPSEL sink argument 为 `register:a0`。
- MIPS/MIPSEL `full_init_repair_applied=true`，修复原因为 `mips_full_init_block_level_stepping_for_bal_delay_slot_startup_stub`。
- auto 模式下 MIPS/MIPSEL 应选择 `full_init`，不再依赖 direct-main fallback。

### toy_03 path/sanitizer-sensitive negative behavior

toy_03 的 cross-arch 预期是 planner-level rejection：

- `expected_behavior=planner_reject_expected`
- `candidate_count=0`
- `rejected_count=4`
- `rejected_reason=marker_length_exceeds_required_window`

这用于确认 MIPS block-level stepping 修复不会把 sanitizer/marker 不兼容的负例误判为 `sat`。

### toy_04/toy_05 false-positive regression

toy_04/toy_05 用于确认 verifier 不会把不可证明的 source-to-sink evidence 误报为 `sat`：

- toy_04：branch guard 要求输入以 `AB` 开头，当前 benign marker candidates 不满足该条件，预期 `unsat_expected`。
- toy_05：程序到达固定 benign command sink，但 source/marker 不进入 sink 参数；Step 56 后 sink-specific policy 将其归类为 `negative_evidence`，预期 `unsat`，不得 `sat`。
- `false_positive_count` 统计 `unsat_expected`、`no_sink_expected`、`planner_reject_expected` case 中错误返回 `sat` 的数量。

### toy_06/toy_07 format-flow regression

toy_06/toy_07 用于确认 `snprintf`/`sprintf` format-flow 不能被单独当成 command sink evidence：

- toy_06：`snprintf(cmd, ..., ip)` 后 `system(cmd)`，预期 `format_flow.status=positive` 且 `sink_policy.policy_status=positive_evidence`，全架构 `sat`。
- toy_07：source 进入 format/log buffer，但 `system` 使用固定 benign command，预期 `format_flow.status=negative` 且 `sink_policy.policy_status=negative_evidence`，全架构 `unsat`。
- 关键边界：只有 `system(arg0)` 中观察到 source/marker 才能产生 positive command evidence。

### toy_08/toy_09/toy_10/toy_11 format/memory boundary regression

toy_08/toy_11 用于防止过度简化的 libc/memory model 产生误报：

- toy_08：`snprintf` concrete size 太小，marker 被截断，预期 `unknown`/inconclusive，不得 `sat`。
- toy_09：`snprintf` size 足够，marker 完整进入 `system(arg0)`，预期 `sat`。
- toy_10：`memcpy` concrete length 足够，marker 进入 command buffer 并被 `system(arg0)` 读取，预期 `sat`。
- toy_11：`memcpy` concrete length 太小，marker 被截断，预期 `unknown`/inconclusive，不得 `sat`。

当前 auto/full-init smoke 结果：

- `total_cases=55`
- `symbolic_sat_count=25`
- `symbolic_unsat_count=15`
- `planner_reject_count=5`
- `safe_negative_count=10`
- `format_flow_positive_count=25`
- `format_flow_negative_count=5`
- `truncation_negative_count=10`
- `memcpy_positive_count=5`
- `memcpy_truncation_negative_count=5`
- `false_positive_count=0`

## Facts 状态

### toy_01

- real facts 文件：`examples/ghidra_exports/toy_01_facts.real.json`
- functions：18
- imports：5
- dangerous sinks：2
- callsites：2
- strings：81
- decompiled snippets：1
- selected sink：`system @ 0x4011f9`

### toy_02

- real facts 文件：`examples/ghidra_exports/toy_02_facts.real.json`
- functions：20
- imports：6
- dangerous sinks：2
- callsites：2
- strings：84
- decompiled snippets：1
- selected sink：`system @ 0x40127a`

### toy_03

- real facts 文件：`examples/ghidra_exports/toy_03_facts.real.json`
- functions：20
- imports：6
- dangerous sinks：2
- callsites：2
- strings：84
- decompiled snippets：1
- selected sink：`system @ 0x40127f`

## 生成的关键文件

### toy_02

- `examples/ghidra_exports/toy_02_facts.real.json`
- `examples/dangerous_tasks/toy_02_task.real.json`
- `examples/candidates/toy_02_candidates.rule.generated.json`
- `reports/planner_runs/toy_02_rule_symbolic/summary.json`
- `reports/planner_runs/toy_02_rule_symbolic/summary.md`
- `reports/evidence/toy_02_verification.symbolic.json`
- `reports/evidence/toy_02_evidence.symbolic.md`

### toy_03

- `examples/ghidra_exports/toy_03_facts.real.json`
- `examples/dangerous_tasks/toy_03_task.real.json`
- `examples/candidates/toy_03_candidates.rule.generated.json`
- `reports/planner_runs/toy_03_rule_symbolic/summary.json`
- `reports/planner_runs/toy_03_rule_symbolic/summary.md`
- `reports/evidence/toy_03_verification.symbolic.json`（保留旧单 candidate unsat 示例）
- `reports/evidence/toy_03_evidence.symbolic.md`（保留旧单 candidate unsat 示例）

## 手动复现命令

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC
```

### toy_02

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --binary datasets/toy_cgi/build/toy_02 \
  --out examples/ghidra_exports/toy_02_facts.real.json

.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_02_facts.real.json \
  --target configs/toy_02.yaml \
  --out examples/dangerous_tasks/toy_02_task.real.json

.venv/bin/python -m ns_aeg.planner.rule_planner \
  --task examples/dangerous_tasks/toy_02_task.real.json \
  --out examples/candidates/toy_02_candidates.rule.generated.json

.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_02_task.real.json \
  --planner rule \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_02_rule_symbolic
```

### toy_03

```bash
.venv/bin/python -m ns_aeg.ghidra.export_facts \
  --binary datasets/toy_cgi/build/toy_03 \
  --out examples/ghidra_exports/toy_03_facts.real.json

.venv/bin/python -m ns_aeg.tasks.builder \
  --facts examples/ghidra_exports/toy_03_facts.real.json \
  --target configs/toy_03.yaml \
  --out examples/dangerous_tasks/toy_03_task.real.json

.venv/bin/python -m ns_aeg.planner.rule_planner \
  --task examples/dangerous_tasks/toy_03_task.real.json \
  --out examples/candidates/toy_03_candidates.rule.generated.json

.venv/bin/python -m ns_aeg.pipeline.run_planner_verifier \
  --task examples/dangerous_tasks/toy_03_task.real.json \
  --planner rule \
  --mode symbolic \
  --out-dir reports/planner_runs/toy_03_rule_symbolic
```

## 当前限制

- 当前 benchmark 仍是 toy binaries，不是真实固件。
- symbolic backend 仍主要支持 argv-based CGI 输入。
- sink argument inspection 已抽象为 ABI 映射层；当前 cross-arch toy_01/toy_02 已覆盖 AMD64 `rdi`、ARM32 `r0`、AArch64 `x0`、MIPS/MIPSEL `a0`。
- `snprintf` 仍是最小 SimProcedure。
- toy_02 的 blacklist sanitizer 由 task builder 带入 task，rule planner 会避开 blacklist 字符。
- toy_03 的长度过滤导致当前 marker-based strategy 与 sanitizer 不兼容；planner 会提前拒绝这些 candidates，并在 summary 中报告 `marker_length_exceeds_required_window`。
- toy_04/toy_05/toy_07 是 negative fixtures；它们用于测试误报风险，不用于扩大攻击能力。
- Step 57-60 已加入 toy-level `snprintf`/`sprintf` format-flow evidence；它不是完整 libc varargs 建模。
- `memcpy` 仅有 toy-level concrete-length propagation，不是完整 alias/memory model。

## 下一步建议

Step 60 已加入 format/memory boundary regression，并新增 toy_08/toy_09/toy_10/toy_11。

重点任务：

- 将 i386 栈参数、更多 sanitizer/branch combinations 纳入回归。
- 保持 sanitizer-aware diagnostics 与 verifier evidence 分离。
- 为短窗口 sanitizer 研究替代 benign evidence marker 策略。
- 扩展完整 `snprintf`/`sprintf` varargs、返回值语义和更通用 `memcpy`/`memmove` alias policy。
