# Cross-Arch Toy Benchmark

## 目的

Step 49 新增 cross-arch toy benchmark scaffold，用于在进入真实固件前验证当前 pipeline 的跨架构适配边界：

```text
cross-arch toy binary -> Ghidra facts -> Dangerous Path Task -> Rule Candidates -> Symbolic Verifier -> Smoke Summary
```

先做 cross-arch toy，而不是直接真实固件，原因是：

- toy 源码和危险路径可控，便于区分 analyzer bug、ABI 支持缺口和程序语义差异；
- Ghidra facts、task builder、planner、symbolic verifier 可以逐层定位失败；
- 不需要执行目标二进制，也不需要触发真实危险命令；
- 可以为 ARM/MIPS/AArch64 的 sink argument inspection 建立最小回归集合。

## 构建矩阵

构建脚本：

```bash
bash tools/build_cross_arch_toys.sh
```

默认输出：

```text
datasets/toy_cgi/build_cross/
  x86_64/toy_01
  x86_64/toy_02
  arm32/toy_01
  arm32/toy_02
  aarch64/toy_01
  aarch64/toy_02
  mipsel/toy_01
  mipsel/toy_02
  mips/toy_01
  mips/toy_02
```

默认 compiler 矩阵：

| Arch | Compiler |
| --- | --- |
| x86_64 | `gcc` |
| arm32 | `arm-linux-gnueabihf-gcc` |
| aarch64 | `aarch64-linux-gnu-gcc` |
| mipsel | `mipsel-linux-gnu-gcc` |
| mips | `mips-linux-gnu-gcc` |

如果某个 compiler 不存在，脚本不会失败整个构建，而是在 manifest 中记录：

```json
{
  "build_status": "skipped_compiler_missing"
}
```

## Manifest

构建脚本会生成或更新：

```text
examples/cross_arch/toy_benchmark_manifest.json
```

每个 case 包含：

- `toy_id`
- `arch`
- `binary_path`
- `target_yaml`
- `build_status`
- `compiler`
- `notes`

默认仓库内提供一个 `not_built` scaffold manifest，便于测试和文档引用。真实构建后脚本会覆盖为实际 build/skip 状态。

## Smoke Runner

运行 cross-arch smoke：

```bash
export GHIDRA_INSTALL_DIR=/home/kali/tool/ghidra_12.0.4_PUBLIC

.venv/bin/python -m ns_aeg.pipeline.run_cross_arch_smoke \
  --manifest examples/cross_arch/toy_benchmark_manifest.json \
  --out-dir reports/cross_arch/toy_smoke
```

每个已构建且存在的 binary 会尝试：

1. Ghidra facts export；
2. Dangerous Path Task build；
3. rule planner candidate generation；
4. task-driven symbolic verifier；
5. planner summary Markdown。

输出结构：

```text
reports/cross_arch/toy_smoke/
  summary.json
  summary.md
  <arch>_<toy>/
    facts.real.json
    task.real.json
    candidates.rule.json
    planner_summary.json
    planner_summary.md
    planner_run/
```

## 状态含义

- `built`: compiler 成功生成 binary。
- `skipped_compiler_missing`: compiler 不存在，允许跳过。
- `failed`: compiler 存在但编译失败。
- `facts_status=ok/partial`: Ghidra facts export 成功或有 warning。
- `task_status=ok`: task builder 成功。
- `verifier_status=sat`: 至少一个 candidate 在 symbolic mode 下得到 `sat`。
- `verifier_status=unsupported`: symbolic backend 当前不支持该 case 或架构。
- `verifier_status=no_candidates`: planner 没有生成可验证 candidates。

`unsupported` 是允许结果，尤其是非 AMD64 真实 symbolic 回归尚未完整实现时。它不等价于漏洞不存在，也不等价于 verifier bug。

## 与 Sink Argument Inspector 的关系

Step 48 已将 sink argument inspection 从 AMD64 `rdi` 硬编码改为 ABI 映射层：

- AMD64: `rdi/rsi/rdx/rcx/r8/r9`
- ARM32: `r0-r3`
- AArch64: `x0-x7`
- MIPS32: `a0-a3`

Step 49 的 cross-arch scaffold 用于把这些映射从单元测试推进到真实 cross-compiled toy binaries。当前不强制所有架构 `sat`；smoke summary 会记录每个 case 的 `sink_argument_arch` 和 `sink_argument_location`，以便定位 ABI 支持差异。

Step 52 后，cross-arch summary 不再只报告总 `sat`。它还会区分：

- `full_init_sat_count`: 从程序初始化路径达到 sink 的 case 数；
- `direct_main_sat_count`: 通过 `main(argc, argv)` fallback 达到 sink 的 case 数；
- `full_startup_proof_count`: 可以声明 full startup symbolic proof 的 case 数；
- `direct_main_only_count`: 只能声明 direct-main symbolic evidence 的 case 数。

Step 52 时 MIPS/MIPSEL toy 的 `sat` 属于 direct-main evidence，用于受控 toy benchmark debugging。Step 53 修复 MIPS full-init stepping 后，当前 MIPS/MIPSEL toy_01/toy_02 已升级为 full-init evidence。summary 中应以 `full_init_sat_count` 和 `direct_main_sat_count` 为准，而不是只看总 `sat`。

## 允许失败

以下情况是允许的：

- 某个 cross compiler 不存在；
- Ghidra/PyGhidra 不可用；
- 某个架构的 symbolic execution 暂时 `unsupported`；
- Ghidra export 成功但 symbolic verifier 不支持该 ABI 或 loader 行为；
- 某个 case 没有候选输入。

不允许的是：

- 静默失败；
- 伪造 `sat`；
- 跳过程序约束；
- 执行目标二进制或 `system`/`popen`。

## 安全边界

cross-arch benchmark 仍然只做静态事实抽取和 symbolic source-to-sink evidence：

- 不执行目标二进制；
- 不执行 `system`/`popen`；
- 不生成 weaponized exploit；
- 不分析真实固件；
- candidates 仍是 benign verification inputs。

## 后续路线

- 为 ARM32/AArch64/MIPS32 增加真实 toy symbolic 回归；
- 实现 i386 stack argument inspection；
- 增强 `snprintf` / varargs sink-specific policy；
- 建立 cross-arch planner/verifier 对比表；
- 再进入真实固件 case study。

Step 50 的 reachability debug 细节见 `docs/design/cross_arch_reachability_debugging.md`。
