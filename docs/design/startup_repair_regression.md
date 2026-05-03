# Startup Repair Regression

Step 54 固化 cross-arch startup repair 的回归边界，并把 toy_03 纳入 path/sanitizer-sensitive 负例验证。

## 目的

Step 53 为 MIPS/MIPSEL full-init 增加了保守的 block-level stepping 修复，用于处理 startup stub 中 `bal`/delay-slot 在 angr 单指令 stepping 下导致的 early termination。Step 54 的目标不是继续扩大修复范围，而是确认：

- x86_64、AArch64、ARM32、MIPS、MIPSEL 的 toy_01/toy_02 full-init 结果稳定；
- MIPS/MIPSEL 在 auto 模式下不再依赖 direct-main fallback；
- MIPS/MIPSEL 修复后仍从程序 startup 进入 `main`，再沿 `main` 内部约束到达 sink；
- toy_03 的 sanitizer/path-sensitive negative behavior 不会因为 block-level stepping 修复而被误判为 `sat`。

## 回归断言

cross-arch toy_01/toy_02 的 full-init 回归应满足：

- `full_startup_proof_count=10`
- `symbolic_sat_count=10`
- MIPS/MIPSEL `selected_startup_mode=full_init`
- MIPS/MIPSEL `full_init_repair_applied=true`
- MIPS/MIPSEL `sink_argument.location=register:a0`
- auto 模式下 direct-main 不再是 MIPS/MIPSEL 的首选结果

这些断言不依赖固定 callsite 地址。具体地址可能随重新编译变化，通用测试只检查 matched sink 是否属于 selected sink / callsites / normalized candidates。

## toy_03 负例验证

toy_03 包含 `length_window` sanitizer：输入前 16 字节内必须出现 NUL。当前 benign marker `__NS_AEG_MARKER__` 长度超过该窗口，因此 marker-based source-to-sink evidence strategy 与 sanitizer 条件不兼容。

预期行为是 planner-level rejection：

- `expected_behavior=planner_reject_expected`
- `candidate_count=0`
- `rejected_count>0`
- `rejected_reason=marker_length_exceeds_required_window`
- pipeline graceful 生成 summary

这不是 verifier 崩溃，也不是 exploit 失败；它表示当前 benign marker strategy 与程序路径条件不兼容。

## 证据分层

- `sat`: candidate 被 symbolic verifier 证明可达 selected sink，并观察到 source/marker evidence。
- `unsat`: verifier 对已有 candidate 没有找到可达路径。
- `0 candidates`: planner 没有生成可验证 candidate，通常是 sanitizer/marker planning incompatibility。
- `rejected_candidates`: planner 明确拒绝的策略及原因，不会送入 verifier。

## 安全边界

本回归仅用于 toy benchmark：

- 不执行目标二进制；
- 不执行 `system`/`popen`；
- 不生成 weaponized exploit；
- 不对真实固件做结论；
- 不为了 `sat` 跳过 sanitizer、branch 或 path constraints。

## 后续

后续可以增加专门的 branch-negative toy、短 marker strategy、以及更多 libc startup fixture，进一步确认 startup repair 不引入 false positive。
