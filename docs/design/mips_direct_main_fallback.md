# MIPS Direct-Main Fallback

## 目的

Step 51 为 MIPS/MIPSEL toy benchmark 增加受控的 `main(argc, argv)` direct startup fallback。它用于调试 angr 在 MIPS ELF startup、loader stub、branch/delay-slot 组合下没有稳定到达 Ghidra callsite 的问题。

Step 53 已定位 full-init 失败根因并做最小修复：MIPS startup stub 中的 `bal`/delay-slot 不适合单指令 stepping，改用 block-level stepping 后 full-init 能到达 `main` 和 sink。因此当前 MIPS/MIPSEL toy_01/toy_02 的 auto 模式会选择 `full_init`，direct-main 主要保留为对比和调试工具。

该 fallback 只用于 toy benchmark 或明确 `task.entry.function=main` 的任务。它不会执行目标二进制，不会执行 `system`/`popen`，不会生成 weaponized exploit。

## 为什么 MIPS full-init 可能失败

在 MIPS/MIPSEL toy 上，`full_init_state(args=...)` 可能卡在 startup/loader 早期路径或遇到单指令 stepping 的 branch/delay-slot 解码问题。Step 50 的 debug 中可以看到：

- recent basic blocks 停在 `_start` 或 early block；
- active states 在到达 Ghidra callsite 前结束；
- Ghidra callsite 与 angr active address 可能不一致；
- `system` 可能通过 extern/PLT/stub 地址暴露给 angr。

因此 Step 51 保留 full-init 结果，同时允许在 `auto` 模式下尝试 direct-main fallback。

## Startup Modes

symbolic verifier 支持：

```text
startup_mode=full-init
startup_mode=direct-main
startup_mode=auto
```

- `full-init`: 从 angr full init state 启动，保留原始 startup 行为。
- `direct-main`: 从 task 中的 `main` 地址创建 `call_state`，构造 `argc/argv`，然后从 `main` 开始执行。
- `auto`: 先尝试 full-init；如果 MIPS full-init 未到达 sink，并且 safe startup policy 允许，再尝试 direct-main。Step 53 后当前 MIPS toy_01/toy_02 已不再需要 fallback。

CLI 示例：

```bash
.venv/bin/python -m ns_aeg.pipeline.run_cross_arch_smoke \
  --manifest examples/cross_arch/toy_benchmark_manifest.json \
  --startup-mode auto \
  --out-dir reports/cross_arch/toy_smoke
```

## Direct-Main 如何建模 argv

direct-main 不直接跳到 sink，而是：

1. 使用 `task.entry.address` 作为 `main` 地址；
2. 构造 `argc`；
3. 在 symbolic state 中分配 `argv` 指针数组；
4. 将 `argv[0]` 写为 binary path；
5. 将 `argv[1]` 绑定为 candidate input 的 symbolic bytes；
6. 按目标 ABI 设置 `main(argc, argv)` 的参数寄存器。

MIPS/MIPSEL 上，参数寄存器为：

- `arg0=a0`
- `arg1=a1`

之后 verifier 仍然从 `main` 内部执行路径约束，探索到 sink candidate address 后才读取 sink argument。

## 证据强度差异

`full-init` evidence：

- 覆盖 loader/startup 到 main 的路径；
- 更接近完整程序启动；
- 可能受 angr loader、startup stub、架构解码限制影响。

`direct-main` evidence：

- 只证明从 `main(argc, argv)` 入口开始的 source-to-sink reachability；
- 不验证 ELF startup/loader 行为；
- 适合受控 toy benchmark；
- 不应直接作为真实固件结论。

当 `auto` 使用 fallback 时，verification JSON 会记录：

```json
{
  "startup_debug": {
    "requested_startup_mode": "auto",
    "attempted_modes": ["full_init", "direct_main"],
    "selected_startup_mode": "direct_main",
    "fallback_reason": "full_init failed to reach sink; direct_main fallback reached sink",
    "full_init_status": "unsat",
    "direct_main_status": "reached"
  }
}
```

Step 52 还会写入 `evidence_strength`：

```json
{
  "evidence_strength": {
    "startup_mode": "direct_main",
    "level": "direct_main_symbolic",
    "can_claim_full_startup_proof": false,
    "requires_explicit_opt_in": false
  }
}
```

真实固件、非 toy 或未知 scope 默认不能自动使用 direct-main fallback。若确实需要调试，必须显式使用
`--allow-direct-main-for-non-toy` 或在 task 中标注 `allow_direct_main=true`。这只应作为建模调试，不应作为独立真实固件结论。

## 当前 MIPS 结果

Step 51 时 cross-arch smoke 中：

- MIPS/MIPSEL full-init 保留原始未到达 sink 的 debug；
- MIPS/MIPSEL direct-main 可以到达 angr loader external `system` symbol；
- sink argument inspection 在 `register:a0` 中观察到 source symbolic bytes 和 benign marker；
- auto 模式将 MIPS/MIPSEL toy_01/toy_02 从 unsat 转为 sat，并明确标记 selected startup mode 为 `direct_main`。

Step 53 后：

- MIPS/MIPSEL full-init 已能到达 `main`；
- full-init 能在 loader external `system=0x500004` 命中 sink；
- auto 模式选择 `full_init`，证据强度升级为 `full_program_startup_symbolic`；
- direct-main 仍可作为显式调试模式运行，但不再是当前 MIPS toy 的默认证据路径。

## 安全边界

- 不执行目标二进制；
- 不执行 `system`/`popen`；
- 不跳过 main 内部路径约束；
- 不直接跳到 sink；
- 不生成 exploit payload；
- direct-main 结果只表示 `main` 内 source-to-sink symbolic evidence。
- direct-main 结果不代表 full program startup proof。

## 后续工作

- 调试 MIPS full-init startup/loader 失败根因；
- 增强 PLT/thunk/callsite 映射；
- 为 MIPS direct-main 增加更小的 unit-level argv memory tests；
- 在真实固件前继续限定 direct-main evidence 的解释范围。
