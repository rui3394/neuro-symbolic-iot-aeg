# Cross-Arch Reachability Debugging

## 目的

Step 50 为 task-driven symbolic verifier 增加跨架构 reachability debug 信息，用于解释 ARM32/MIPS toy binaries 为什么可能无法到达 Ghidra 导出的 `system` callsite。

本步不执行目标二进制，不执行 `system`/`popen`，不生成 weaponized exploit。所有结果仍然是受控 toy binary 上的 symbolic source-to-sink evidence。

## 为什么 Ghidra Callsite 与 angr Reach Address 会不一致

Ghidra 和 angr 对“调用点”的地址建模可能不同，尤其在非 x86 架构上：

- Ghidra 可能报告 call 指令地址；
- angr 的 active state 可能落在 call 指令、下一条指令、Thumb 地址、PLT stub 或 thunk；
- 某些架构有指令模式位或 delay slot；
- 动态链接 stub、PLT、外部符号地址与真实 callsite 地址不同。

因此 Step 50 不再只检查一个地址，而是构造一个保守的 sink candidate address 集合，并记录实际命中的地址和原因。

## ARM / Thumb Bit

ARM32 binary 可能使用 Thumb 模式。Thumb 地址常通过最低位标识模式：

- Ghidra 可能给出偶数地址，例如 `0x1054c`；
- angr active state 可能表现为 `0x1054d`；
- 这不是“附近任意地址”，而是同一 Thumb callsite 的模式位表示。

当前实现会为 ARM32 增加：

- selected sink address；
- `address | 1` 作为 `thumb_bit_candidate`；
- `address & ~1` 作为 `thumb_cleared_candidate`；
- 小范围 halfword/instruction 前后候选。

命中 Thumb 候选时，verification JSON 会记录：

```json
{
  "matched_sink_address": "0x1054d",
  "match_reason": "thumb_bit_candidate",
  "thumb_adjusted": true
}
```

## MIPS Delay Slot

MIPS branch/call 指令后通常有 delay slot。Ghidra 报告的 callsite、delay slot 和下一条指令在 angr trace 中可能表现不同。

当前实现会为 MIPS32 增加：

- selected sink address；
- `address - 4` 作为 `mips_branch_instruction_candidate`；
- `address + 4` 作为 `mips_delay_slot_candidate`；
- `address + 8` 作为 `mips_after_delay_slot_candidate`。

这些候选窗口很小，且必须是明确架构规则解释的地址；不会把任意附近地址当成 sink。

## PLT / Thunk / External Address

Ghidra facts 同时包含：

- `selected_sink.address`: 当前 task 使用的 callsite 地址；
- `external_address`: imported external symbol 地址；
- `callsites[]`: Ghidra xref/caller extraction 得到的调用点。

Step 50 的 debug 字段会记录这些信息。对于明显不是代码地址的小 external address，例如 `0x3`、`0x5`，runner 不会把它作为可达目标。

在 angr loader 中，imported sink 也可能有独立的 external symbol 地址，例如 MIPS toy 中的 `system` 可表现为 `0x500004`。该地址会以 `loader_external_symbol_address` 记录，并与 Ghidra 的小 external id 区分。

## Reachability Debug 字段

symbolic verification JSON 新增 `reachability_debug`：

- `arch`
- `binary_path`
- `entry_address`
- `selected_sink_address`
- `selected_sink_external_address`
- `selected_sink_callsites`
- `sink_address_candidates`
- `matched_sink_address`
- `match_reason`
- `thumb_adjusted`
- `delay_slot_adjusted`
- `reached_addresses_near_sink`
- `active_state_count`
- `deadended_state_count`
- `errored_state_count`
- `recent_bbl_addrs`
- `reason`

未到达 sink 时，也会保留 debug 字段，而不是只输出 `"selected sink callsite was not reached"`。

## 当前实现结果

当前 cross-arch toy smoke 中：

- x86_64 toy_01/toy_02 仍命中 `register:rdi`；
- AArch64 toy_01/toy_02 仍命中 `register:x0`；
- ARM32 toy_01/toy_02 通过 Thumb bit candidate 命中 `register:r0`；
- MIPS/MIPSEL toy_01/toy_02 在 Step 51 后可通过 direct-main fallback 到达 loader external `system` symbol，并在 `register:a0` 中观察 source/marker。

MIPS full-init 未到达 sink 的结果仍保留为对比，不应解释为程序路径不可达的最终证明。

## 安全边界

- 不执行目标二进制；
- 不执行 `system`/`popen`；
- 不生成 exploit payload；
- 不跳过路径约束；
- 只有命中明确 sink candidate address 后才读取 sink argument；
- 如果 reach 到 sink 但参数检查失败，结果应为 `unknown`，不是 `sat`。

## 后续工作

- 继续调试 MIPS/MIPSEL 的 full-init startup/main transition；
- 保持 direct-main fallback 与 full-init evidence 的证据强度区分；
- 增强 PLT/thunk target extraction；
- 将 MIPS delay slot 命中场景纳入真实 sat 回归；
- 为 ARM32/AArch64/MIPS 增加更细的 argument-state tests。
