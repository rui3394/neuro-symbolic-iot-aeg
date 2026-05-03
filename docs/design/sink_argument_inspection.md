# Sink Argument Inspection

## 目的

Step 48 将 symbolic verifier 中的 sink 参数读取逻辑抽象为独立模块：

`ns_aeg/verifier/sink_argument_inspector.py`

此前 toy symbolic verifier 主要在主流程中直接读取 AMD64 的 `rdi`，也就是 SysV ABI 的第一个参数。这对 `system(command)` 足够，但不利于后续支持不同 sink 参数位置、不同 ABI、以及 ARM/MIPS/AArch64 等 IoT 常见架构。

新的 inspector 只读取 symbolic state 中的参数位置和内存内容，不执行目标二进制，不调用 `system`/`popen`，也不生成 weaponized exploit。

## 接口

核心接口：

```python
inspect_sink_argument(
    state,
    project,
    sink,
    arg_index,
    source_symbolic_name="sym_ip",
    benign_marker="__NS_AEG_MARKER__",
    read_size=256,
    arch=None,
)
```

返回结构包含：

- `arch`: 归一化后的架构名；
- `arg_index`: 被检查的 sink 参数编号；
- `register` / `location`: 参数位置；
- `value_repr`: 参数指向字符串的安全预览；
- `contains_marker`: 是否观察到 benign marker；
- `contains_source`: 是否包含 source symbolic variable；
- `method`: 检查方法；
- `limitations`: 当前检查的限制说明。

verification JSON 中的 `source_bound` 和 `marker_observed` 继续保留，并由 `sink_argument.contains_source` / `sink_argument.contains_marker` 推导。

## ABI 映射

当前实现的寄存器参数映射：

| ABI / 架构 | 参数映射 |
| --- | --- |
| AMD64 SysV | arg0=`rdi`, arg1=`rsi`, arg2=`rdx`, arg3=`rcx`, arg4=`r8`, arg5=`r9` |
| ARM32 | arg0=`r0`, arg1=`r1`, arg2=`r2`, arg3=`r3` |
| AArch64 | arg0=`x0`, arg1=`x1`, arg2=`x2`, arg3=`x3`, arg4=`x4`, arg5=`x5`, arg6=`x6`, arg7=`x7` |
| MIPS32 | arg0=`a0`, arg1=`a1`, arg2=`a2`, arg3=`a3` |
| i386 | 参数在栈上，当前标记为 partial/unsupported |

第一版真实回归目标仍是 AMD64 toy_01/toy_02。ARM32、AArch64、MIPS32 当前提供参数位置映射和 graceful result，不声称已经完成真实跨架构 symbolic verification。

## arg_index 来源

优先使用 dangerous path task 中 sink 的 `arg_index`：

- `system` / `popen` 的 command 参数通常是 `arg_index=0`；
- `snprintf` 的 format 参数在当前 sink catalog 中是 `arg_index=2`；
- 如果 task 缺失 `arg_index`，inspector 会尝试从 `sink_catalog` 回退，并在 `limitations` 中记录 `"sink arg_index missing; used sink catalog default"`。

如果无法解析参数编号，结果会标记为 `unsupported_missing_arg_index`，不会伪造证据。

## 当前支持范围

已支持：

- AMD64 SysV register argument 的 symbolic memory string 读取；
- source symbolic variable presence 检查；
- benign marker concrete preview 检查；
- unsupported 架构和参数越界的 graceful result；
- i386 栈参数的明确 partial/unsupported 标记。

尚未支持：

- i386 栈参数真实读取；
- ARM/MIPS/AArch64 真实 binary 回归；
- 复杂 varargs sink 的完整参数语义；
- 多级指针、结构体参数、数组参数；
- taint-equivalence proof 或完整 exploit verification。

## 安全边界

inspector 是只读证据组件：

- 不执行目标二进制；
- 不执行 `system`/`popen`；
- 不生成 shell command injection payload；
- 不输出 weaponized exploit；
- 输出的是 source-to-sink symbolic evidence，不是完整 exploit proof。

## Roadmap

后续可扩展方向：

- Step 49/后续：i386 stack argument inspection；
- ARM/MIPS/AArch64 toy binary 回归；
- sink-specific argument policy，例如 `snprintf` 的 format/value 参数关系；
- 更通用的 pointer/string/byte-array evidence；
- sanitizer-aware verifier 与 planner 的联合解释。
