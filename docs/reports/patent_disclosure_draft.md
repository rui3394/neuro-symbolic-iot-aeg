# 发明专利交底书草稿

声明：本文档为内部技术讨论草稿，不是正式法律文件，不替代专利代理人、律师或知识产权部门的专业意见。正式申请前应由专利代理人进行新颖性、创造性、权利要求范围和合规性审查。

## 1. 发明名称候选

候选名称：

1. 一种面向 IoT CGI 二进制的危险路径验证任务构建与触发输入合成方法。
2. 一种基于 Ghidra 静态事实和符号执行的 IoT CGI 危险路径验证系统。
3. 一种面向固件二进制的神经符号危险函数可达性验证与证据生成方法。
4. 一种将逆向分析危险函数告警转化为 source-to-sink 可验证证据的方法及系统。

推荐名称：

```text
一种面向 IoT CGI 二进制的危险路径验证任务构建与触发输入合成方法
```

## 2. 技术领域

本发明涉及软件安全、二进制程序分析、IoT 固件安全、逆向工程辅助分析、符号执行、神经符号系统、漏洞验证和安全证据生成技术领域。

更具体地，本发明涉及一种将 Ghidra 等逆向分析工具抽取的二进制静态事实结构化为验证任务，并结合规则规划器或大语言模型规划器生成非武器化候选输入，再通过符号执行验证 source-to-sink 危险路径可达性的方法、系统、设备和存储介质。

## 3. 背景技术

IoT 设备固件中常包含 Web 管理接口，其中 CGI 二进制程序负责处理 HTTP 请求、系统配置和设备管理操作。此类 CGI 二进制中常见的危险函数包括命令执行函数、格式化函数、文件操作函数和网络操作函数等。安全研究人员通常需要判断外部输入是否可能传播到危险函数参数，并形成可复现证据。

现有技术存在以下不足：

1. Ghidra/IDA 人工分析成本高。

   逆向人员可以在 Ghidra 或 IDA 中手动定位 `system`、`popen`、`snprintf` 等函数调用，但还需要人工区分 external symbol 地址和真实 callsite 地址，追踪 caller function、输入来源和参数传播路径。该过程依赖经验，耗时较长，且难以批量复现。

2. 传统静态 taint 分析容易产生误报或缺少可执行证据。

   静态 taint 可以标记 source 到 sink 的潜在传播，但在二进制层面遇到间接调用、库函数、字符串格式化、路径约束和架构差异时容易产生误报。静态告警通常不能直接说明某个输入是否能使路径可达。

3. 纯符号执行难以从真实逆向上下文中自动选择目标。

   angr 等符号执行工具能够验证路径可达性，但需要明确二进制路径、入口、source 建模、sink 地址和探索目标。若缺少 Ghidra 中的静态上下文，符号执行往往需要大量人工配置。

4. 纯 LLM 方法存在幻觉和不可验证问题。

   大语言模型可以基于反编译代码提出候选输入或分析结论，但模型输出可能出现幻觉，且缺乏与二进制级符号执行证据的强绑定。如果直接生成攻击 payload，还可能带来安全合规风险。

5. 缺少从逆向事实到验证证据的统一接口。

   现有流程往往停留在“发现危险函数”或“手工写 PoC”两端，中间缺少一种结构化任务抽象，将 source、sink、callsite、caller、sanitizer、candidate 和验证结果组织为可复用、可审计的证据链。

## 4. 发明要解决的技术问题

本发明要解决的技术问题是：如何将逆向分析中发现的危险函数告警，转化为结构化、可验证、可复现且非武器化的 source-to-sink evidence。

具体包括：

- 如何从 Ghidra 等逆向工具中自动抽取二进制静态事实。
- 如何区分危险函数 external symbol 地址和真实 callsite 地址。
- 如何将 source、sink、callsite、caller、sanitizer 和 expected oracle 组织为统一验证任务。
- 如何在不生成武器化 exploit 的前提下生成 benign candidate inputs。
- 如何利用符号执行验证 candidate 是否使 source 到达 sink。
- 如何以机器可读和人工可读形式输出证据报告。
- 如何降低 LLM 幻觉对最终结论的影响，使 LLM 输出必须经过本地校验和符号验证。

## 5. 技术方案

本发明提出一种面向 IoT CGI 二进制的危险路径验证任务构建与触发输入合成方法。该方法包括以下步骤。

### 5.1 Ghidra 静态事实抽取

对待分析 IoT CGI 二进制程序进行 Ghidra 或 PyGhidra 静态分析，抽取以下事实：

- 二进制路径、名称、架构、image base。
- 函数名称和函数入口地址。
- imports、externals 和外部符号。
- 字符串字面量。
- 危险函数匹配结果。
- 危险函数 external symbol 地址。
- 指向危险函数的 xrefs/callsites。
- callsite 所属 caller function。
- caller function entry。
- 可选反编译片段。

其中，危险函数可以来自预定义 sink catalog，例如命令执行函数、格式化函数、文件操作函数、网络操作函数等。

### 5.2 Source/Sink/Callsite/Sanitizer 任务抽象

将 Ghidra 静态事实与目标配置文件中的输入 source 信息合并，构造 Dangerous Path Task。该任务至少包括：

- `binary`：二进制路径、名称、架构。
- `entry`：入口函数和入口地址。
- `sources`：source 标识、类型、名称、carrier、最大长度、符号变量名。
- `sinks`：sink 标识、类型、函数名、callsite 地址、参数索引、caller。
- `sanitizers`：可为空，用于记录过滤或净化函数。
- `evidence`：字符串、反编译片段等静态证据。
- `expected`：验证 oracle 和 benign marker。
- `provenance`：facts 文件路径和 target 文件路径。

该任务抽象将逆向工具输出转化为 planner 和 verifier 的统一输入接口。

### 5.3 Planner 生成 Benign Candidate

基于 Dangerous Path Task 中的 source 信息和 benign marker，生成候选输入。Planner 可以包括：

1. 规则规划器。

   根据 source name、max_len 和 benign marker 生成确定性 benign candidates，例如 marker-only、prefix-with-marker、length-boundary-safe 等。

2. API LLM 规划器。

   使用 OpenAI-compatible Chat Completions 接口调用大语言模型生成 candidate JSON，但要求模型只输出非武器化、benign source-to-sink verification inputs。

Planner 输出必须经过本地校验，包括：

- 是否覆盖所有 source。
- 是否包含 benign marker。
- 是否超过 source 最大长度。
- 是否包含危险命令拼接字符。
- `safety.weaponized` 是否为 `false`。

只有通过本地校验的 candidate 才进入 verifier。

### 5.4 Symbolic Verifier 验证路径

符号执行验证器读取 Dangerous Path Task 和 candidate，执行以下操作：

- 根据 task 中的 binary path 加载二进制。
- 根据 source carrier 构造符号化输入。
- 根据 candidate 对符号变量施加约束。
- 根据 task 中 sink 的 callsite 地址设置探索目标。
- 使用符号执行搜索路径是否可达 sink。
- 在到达 sink 后检查 source 符号变量和 benign marker 是否进入 sink 参数或 sink 附近状态。

验证结果包括：

- `status`：`sat`、`unsat`、`timeout`、`unknown` 或 `unsupported`。
- `sink_reached`：是否到达 sink callsite。
- `source_bound`：source 是否与 sink 参数存在绑定证据。
- `marker_observed`：benign marker 是否被观察到。
- `selected_sink`、`selected_entry`、`constraints_summary` 和 limitations。

### 5.5 Marker-based Evidence

本发明使用 benign marker 作为 source-to-sink evidence 的观察机制。Candidate 输入中包含 benign marker，符号执行到达 sink 后检查该 marker 是否出现在 sink 参数或相关内存表达式中。

该机制的特点是：

- 不需要生成真实攻击 payload。
- 可以提供 source 到 sink 的传播证据。
- 可以与人工报告结合，形成可审阅证据链。

### 5.6 Evidence Report 生成

系统将 verification JSON 转换为 Markdown 报告，报告包括：

- task ID 和 candidate ID。
- 二进制信息。
- source 和 sink 检查结果。
- symbolic evidence。
- reason 和 limitations。
- safety note。

系统还可对 planner batch run 生成 summary JSON 和 summary Markdown，记录 candidate 数量、validation 结果、status counts、best candidate 和 selected sink。

## 6. 有益效果

与现有技术相比，本发明至少具有以下有益效果：

1. 降低人工验证成本。

   将 Ghidra 中需要人工记录的函数、sink、callsite 和 caller 自动结构化，减少人工复制地址和手动配置符号执行目标的成本。

2. 将静态危险告警转为可验证证据。

   静态发现 `system` 等危险函数并不等于可达。本发明通过 Dangerous Path Task 和 symbolic verifier 将告警转化为 source-to-sink symbolic evidence。

3. 减少 LLM 幻觉影响。

   LLM 只负责生成 candidate suggestions，其输出必须通过本地结构和安全校验，并由符号执行验证，避免直接信任 LLM 结论。

4. 支持 planner-verifier 闭环。

   规则 planner 和 LLM planner 可以使用同一 task 和 verifier 进行比较，形成可批量评估的闭环。

5. 支持跨架构和跨目标扩展。

   通过将 binary、arch、source、sink、callsite 和参数位置结构化，后续可扩展到更多架构、更多 sink 类型和更多 IoT firmware case。

6. 避免生成武器化 exploit。

   系统使用 benign marker 和 benign candidate inputs 形成证据，不执行危险命令，不输出武器化 payload，更适合研究和合规场景。

## 7. 具体实施方式

以下以 toy_01 IoT CGI 二进制为例说明，但本发明不限定于该示例。

### 7.1 静态事实抽取

系统对 toy_01 二进制运行 Ghidra facts exporter。导出的事实包括：

- functions：18
- imports：5
- externals：5
- dangerous sinks：2
- callsites：2
- strings：81
- decompiled snippets：1

其中识别到：

- `snprintf` callsite：`0x4011ea`
- `system` callsite：`0x4011f9`
- caller function：`main`
- caller entry：`0x401176`

### 7.2 构建 Dangerous Path Task

系统将 Ghidra facts 与 target YAML 合并，得到 task。该 task 记录：

- binary path：toy_01 二进制路径。
- source：`ip`，carrier 为 `argv[1]`。
- sink：`system @ 0x4011f9`。
- expected oracle：`source_reaches_sink`。
- benign marker：`__NS_AEG_MARKER__`。

### 7.3 生成 Benign Candidate

Rule planner 可生成多个 benign candidates，例如包含 benign marker 的普通字符串。API LLM planner 也可生成结构相同的 candidate JSON。

这些 candidates 仅用于验证 marker 是否能从 source 传播到 sink，不包含命令拼接字符，不包含换行，不标记为 weaponized。

### 7.4 符号执行验证

Verifier 使用 angr 加载 toy_01，构造 argv-based symbolic input，约束输入为 candidate 值，并探索到 `system @ 0x4011f9`。当前结果显示：

- `status=sat`
- `sink_reached=true`
- `source_bound=true`
- `marker_observed=true`

这说明在该 toy binary 中，存在 source-to-sink symbolic evidence。

### 7.5 证据报告

系统生成 Markdown evidence report 和 planner summary report。报告中明确说明：

- 未具体执行目标二进制。
- 未执行 `system` 或 `popen`。
- 未生成武器化 exploit。
- 当前结果是 source-to-sink symbolic evidence，不是完整 exploit verification。

## 8. 可选权利要求草案

以下为内部讨论用初稿，正式申请前需由专利代理人重写和审查。

### 权利要求 1：方法权利要求

一种面向 IoT CGI 二进制的危险路径验证任务构建与触发输入合成方法，其特征在于，包括：

1. 对待分析二进制程序进行逆向静态分析，抽取函数、导入符号、字符串、危险函数、危险函数调用点和调用者函数信息；
2. 根据所述静态分析结果和输入源配置，构建包含二进制信息、输入源、危险函数调用点、调用者、验证期望和证据字段的危险路径验证任务；
3. 根据所述危险路径验证任务生成一个或多个非武器化候选输入；
4. 使用符号执行对所述候选输入进行 source-to-sink 可达性验证；
5. 根据验证结果生成机器可读验证结果和人工可读证据报告。

### 权利要求 2：静态事实抽取

根据权利要求 1 所述的方法，其中，所述静态分析结果包括危险函数的外部符号地址和真实调用点地址，并将真实调用点地址作为符号执行验证的目标地址。

### 权利要求 3：任务抽象

根据权利要求 1 所述的方法，其中，所述危险路径验证任务包括 source、sink、callsite、caller、sanitizer、expected oracle、benign marker 和 provenance 字段。

### 权利要求 4：候选输入生成

根据权利要求 1 所述的方法，其中，候选输入由规则规划器或基于 API 的大语言模型规划器生成，且所述候选输入包含 benign marker，并被限制为非武器化验证输入。

### 权利要求 5：候选输入校验

根据权利要求 4 所述的方法，其中，候选输入在进入符号执行验证前经过本地校验，所述校验包括 source 覆盖、长度限制、危险字符检查、benign marker 检查和 weaponized 标记检查。

### 权利要求 6：符号执行验证

根据权利要求 1 所述的方法，其中，符号执行验证包括将候选输入绑定到符号化 source，探索至危险函数调用点，并检查 source 符号变量或 benign marker 是否出现在危险函数参数中。

### 权利要求 7：系统权利要求

一种面向 IoT CGI 二进制的危险路径验证系统，其特征在于，包括：

- 静态事实抽取模块；
- 危险路径任务构建模块；
- 候选输入规划模块；
- 符号执行验证模块；
- 证据报告生成模块；

其中，各模块被配置为执行权利要求 1 至 6 任一项所述的方法。

### 权利要求 8：存储介质权利要求

一种计算机可读存储介质，其上存储有计算机程序，所述计算机程序被处理器执行时实现权利要求 1 至 6 任一项所述的方法。

## 9. 安全与合规说明

本发明的系统输出为 benign verification input 和 source-to-sink evidence，不用于生成或执行真实攻击 payload。系统设计中包括以下安全边界：

- 不具体执行目标二进制。
- 不执行 `system`、`popen` 或其他真实危险命令。
- 不生成 weaponized exploit。
- 不输出命令注入 payload。
- LLM planner 输出必须通过本地安全校验。
- 报告中明确标注当前结果为 source-to-sink symbolic evidence，而非完整 exploit verification。

因此，本发明更适用于安全研究、漏洞验证辅助、固件审计流程自动化和合规证据生成场景。

## 10. 需要专利代理人进一步确认的问题

正式申请前，建议专利代理人重点确认：

- 发明名称是否足够宽泛，是否应强调“任务构建”“验证闭环”或“证据生成”。
- 权利要求是否应覆盖 Ghidra 以外的逆向工具，例如 IDA、Binary Ninja 或自研反汇编器。
- “神经符号”相关表述是否应写入独立权利要求，还是仅作为实施例。
- LLM planner 是否应作为可选实施方式，以避免权利要求过度依赖大模型。
- benign marker-based evidence 是否具备独立创新点，是否应单列权利要求。
- 对“非武器化”“不执行危险命令”的安全边界是否需要写入说明书或权利要求。
- 是否需要增加装置、设备、存储介质和计算机程序产品等多类型权利要求。
- 与现有静态 taint、动态 taint、符号执行、自动 PoC 生成工具之间的新颖性和创造性差异。

