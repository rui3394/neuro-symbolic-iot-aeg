# Toy CGI Target

This directory contains local, authorized toy CGI-like targets for experiments.

`toy_01_basic_cmd.c` simulates an HTTP parameter entering a backend binary and
being concatenated into a command buffer before a `system` call.

Current `toy_01` use is limited to validating source-to-sink analysis:

```text
argv[1] -> snprintf -> system
```

`toy_02_filter_chars.c` is another local test program. It checks the first 32
input bytes for the fixed test byte `0x3b`, prints `NS_AEG_FILTERED` if found,
and otherwise builds a harmless marker command:

```text
argv[1] -> local check -> snprintf -> system
```

`toy_02` exists to validate whether `observe-constraints` can classify an
explicit local input check as a sanitizer candidate. It does not generate input,
does not test real devices, does not access the network, and only prints
harmless marker output.

`toy_03_length_limit.c` is a local length-check test program. It uses an
explicit loop to require a null byte within the first 16 input characters,
prints `NS_AEG_LENGTH_FILTERED` when the local check rejects the input, and
otherwise builds the same harmless marker command:

```text
argv[1] -> length check -> snprintf -> system
```

`toy_03` exists to validate whether `observe-constraints` can observe
length-check style constraints. It does not generate input, does not test real
devices, does not access the network, and only prints harmless marker output.

`toy_04_branch_check.c` is a local branch-condition test program. It requires
`argv[1]` to start with `AB` before reaching the harmless marker command:

```text
argv[1] -> branch check -> snprintf -> system
```

`toy_04` exists to validate whether path constraint observation can classify
source byte equality constraints as branch conditions. It does not generate
input, does not test real devices, does not access the network, and only prints
harmless marker output.

`toy_05_safe_case.c` is a local safe-control test program. It reads `argv[1]`
and prints it to stdout, but the `system` command uses only a fixed harmless
marker:

```text
argv[1] -> printf
fixed marker -> snprintf -> system
```

`toy_05` exists to validate that the analysis does not report source-to-sink
when the source input does not reach the sink argument. It does not generate
input, does not test real devices, does not access the network, and only prints
harmless marker output.
