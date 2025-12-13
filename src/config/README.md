## 概述
采用分层配置 `loader.rc` 格式，默认不再自动加载配置文件；`elf/src/config/loader.rc.sample` 仅为样板。运行时如需配置，请用 `-c /path/to/loader.rc` 指定。

## 结构与语法
- 注释 `#` 开头，空行忽略。
- 段落：`[Host Layer]`、`[Guest Layer]`。
- 指令：指令名 + 空格 + 参数。

### Host Layer（loader / 子 loader）
- `ROOT <path>`：容器根。
- `BIND <host>:<guest>`：可多次。
- `DEBUG <0-4|on|off>`：日志级别，对应 HOOK_LOG。`4`/`on` 输出完整调试日志（桩岛 hook 也在此级别），`0`/`off` 关闭。
- `PAYLOAD <path>`：payload 路径。

### Guest Layer（tiny-init）
- 已实现：`ENV KEY=VAL`、`WORKDIR <path>`、`CMD <cmd line>`（直接拆 argv 并 execvp，不再 `/bin/sh -c`；未指定时默认 `/bin/sh`）。
- 预留未实现（忽略）：`RUN`、`DAEMON`、`USER` 等。
- 钩子范围（可选）：`HOOK_RANGE min-max` 作用于目标，`HOOK_RANGE_INTERP min-max` 作用于解释器（如 musl）。用于缩小扫 SVC 范围，便于定位问题。

## 解析与传递
1) Loader 读取 Host 段并应用 ROOT/BIND/DEBUG/PAYLOAD。
2) Guest 段原样写入匿名 memfd；子 loader 仅需 Host 段。
3) `--init` 时，loader 通过环境变量 `INIT_CONFIG_FD` 把 memfd 传给内嵌 tiny-init；tiny-init 启动时解析：
   - ENV → setenv
   - WORKDIR → chdir
   - CMD → `/bin/sh -c`
   - 未实现指令忽略。

## 示例
```
[Host Layer]
ROOT /storage/Users/currentUser/alpine
BIND /bin:/storage/Users/currentUser/alpine/bin
DEBUG 4
PAYLOAD /data/service/hnp/horpkg-base.org/horpkg-base_1.0/bin/payload.bin

[Guest Layer]
ENV HOME=/home
WORKDIR /opt
CMD /bin/sh
# 仅对 musl 扫前 200 个 SVC，用于调试
HOOK_RANGE_INTERP 0-200
```
启动：`elfloader --init -c /path/to/loader.rc -- bin/busybox sh`
