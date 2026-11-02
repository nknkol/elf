# 本轮审查修复的统一测试需求

范围：59c7dd9（R1–R5），以及之后的竞争与异常修复 4d74389、e5ff903、dc6a40e。每条需求对应具体用例，写明
前置条件、操作、预期结果和宿主后置检查；状态分“已有”（已在回归中运行）和“待补”。

## 通用约定

- **环境**：HarmonyOS 真机（HongMeng Kernel 1.13.0，AArch64），在设备上原生构建与运行（[STATUS](STATUS.md)
  里的设备流程）。隔离用例用 `build/elfloader-guarded` 加 `--isolate`；OCI 用例用测试专用存储
  （`ELF_OCI_TEST_HOME`）和 `test/alpine:1` 镜像，常规与 `--isolate` 各跑一遍（下文标“两种模式”）。
- **哨兵**：树外或上下文外放内容唯一的哨兵（含随机后缀）。任何输出、镜像内容或 guest 可见数据中出现哨兵
  即失败；宿主侧在操作前后对哨兵所在目录比较名字、模式、大小、时间与内容。
- **伪造请求**：`test/isolation/probe.c` 的 `lazy` 操作从 guest 直接向 broker 发 `BROKER_LAZY_MOUNT`，绕过
  payload。带次数 N 时先输出 `ready`、等宿主一行输入，再连发 N 次，按返回值计数（`lazy-rc RC COUNT`）。
- **竞争用例**：宿主线程在 guest 输出 `ready` 之后才开始改动，保证 broker 启动时的树登记不受干扰。每个竞争
  用例都用修复前的 loader 跑过一遍确认会失败（下文“修复前”），证明用例确实能抓到问题。
- **注入用例**：OCI 的暂停用例在测试进程内导入 `tools/oci`，替换 `os.killpg`、`runtime.stopped`、
  `runtime.read_proc`、`runtime.list_proc` 或 `build.commit_paused`。`build.commit_paused` 被替换为记录调用，
  记录为空即说明没有进入文件扫描。
- **入口**：R1 → `make check-isolation`（`test/isolation/lazy_nested.py`）；R2、R4、R5 → `make check-oci`
  （`test/oci/run.py`）；R3 → `test/fs_policy/agent_launch.py`、`test/agent_sandbox/test_launch.py`。

## 总览

| 需求 | 已有用例 | 待补用例 |
|---|---|---|
| R1 层镜像展开不越过受保护子树 | T-R1-01 至 T-R1-04 | T-R1-05 至 T-R1-09 |
| R2 构建上下文不读上下文外的文件 | T-R2-01 至 T-R2-04 | T-R2-05 至 T-R2-08 |
| R3 启动器不把继承的 FD 交给 guest | T-R3-01 | T-R3-02、T-R3-03 |
| R4 `commit --pause` 真正暂停、唯一所有者、失败即恢复 | T-R4-01 至 T-R4-12 | T-R4-13 至 T-R4-16 |
| R5 监视进程失效后主进程组不残留 | T-R5-01 | T-R5-02 |

## R1 层镜像展开（broker）

需求：broker 代为展开或填充层镜像缓存时，不得读写缓存中受保护（`r`、`d`、glue、loader 文件）的子树。检查
做在遍历实际打开的对象上，不受检查之后的改名、链接替换影响。来源：R1（59c7dd9）、竞争修复（4d74389）、完成
标记修复（e5ff903）。

公共前置（T-R1-01 至 T-R1-04）：`/rw` 为可写卷。受保护子树另以单独的挂载登记，权限向量 `dwr`（只读）和
`dwd`（拒绝）各跑一遍。镜像与缓存均位于 guest 可读的位置，只有缓存的权限是被测对象。

### T-R1-01 静态嵌套：展开与填充被拒（已有）

- 用例：`lazy_nested.py` 中的 `{vector}: expand protected / expand the cache root / fill protected/a inside a
  protected subtree is refused`，以及 `{vector}: protected unchanged`。
- 前置：镜像含 `top`、`protected/a`、`protected/new`。宿主先展开缓存根与 `protected`，再删掉
  `protected/new`（展开会把它加回来）；`cache/protected` 单独挂载到 `/prot`。
- 操作：伪造请求，依次展开 `/protected`、展开 `/`（缓存根），填充 `/protected/a`。
- 预期：三个请求都返回 EACCES。
- 宿主后置：`cache/protected` 的快照（每个条目的名字、模式、大小、mtime、atime、内容）与操作前一致：`new`
  未被加回，`a` 仍是占位文件。

### T-R1-02 对照：没有受保护子树的缓存照常展开（已有）

- 用例：`a cache with nothing protected inside still expands`。
- 前置：同一镜像，空缓存 `cache2`，其中没有任何受保护子树。
- 操作：伪造请求展开 `/`。
- 预期：返回 0。
- 宿主后置：`cache2/top` 存在，`cache2/protected` 是目录。这一项也证明 T-R1-01 的拒绝来自权限检查，而不是
  镜像不可读。

### T-R1-03 检查之后才移进缓存的受保护子树（已有）

- 用例：`{vector}: a protected subtree moved into the cache after the check is refused where met`，以及
  `{vector}: protected unchanged while moved in and out`。
- 前置：镜像含 `holder/protected/{a,new}`。宿主展开后删掉 `new` 和 `protected` 的完成标记，把 `holder` 移到
  `/rw/outside`；`outside/holder/protected` 单独挂载。
- 操作：guest 就绪后，宿主线程每约 0.5 ms 把 `holder` 在 `outside` 和 `cache3` 之间来回移动；同时 guest
  连发 400 次展开 `/holder/protected`，再连发 400 次填充 `/holder/protected/a`。
- 预期：每组计数合计 400，没有 0（成功），且出现过 EACCES（其余为路径不在时的 ENOENT）。
- 宿主后置：`protected` 的快照不变。
- 修复前：59c7dd9 的 loader 有 28–50 次成功，`new` 被加回、`a` 被填充。

### T-R1-04 完成标记被换成指向树外的链接（已有）

- 用例：`a symlink at the completion marker never creates the path it points to`。
- 前置：镜像目录 `many` 含 300 个空文件（拉长“检查标记不存在”到“创建标记”之间的窗口）。宿主已展开缓存根；
  `secret/` 不在任何树内，`secret/created-by-marker` 不存在。
- 操作：guest 就绪后，宿主线程循环执行：删掉已完成的普通标记文件，在 `many/.wh..elf-lazy` 放一个指向
  `secret/created-by-marker` 的符号链接，再删掉它；同时 guest 连发 400 次展开 `/many`。
- 预期：计数合计 400，返回值只有 0（标记已在）或 -ELOOP（拒绝这个链接）。
- 宿主后置：`secret/created-by-marker` 不存在（`lexists`），`secret/` 为空。
- 修复前：4d74389 的 loader 经这个链接在 `secret/` 下建出了文件。另外，标记创建在 EEXIST 之后发现链接已被
  删掉时会重试；该情形曾返回过一次 ENOENT，加入重试后连续 3 轮通过。

### T-R1-05 新建条目的 chmod 不跟随换进来的链接（待补）

- 对应修复：`lazy_layer.c` 的 `chmod_made`（4d74389）；宿主侧 `erofs.py` 的 `_chmod_made`（e5ff903）。
- 前置：镜像含模式为 0755 的目录条目和一个 FIFO 条目；树外哨兵文件模式为 0600。
- 操作：guest 反复展开该目录，宿主线程不断把临时名 `.wh..elf-lazy-tmp`（目录条目在这里创建）和 FIFO 的名字
  换成指向哨兵的符号链接。
- 预期：请求的返回值不作要求（`chmod_made` 失败时调用方忽略，条目保留创建时的模式）。
- 宿主后置：哨兵的模式、内容、mtime 不变。

### T-R1-06 改名不覆盖期间出现的同名条目（待补）

- 对应修复：`place_child`（`RENAME_NOREPLACE`）。
- 前置：可写缓存中待展开的目录。
- 操作：展开期间，宿主在子条目的最终名字上抢先建出自己的文件。
- 预期：请求返回 0。
- 宿主后置：该名字仍是宿主建的那个 inode（inode 号和内容不变），临时名已清理。
- 备注：存储不支持 `RENAME_NOREPLACE` 时会退回覆盖，用例需先探测存储是否支持，不支持则记为不适用。

### T-R1-07 填充写入的必须是检查并加锁的那个文件（待补）

- 对应修复：`fill_at` 比对写入 FD 与加锁 FD 的 (dev, ino)。
- 前置：缓存中有一个占位文件；可写区另有一个普通文件 `victim`。
- 操作：反复伪造填充请求，宿主线程在两次打开之间把占位文件的名字换成 `victim`（改名覆盖）。
- 预期：请求返回 0 或 EAGAIN。
- 宿主后置：`victim` 的内容与大小不变。

### T-R1-08 下层缓存路径同样受保护（待补）

- 对应修复：`lazy_request`（下层缓存，`self=1`）与 `BROKER_LAZY_MOUNT` 共用 `lazy_check_object`。现有用例
  只覆盖后者。
- 前置：`--lower` 指定一个层镜像缓存，缓存内某个子目录另以只读或拒绝挂载登记。
- 操作：伪造下层缓存的展开或填充请求，目标在该子目录内；再做一个竞争变体（同 T-R1-03）。
- 预期：EACCES，从未成功。
- 宿主后置：子目录快照不变。

### T-R1-09 宿主侧 `erofs.py` 的完成标记与 chmod（待补）

- 对应修复：`erofs._make_marker` 与 `_chmod_made`。这条路径由 `docker cp`、guestfs、`--cow` 的宿主读取触发，
  以宿主身份执行。
- 前置：已展开父目录的缓存；树外哨兵路径不存在。
- 操作：(a) 在目标目录预先放一个指向哨兵路径的符号链接标记，删掉完成标记后调用 `erofs.expand`；(b) 竞争
  变体：宿主线程在展开期间放置这个链接。
- 预期：(a) 得到 ELOOP 错误；(b) 只有成功或 ELOOP 两种结果。
- 宿主后置：哨兵路径不存在。

## R2 构建上下文

需求：构建只读取上下文内的文件。链接不能把读取引到上下文外；`.dockerignore` 排除的文件从不打开；OCI 存储
即使在上下文内也不会被复制。来源：R2（59c7dd9）、上下文快照修复（4d74389）。

### T-R2-01 上下文里的链接读不到上下文外（已有）

- 用例：`build: context links never read outside the context (COPY, ADD, directory, RUN --mount bind; absolute
  and relative links)`。
- 前置：`outside-ctx/sentinel` 与 `outside-ctx/dir/f` 含随机哨兵；上下文中 `abs` 是指向 `outside-ctx` 的绝对
  链接，`rel` 是 `../outside-ctx`。
- 操作：对 `abs` 和 `rel` 各构建 6 个镜像：`COPY link/sentinel`、`ADD link/sentinel`、`COPY link/dir`、
  `COPY link/dir/`、`RUN --mount=type=bind,source=link/sentinel`、`RUN --mount=type=bind,source=link`（读
  `/m/sentinel`）；构建成功的镜像再运行一次，显示复制或读到的内容。
- 预期：12 个构建的输出和镜像内容都不含哨兵（构建失败也可以接受）。
- 宿主后置：构建只读，未做后置检查；补一项 `outside-ctx` 前后快照一致（待补）。

### T-R2-02 上下文内的链接照常可用（已有）

- 用例：`build: links inside the context still work`。
- 操作：`alias` 链接到 `inside`，`COPY alias /alias`。
- 预期：镜像中 `/alias` 仍是链接（`readlink` 得到 `inside`），读出 `inside`。

### T-R2-03 被忽略的文件从不读取，例外规则仍生效（已有）

- 用例：`build: ignored files are never read (unreadable ones too); exceptions still apply`。
- 前置：`.dockerignore` 为 `deps`、`!deps/keep`、`*.tmp`。`deps/big` 目录及其中文件模式为 0，
  `unreadable.tmp` 模式为 0，`deps/keep` 可读。
- 操作：`COPY . /ctx/` 后列出 `/ctx`。
- 预期：构建成功；`/ctx` 恰为 `.dockerignore`、`Dockerfile`、`app`、`deps`、`deps/keep`。
- 宿主后置：测试结束时恢复 `deps/big` 的模式（清理）。补一项上下文内容与模式前后一致（待补）。

### T-R2-04 存储位于上下文内时不被复制（已有）

- 用例：`build: a store inside the context is not copied into it`。
- 前置：上下文 `store-ctx` 下的 `store/` 作为 OCI 存储（`ELF_OCI_HOME`）。
- 操作：`FROM scratch` 加 `COPY . /ctx/`，然后保存镜像并列出所有层。
- 预期：构建成功；层中有 `ctx/f`，没有任何 `ctx/store` 开头的条目（不递归复制自身）。

### T-R2-05 `.dockerignore` 是链接或不是普通文件（待补）

- 前置：`.dockerignore` 分别为指向上下文外文件的符号链接、目录、FIFO。
- 操作：构建。
- 预期：构建失败，报 `cannot read .dockerignore`，不会因 FIFO 卡住。
- 宿主后置：链接目标的 atime 不变（或用不可读的目标证明它从未被打开）。

### T-R2-06 缓存键遵守例外规则（待补）

- 对应修复：`hash_tree` 与 `copy_into` 共用 `skipped`。
- 前置：同 T-R2-03 的规则，先构建一次。
- 操作：(a) 修改 `deps/keep` 后重新构建；(b) 修改被排除的 `deps/big/x` 后重新构建。
- 预期：(a) COPY 步骤的缓存失效；(b) 缓存命中。

### T-R2-07 含 `**` 的例外规则（待补）

- 前置：`.dockerignore` 为 `*`、`!**/*.go`；上下文中有多级目录，各级都有 `.go` 和非 `.go` 文件，其中一个
  非 `.go` 文件不可读。
- 操作：`COPY . /ctx/`。
- 预期：构建成功，各级 `.go` 文件全部复制，其他文件都没有。

### T-R2-08 快照之后上下文被改动（待补）

- 前置：Dockerfile 中先 `RUN sleep` 若干秒，再 `COPY`。
- 操作：构建期间，宿主把上下文里的某个文件换成指向上下文外哨兵的链接。
- 预期：COPY 得到的是快照时的内容。
- 宿主后置：镜像中没有哨兵。

## R3 agent 启动器的继承 FD

需求：启动器把 stdio 以外的继承 FD 全部设为 close-on-exec，只有用 `--pass-fd` 显式交出的 FD 到达 guest。
来源：R3（59c7dd9）。

### T-R3-01 留着的 FD 到不了 guest，stdio 和 `--pass-fd` 可以（已有）

- 用例：`agent_launch.py` 的 `PASS: FDs the caller left open do not reach the guest; stdio and --pass-fd do`，
  两种后端（`isolate`、`in-process`）各一遍。
- 前置：父进程打开上下文外的只读文件 `secret`（内容 `LEFT-OPEN-SECRET`）、追加写打开的 `target`（内容
  `unchanged`）、外部目录和一端 UNIX socket，并用 `pass_fds` 留给子进程；另建一个已写入 `granted` 的 pipe，
  其读端用 `--pass-fd` 交出。
- 操作：guest shell 对每个 FD 尝试重定向，`cat` 读 `secret`，向 `target` 写入，再 `cat` 读 pipe。
- 预期：`secret`、`target`、目录、socket 四个 FD 都打不开，pipe 读端打得开并读出 `granted`；输出中没有
  `LEFT-OPEN-SECRET`。
- 宿主后置：`target` 内容仍为 `unchanged`。

### T-R3-02 `--pass-fd` 的参数处理（待补，行为待定）

- 位置：`test/agent_sandbox/test_launch.py`。
- 现状：`launch.py` 不校验，未打开的 FD 和负数都被静默忽略，0–2 与重复值无影响。
- 待定：未打开的 FD 是否应报错（建议报错，以免调用者误以为已交出）。定下后用例固定该行为。
- 操作：`--pass-fd` 分别给未打开的 FD、负数、0–2、重复值。
- 预期：按定下的行为；无论如何，stdio 始终保留，其他未列出的 FD 始终被关闭。

### T-R3-03 进程内后端下交出的 FD 仍受规则约束（待补）

- 依据：文档写明，进程内防护下交出的 FD 仍受原有规则约束（可以读继承的流，不能写），broker 后端下 guest
  可以直接使用。
- 操作：用 `--pass-fd` 交出一个 pipe 的写端，guest 向它写入。
- 预期：`in-process` 后端写入被拒，`isolate` 后端写入成功。
- 宿主后置：两种后端下宿主从 pipe 读端读到的内容与预期一致。

## R4 `commit --pause`

需求：
- 读取容器文件期间，容器的所有进程（主进程组和登记的 exec 进程组）都已确认停下。
- 暂停有唯一所有者，只有所有者的恢复能继续容器。
- 不能确认全部停下（发不出信号、超时、读不到状态、`/proc` 无法枚举、任何异常或中断）时，不读取任何文件，
  立即恢复所有进程组并清除暂停状态。

来源：R4（59c7dd9）、所有权与超时（4d74389）、状态不可读（e5ff903）、整体清理（dc6a40e）。HongMeng 在
`/proc` 里把停止的任务显示为 `S`，测试用的停止判断与运行时相同：逐线程看，状态为 T/t/Z/X，或 wchan 为
`thread_precheck_deliver_signal`。

公共前置（T-R4-01 至 T-R4-12，两种模式）：以 root 运行容器 `pausing`，命令为不停地把递增计数写入 `/a` 和
`/b` 的循环，运行 1 秒后开始。T-R4-03 起另用 `docker exec -d` 启动 `sleep 300`，因此有两个进程组。

### T-R4-01 提交期间暂停，层与镜像 rootfs 一致（已有）

- 用例：`commit --pause: the layer and the image rootfs agree; the container runs on`。
- 操作：`docker commit pausing test/paused:1`。
- 预期：退出码 0；新镜像最后一层里 `a`、`b` 的内容与运行新镜像 `cat /a /b` 的输出一致。
- 宿主后置：提交后主进程未处于停止状态；相隔 0.5 秒两次 `exec cat /a` 的结果不同（容器在继续运行）。

### T-R4-02 提交失败也会恢复容器（已有）

- 用例：`commit --pause: a failed commit continues the container`。
- 操作：`docker commit -c 'FROM busybox'`（非法的修改，在暂停期间失败）。
- 预期：退出码非 0。
- 宿主后置：主进程未停止；`docker exec pausing true` 成功。

### T-R4-03 第二次暂停被拒，且不会恢复第一个所有者的暂停（已有）

- 用例：`commit --pause: a second pause is refused and does not continue the first owner's`。
- 前置：测试进程调用 `runtime.pause` 成为所有者。
- 操作：另起 `docker commit`；完成后测试进程调用自己的恢复函数。
- 预期：`docker commit` 退出码非 0，报 `already paused`；在所有者恢复之前，两个进程组都仍处于停止状态。
- 宿主后置：恢复后两个组都在运行；`Paused` 为 False，`PauseOwner` 为空。

### T-R4-04 至 T-R4-11 无法确认全部停下时中止（已有，注入）

用例名统一为 `commit --pause: <情形>: nothing is read, every group continues`。

| 编号 | 情形 | 注入 |
|---|---|---|
| T-R4-04 | a group that cannot be stopped | 对 exec 组发 SIGSTOP 时抛 EPERM |
| T-R4-05 | processes that do not stop in time | `stopped()` 恒为 False，5 秒超时 |
| T-R4-06 | a process whose stat cannot be read | 读主进程的 `/proc/PID/stat` 抛 EACCES |
| T-R4-07 | a process whose threads cannot be listed | 列组成员的 `/proc/PID/task` 抛 EIO |
| T-R4-08 | a thread whose wchan cannot be read | 读组成员线程的 `wchan` 抛 EACCES |
| T-R4-09 | /proc that cannot be listed | 枚举 `/proc` 本身抛 EMFILE |
| T-R4-10 | an unexpected error while waiting | `stopped()` 抛 RuntimeError |
| T-R4-11 | an interruption while waiting | `stopped()` 抛 KeyboardInterrupt |

- 操作：调用 `build.cmd_commit`（其中 `commit_paused` 已替换为记录调用）。
- 预期：抛出含 `cannot pause` 的错误（T-R4-11 为中断原样抛出）；`commit_paused` 没有被调用。
- 宿主后置：0.2 秒后两个进程组都在运行；`Paused` 为 False，`PauseOwner` 为空。
- 备注：T-R4-08 依赖 HongMeng 把停止的任务显示为 `S`（因而会去读 wchan）；在 Linux 上任务显示为 T，不读
  wchan，该项不适用。

### T-R4-12 所有者死亡后的暂停在下次查看时恢复（已有）

- 用例：`a pause whose owner died is continued when the container is next looked at`。
- 前置：宿主对两个组发 SIGSTOP，把状态写成 `Paused=True`，`PauseOwner` 为一个不存在的 pid。
- 操作：`docker ps`。
- 预期与宿主后置：两个组都在运行，状态已清除。

### T-R4-13 暂停期间拒绝新的 exec（待补）

- 前置：测试进程持有暂停（同 T-R4-03）。
- 操作：`docker exec pausing true`。
- 预期：退出码非 0，报 `is paused`。
- 宿主后置：`execs.json` 没有新增条目；恢复后 exec 正常。

### T-R4-14 `--pause=false` 不暂停（待补）

- 操作：`commit --pause=false`，`commit_paused` 替换为在调用时记录各组的停止状态，再调用原函数。
- 预期：记录显示各组都未停止；提交成功。

### T-R4-15 多线程进程的停止判断（待补）

- 前置：宿主上启动一个带 3 个忙循环线程的进程，放在独立的进程组。
- 操作：先调用 `runtime.stopped(pgid)`；发 SIGSTOP 后再调用；发 SIGCONT 后再调用。
- 预期：依次为 False、True、False。
- 备注：设备上已手动验证过（停止的单线程和多线程进程 wchan 均为 `thread_precheck_deliver_signal`，睡在
  `pause()` 的进程不是），尚未写成用例。

### T-R4-16 Linux 上的停止判断（待补）

- 环境：Android arm64 chroot（Linux 内核，停止的任务显示为 T）。
- 操作：运行 T-R4-01 至 T-R4-07、T-R4-09 至 T-R4-12。
- 预期：全部通过（T-R4-08 不适用）。

隐含覆盖：设备上约 290 个其他用户的进程，其 `/proc` 条目连 stat 都不允许。T-R4-01 在设备上能成功暂停，说明
这些条目被正确跳过，而不是被当作“无法确认”。

## R5 监视进程失效后的主进程组

需求：刷新状态时，如果监视进程和入口进程都已不在，就结束入口进程原来那个进程组的残余进程，但不误杀复用了该
pid 的进程组。来源：R5（59c7dd9）。

### T-R5-01 监视进程被杀后，入口进程留下的后台任务被结束（已有）

- 用例：`a container whose monitor died leaves no job of its process group`，两种模式。
- 前置：`docker run -d` 的命令为 `sleep 300 & sleep 2; exit 0`；等 `run.json` 记下 `Pid` 和 `MonitorPid`。
- 操作：SIGKILL 杀掉监视进程，等入口进程退出（同组的 `sleep 300` 仍在），然后执行 `docker ps -a`。
- 预期：刷新前组内仍有进程；`docker ps` 显示容器为 `exited`。
- 宿主后置：0.3 秒后该进程组已没有进程。

### T-R5-02 pid 被复用时不误杀（待补）

- 前置：容器记录的 `Pid` 改为一个无关的存活进程（在另一个进程组），`PidStart` 与它的实际启动时间不同；
  `MonitorPid` 为一个不存在的 pid。
- 操作：`docker ps -a`。
- 预期：容器显示为 `exited`。
- 宿主后置：该无关进程及其进程组仍然存活。

## 待补用例的优先级

1. **T-R1-05、T-R1-07、T-R1-08**：broker 的边界修复目前没有用例直接约束（chmod 不跟随链接、填充核对
   inode、下层缓存路径）。
2. **T-R4-13、T-R4-15、T-R5-02**：已实现但只靠代码阅读或手动验证的行为。
3. **T-R2-05 至 T-R2-08、T-R1-06、T-R1-09**：边角输入与宿主侧路径。
4. **T-R3-02、T-R3-03、T-R4-14、T-R4-16**：参数校验、进程内后端的语义、Linux 平台。
