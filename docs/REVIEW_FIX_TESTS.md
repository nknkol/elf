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
| R1 层镜像展开不越过受保护子树 | T-R1-01 至 T-R1-09 | — |
| R2 构建上下文不读上下文外的文件 | T-R2-01 至 T-R2-08 | — |
| R3 启动器不把继承的 FD 交给 guest | T-R3-01 至 T-R3-03 | — |
| R4 `commit --pause` 真正暂停、唯一所有者、失败即恢复 | T-R4-01 至 T-R4-16 | — |
| R5 监视进程失效后主进程组不残留 | T-R5-01、T-R5-02 | — |

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

### T-R1-05 新建条目的 chmod 不跟随换进来的链接（已有，修复前未复现）

- 用例：`a link put at a made directory before its chmod never changes what it points to`。
- 对应修复：`lazy_layer.c` 的 `chmod_made`（4d74389）；宿主侧 `_chmod_made` 见 T-R1-09。
- 前置：镜像目录 `d` 含 200 个模式为 0755 的子目录；树外哨兵文件模式为 0600。
- 操作：guest 就绪后连发 400 次展开 `/d`。宿主线程不停尝试删掉临时名 `.wh..elf-lazy-tmp` 处刚建的目录，
  换成指向哨兵的符号链接；每次展开完成后删掉标记和全部子条目，让下一次重新展开。
- 预期：计数合计 400，返回值不作要求（`chmod_made` 失败时调用方忽略，条目保留创建时的模式）。
- 宿主后置：哨兵的模式、大小、mtime、内容不变；哨兵所在目录只有哨兵。
- 修复前：59c7dd9 的 loader 同样通过。设备上每轮约有 300–600 次换成了链接，但 mkdir 与 chmod 之间的窗口
  只有一个系统调用，没能落进去。因此这条用例只约束结果，不能证明修复有效。FIFO 条目（在自己的名字上建，再
  chmod）没有单独做竞争：HarmonyOS 的应用存储拒绝之后再改 FIFO 的模式。

### T-R1-06 改名不覆盖期间出现的同名条目（已有）

- 用例：`a name made meanwhile is never replaced by the expansion (and no temporary name is left)`。
- 对应修复：`place_child`（`RENAME_NOREPLACE`）。
- 前置：先用一对文件探测存储是否支持 `RENAME_NOREPLACE`，不支持则输出 SKIP（那里会退回覆盖）。镜像目录
  `d` 含 200 个文件。
- 操作：guest 就绪后连发 400 次展开 `/d`。宿主线程每轮先清空 `d`，再从最后一个名字往前，用 `O_EXCL` 抢先
  建出自己的文件（内容 `host`），记下 inode；等到标记出现后逐个核对。
- 预期：计数合计 400。
- 宿主后置：宿主建的每个文件 inode 和内容都不变；最后没有残留的临时名。设备上一次运行宿主共建了约 2000 个
  文件。

### T-R1-07 填充写入的必须是检查并加锁的那个文件（已有）

- 用例：`a fill never writes a file renamed over the placeholder after its check`。
- 对应修复：`fill_at` 比对写入 FD 与加锁 FD 的 (dev, ino)。
- 前置：镜像文件 `f` 为 64 KiB；宿主保存一份占位文件（带占位 atime 标记）用于每轮放回。
- 操作：guest 就绪后连发 400 次填充 `/f`。宿主线程循环：放回占位文件；约 0.3 ms 后把内容为 `victim` 的新文件
  改名覆盖到 `f`；再约 0.3 ms 后把它移到缓存外的 `victims6/` 保存。
- 预期：计数合计 400，返回值只有 0、-ENOENT（名字正处在移走与放回之间）、-EAGAIN（核对不符）。
- 宿主后置：`victims6/` 中每个文件（设备上约 100 个）内容都仍为 `victim`。
- 修复前：59c7dd9 的 loader 把镜像内容写进了其中一个 victim。

### T-R1-08 下层缓存路径同样受保护（已有）

- 用例：`{vector}: lower cache: expand protected / expand the cache root / fill protected/a inside a protected
  subtree is refused`、`{vector}: lower cache: protected unchanged`、`lower cache: with nothing protected
  inside it still expands`、`{vector}: lower cache: a protected subtree moved in after the check is refused
  where met`、`{vector}: lower cache: protected unchanged while moved in and out`；向量为 `dr`、`dd`。
- 对应修复：`lazy_request`（下层缓存，`self=1`）与 `BROKER_LAZY_MOUNT` 共用 `lazy_check_object`。
- 前置：`--root UPPER --lower CACHE --lower-image IMAGE`。probe 新增 `lazypath HOST OP [N]`，直接发
  `BROKER_LAZY_PATH`。
- 操作：
  - 静态：缓存的 `protected` 另以挂载登记，对 `CACHE/protected`、`CACHE` 本身展开，对 `CACHE/protected/a`
    填充。
  - 对照：另一个下层缓存，内部没有受保护子树，展开 `protected`。
  - 竞争：同 T-R1-03，`holder` 在缓存外与下层缓存之间来回移动，各连发 400 次。
- 预期：
  - 静态：三个请求都返回 EACCES。
  - 对照：返回 0，`protected/a` 被建出。
  - 竞争：没有 0，出现过 EACCES。
- 宿主后置：`protected` 的快照不变。
- 修复前：59c7dd9 的 loader 在竞争变体下每组有 26–34 次成功（静态与对照用例照常通过）。

### T-R1-09 宿主侧 `erofs.py` 与 `lazy_layer.c` 同输入同结果（已有）

- 用例：`test/isolation/lazy_parity.py`；以及 `test/oci/run.py` 的 `host expansion: ...` 两项（标记与临时名的
  链接竞争）。
- 统一的差异（涉及安全或数据语义，现在两侧一致）：
  - 改名：`erofs.py` 原先用 `os.rename` 覆盖，现在用 `RENAME_NOREPLACE`。期间出现的同名条目保留，临时名删掉；
    不支持时退回覆盖，与 C 相同。
  - 填充的对象身份：写入前核对写入 FD 与加锁 FD 的 (dev, ino)，不符报 EAGAIN。
  - 短写：继续写完。
  - 失败清理：新建文件失败时删掉临时名；填充失败时仍恢复占位文件的模式。
  - 新建目录的 chmod 失败：与 C 一样忽略，条目保留创建时的模式。原先会中止整个展开。
  - 非法镜像条目：名字含 `/` 或 NUL、符号链接目标为空、过长或含 NUL，都报错（EIO 或 `ImageError`）。原先
    `erofs.py` 跳过名字，链接则抛出别的异常。
  - 未改：错误的报告方式（C 返回错误码，`erofs.fill` 遇到链接静默返回）和内部结构。数据结果相同。
- 同输入对照：同一镜像、同样预设的缓存。C 侧经 broker 的 `BROKER_LAZY_PATH`，Python 侧经 `erofs.expand/fill`。
  逐条比较类型、模式、大小、内容、链接目标，以及 mtime 是否为镜像时间。
  1. 全量展开与填充：目录模式 0755、0750，setuid，空文件，多块文件，符号链接，FIFO。
  2. 完成标记是符号链接：视为已完成，不经它建出任何东西。
  3. 展开前已存在的名字：保留。
  4. 占位文件被换成普通文件：不填充。
  5. 占位文件被换成符号链接：不经它写入。
  6. 镜像中符号链接目标为空：两侧都报 EIO，不放置该条目。
- 仅 `erofs.py`，确定性注入（C 侧的同类情形由 `lazy_nested.py` 以竞争方式覆盖）：
  - 临时名与改名之间出现同名条目：不覆盖，不留临时名。
  - 检查之后把别的文件改名到占位文件上：不写入，报 EAGAIN。
  - 每次只写 100 字节：仍写完整个内容。
  - 新建文件时出错：不留临时名。
  - 填充出错：占位文件的模式（0444）恢复，仍是占位文件。
- 修复前：改动前的 `erofs.py` 在空链接目标一项上失败；之后的注入用例依赖新增的 `_place`，在旧版本上直接中断。

## R2 构建上下文

需求：构建只读取上下文内的文件。链接不能把读取引到上下文外；`.dockerignore` 排除的文件从不打开；OCI 存储
即使在上下文内也不会被复制。来源：R2（59c7dd9）、上下文快照修复（4d74389）。

### T-R2-01 上下文里的链接读不到上下文外（已有）

- 用例：`build: context links never read outside the context (COPY, ADD, directory, RUN --mount bind; absolute
  and relative links); outside unchanged`。
- 前置：`outside-ctx/sentinel` 与 `outside-ctx/dir/f` 含随机哨兵；上下文中 `abs` 是指向 `outside-ctx` 的绝对
  链接，`rel` 是 `../outside-ctx`。
- 操作：对 `abs` 和 `rel` 各构建 6 个镜像：`COPY link/sentinel`、`ADD link/sentinel`、`COPY link/dir`、
  `COPY link/dir/`、`RUN --mount=type=bind,source=link/sentinel`、`RUN --mount=type=bind,source=link`（读
  `/m/sentinel`）；构建成功的镜像再运行一次，显示复制或读到的内容。
- 预期：12 个构建的输出和镜像内容都不含哨兵（构建失败也可以接受）。
- 宿主后置：`outside-ctx` 前后快照（名字、模式、大小、mtime、内容）一致。

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
- 宿主后置：`build: the context is left as it was (names, modes, sizes, times, contents)`：构建前后上下文的快照
  一致（读不了的文件只比元数据）；之后恢复 `deps/big` 的模式（清理）。

### T-R2-04 存储位于上下文内时不被复制（已有）

- 用例：`build: a store inside the context is not copied into it`。
- 前置：上下文 `store-ctx` 下的 `store/` 作为 OCI 存储（`ELF_OCI_HOME`）。
- 操作：`FROM scratch` 加 `COPY . /ctx/`，然后保存镜像并列出所有层。
- 预期：构建成功；层中有 `ctx/f`，没有任何 `ctx/store` 开头的条目（不递归复制自身）。

### T-R2-05 `.dockerignore` 是链接或不是普通文件（已有）

- 用例：`build: a .dockerignore that is a link / directory / fifo stops the build`。
- 前置：`.dockerignore` 分别为指向上下文外可读文件的符号链接、目录、FIFO（存储不允许建 FIFO 时输出 SKIP）。
- 操作：构建（超时 120 秒）。
- 预期：构建失败，报 `cannot read .dockerignore`，不会因 FIFO 卡住。链接目标可读，所以如果跟随了链接，构建
  会成功；构建失败本身就证明没有跟随。
- 发现并修复：`.dockerignore` 是目录时，`os.fdopen` 在类型检查之前就抛出 EISDIR，构建以未处理的错误退出
  （`Error response from daemon: [Errno 21] Is a directory`），而不是报 `cannot read .dockerignore`。
  `read_ignore` 改为先 `fstat` 再 `fdopen`。

### T-R2-06 缓存键遵守例外规则（已有）

- 用例：`build: the cache key changes with a file an exception brings back, not with one left out`。
- 对应修复：`hash_tree` 与 `copy_into` 共用 `skipped`。
- 前置：`.dockerignore` 为 `deps`、`!deps/keep`；Dockerfile 为 `COPY . /ctx/`，再 `RUN cat /ctx/deps/keep >
  /seen`。
- 操作：`build -q` 一次；修改被排除的 `deps/big/x` 后再构建；修改 `deps/keep` 后再构建。
- 预期：第二次的镜像 ID 与第一次相同（缓存命中）；第三次不同，且运行它得到新的 `deps/keep` 内容。

### T-R2-07 含 `**` 的例外规则（已有）

- 用例：`build: a ** exception brings back files at every depth, nothing else`。
- 前置：`.dockerignore` 为 `*`、`!**/*.go`；上下文根、`d1/`、`d1/d2/` 各有 `m.go` 和 `m.txt`，其中
  `d1/d2/m.txt` 模式为 0。Dockerfile 放在上下文外（`-f`）。
- 操作：`COPY . /ctx/`，列出 `/ctx`。
- 预期：构建成功；`/ctx` 恰为 `d1`、`d1/d2` 和三个 `m.go`（`.dockerignore` 也被 `*` 排除，与 Docker 相同）。

### T-R2-08 快照之后上下文被改动（已有）

- 用例：`build: a change of the context after it was copied reaches nothing`。
- 前置：Dockerfile 为 `RUN sleep 3`，再 `COPY data /data`；上下文外有随机哨兵文件。
- 操作：`build --no-cache`。输出出现 `RUN sleep` 这一步时，宿主把 `data` 换成指向哨兵的链接。
- 预期：构建成功；`/data` 为快照时的内容 `as copied`。
- 宿主后置：构建输出和镜像内容中都没有哨兵。

## R3 agent 启动器的继承 FD

需求：启动器把 stdio 以外的继承 FD 全部设为 close-on-exec，只有用 `--pass-fd` 显式交出的 FD 到达 guest；交出的
可写 FD 保持可写；参数在启动前校验。
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

### T-R3-02 `--pass-fd` 的参数处理（已有）

- 用例：`agent_launch.py` 的 `--pass-fd refuses negative, unopened and runtime-reserved FDs before starting;
  repeats count once`。
- 行为（已定）：`--pass-fd` 是显式授权，启动前校验全部指定的 FD。负数、未打开的 FD、与运行时保留 FD 冲突的
  编号（898 及以上：loader FD、控制套接字、broker 通道、挂载表、属主数据库）都明确拒绝；重复指定去重；0–2
  可以指定。loader 自己的 `--pass-fd` 也做同样的检查。
- 操作：
  - 启动器分别给 `-1`、刚关闭的 FD、`898`、`901`，命令为 `echo started`。
  - `--pass-fd 1 --pass-fd 1 --pass-fd 2 --print`。
  - 直接运行 loader，`--pass-fd` 分别给未打开的 FD 和 `899`。
- 预期：
  - 前四种退出码 2，报 `not an FD number`、`not an open FD` 或 `runtime's own`，guest 没有启动（输出中没有
    `started`）。
  - `--print` 打出的 loader 参数里 `--pass-fd` 恰好两个。
  - loader 以非 0 退出，报同样的原因。

### T-R3-03 交出的 FD 保留原有能力，经 payload 与直接调用一致（已有）

- 用例：
  - `test/isolation/pass_fd.py`：`a passed {append,read-only,directory} FD: write, read and listing as its
    access mode allows, the same through the payload and directly`、`... chmod refused`、`an inherited FD not
    passed is not writable through the payload`、`host: the append file holds exactly the two writes ...`。
    `--isolate` 与进程内两种后端各一遍。
  - `agent_launch.py`：`writable FDs given with --pass-fd stay writable under both backends; a read-only one
    does not`。
- 行为（已定）：
  - `--pass-fd` 表示保留该 FD 原有能力：只读仍只读，可写仍可写，不隐式升级。
  - 它是路径策略之外的授权：读、写、列表、锁、共享映射按 FD 的访问方式由内核决定，经 payload 与直接系统调用
    结果相同。
  - 改元数据（fchmod、fchown、xattr、utimensat）不属于 FD 能力，两种路径都拒绝。
  - 降权需要独立选项，或由调用方预先处理。
  - 实现：loader 在启动时记下对象（dev、ino）和访问标志，子 loader 经 `--passed-fds` 继承；每个进程启动时，
    对象与标志都相符的 FD 获得本地能力位 `passed`。它和 pipe 授权一样不进交接快照，之后在同一编号打开的别的
    对象不算。
- 前置（`pass_fd.py`）：上下文外的三个对象，各以 `--pass-fd` 交出：以 `O_APPEND` 写方式打开的文件、只读打开
  的文件、目录。另有一个只继承、未交出的可写 FD。
- 操作：probe 对每个 FD 依次做一字节写、`pread`、`getdents64`（先 `lseek` 回开头，因为各次运行共用同一个
  打开文件描述）、把模式设回原值的 `fchmod`，经 payload（`h`）与直接调用（`d`）各一次。
- 预期：
  - 追加 FD：写 1、读 EBADF。只读 FD：写 EBADF、读出内容。目录：写 EBADF、读 EISDIR、列表非空。每项 `h` 与
    `d` 相同。
  - chmod 经 payload 被拒；`--isolate` 下直接调用也被拒（EPERM）。
  - 未交出的 FD 经 payload 写入得 EACCES。
- 宿主后置：追加文件恰为两次写入的 `xx`；只读文件内容不变；三个对象的模式不变。
- 修正过程：一开始只放行了写，目录列表经 payload 被过滤、直接调用却能列出；共享映射与锁也有同样的差异。现在
  这些操作对交出的 FD 一律按内核结果。

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

### T-R4-13 暂停期间拒绝新的 exec（已有）

- 用例：`commit --pause: an exec while paused is refused and registers nothing`，两种模式。
- 前置：测试进程调用 `runtime.pause` 持有暂停。
- 操作：`docker exec pausing true`；恢复后再执行一次。
- 预期：第一次退出码非 0，报 `is paused`；恢复后的那次退出码 0。
- 宿主后置：暂停期间 `execs.json` 的内容没有变化。

### T-R4-14 `--pause=false` 不暂停（已有）

- 用例：`commit --pause=false: nothing stops while the container is read`，两种模式。
- 操作：`build.cmd_commit(['--pause=false', ...])`，其中 `commit_paused` 被替换为：先记录各进程组是否停止，
  再调用原函数。
- 预期：提交成功；记录恰有一次，且各组都未停止；`Paused` 为 False。

### T-R4-15 多线程进程的停止判断（已有）

- 用例：`a stop of a process with busy threads is seen only once every thread stopped`（宿主进程，不需要
  容器）。
- 前置：宿主上启动一个有 4 个忙循环线程（主线程加 3 个）的 Python 进程，放在独立的会话和进程组。
- 操作：先调用 `runtime.stopped(pgid)`；发 SIGSTOP 后在 5 秒内反复调用，直到为 True；发 SIGCONT 后
  0.2 秒再调用。
- 预期：依次为 False、True、False；线程数不少于 4。

### T-R4-16 Linux 上的停止判断（已有，环境）

- 环境：Android 14 arm64（内核 5.10）上的 Alpine chroot，以 root 运行 `make check-oci`。停止的任务显示为 T。
  `build/alpine-test-root` 从 HarmonyOS 设备复制过去。
- 结果：
  - T-R4-01 至 T-R4-07、T-R4-09 至 T-R4-15、T-R5-01、T-R5-02 两种模式都通过。
  - T-R4-08 输出 SKIP：注入从未触发（不读 wchan），暂停照常成功。
- 在这里暴露并修复的问题：
  - 测试本身：注入循环共用一个 `commit_paused` 调用记录且不清空，一旦某项正常提交，后面各项全部误报失败。
    改为每项清空，wchan 注入没有触发时记为不适用。
  - 测试本身：T-R4-01 用 `exec cat /a` 判断容器在继续运行，但循环 `echo $i > /a` 先截断再写入，读到空的
    概率不低。改为最多重读 10 次，直到读到非空。
  - 运行时：`commit --pause=false` 时文件在读取期间变短，`layers.write_layer` 按先前 stat 的大小写 tar，
    抛出 `unexpected end of data`。改为先把文件复制到临时文件，按实际读到的长度写入。
- 同一环境中与本轮无关的失败：`--owners` 两项和 `build: chown in RUN and COPY --chown` 在 root 下结果不同
  （EPERM 的前提不成立）。

## R5 监视进程失效后的主进程组

需求：刷新状态时，如果监视进程和入口进程都已不在，就结束入口进程原来那个进程组的残余进程，但不误杀复用了该
pid 的进程组。来源：R5（59c7dd9）。

### T-R5-01 监视进程被杀后，入口进程留下的后台任务被结束（已有）

- 用例：`a container whose monitor died leaves no job of its process group`，两种模式。
- 前置：`docker run -d` 的命令为 `sleep 300 & sleep 2; exit 0`；等 `run.json` 记下 `Pid` 和 `MonitorPid`。
- 操作：SIGKILL 杀掉监视进程，等入口进程退出（同组的 `sleep 300` 仍在），然后执行 `docker ps -a`。
- 预期：刷新前组内仍有进程；`docker ps` 显示容器为 `exited`。
- 宿主后置：0.3 秒后该进程组已没有进程。

### T-R5-02 pid 被复用时不误杀（已有）

- 用例：`a recorded pid now heading another process group: exited, that group is left alone`，两种模式。
- 前置：`docker run -d ... sleep 300`，等 `run.json` 记下 `Pid` 和 `MonitorPid`；SIGKILL 杀掉监视进程和
  主进程组，等两者都消失。宿主另起一个无关的进程组：新会话中的 `sh -c 'sleep 300 & exec sleep 301'`，组内
  两个进程。在存储锁下把记录改为：`Pid` 为该组组长，`PidStart` 为它的实际启动时间加 1，`MonitorPid` 为
  一个不存在的 pid。
- 操作：`docker ps -a`。
- 预期：容器显示为 `exited`。
- 宿主后置：0.3 秒后该无关进程组的成员与操作前完全相同（两个进程都在）。

## 剩余事项

- **T-R1-05**：用例只约束结果，修复前的 loader 也能通过（窗口只有一个系统调用）。
- **只继承、未用 `--pass-fd` 列出的 FD**：直接使用 loader 时，经 payload 写入被拒，`--isolate` 下直接调用却
  可以写（过滤器不区分 FD）。这是 [ISOLATION](ISOLATION.md) 记录的残余，启动器默认关闭这些 FD。
