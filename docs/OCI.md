# Docker/OCI 镜像支持

**状态（2026-11-01）**：R1 运行、R2 管理、R3 构建、R4 容器内 mount、R5 属主、R6 写时复制、R7 compose 与 Engine API
已实现（`tools/oci/docker`），在 HarmonyOS 真机上通过验收（见文末各“实现记录”）；R6 中的层镜像（erofs/squashfs）与
`mount -o loop` 没有做（理由见 R6 实现记录）。下文各节保留设计原文，实现与设计不同之处集中写在“实现与设计的差异”。

## 目标

在 HarmonyOS 应用沙箱内，不依赖 Docker 守护进程与虚拟机，直接运行、管理、构建 arm64 的 Docker/OCI 镜像，
命令与 Docker 兼容：

```
docker pull python:3.13-slim
docker run --rm -v ~/work:/work -w /work --env-file .env python:3.13-slim python -m pip install requests
docker run --isolate debian:bookworm-slim bash
docker build -t myapp .
```

镜像本质上是“一个 rootfs + 一份启动配置”。运行时仍然是现有的 loader（PRoot 语义，可选 `--isolate`），
不引入新的执行机制。`docker` 是一个 Python 命令（`tools/oci/`），把子命令和参数翻译成镜像存储操作与
elfloader 命令行。

**不是目标**：
- 虚拟机方案：本机没有 `/dev/kvm`，纯软件模拟（QEMU TCG）实际用过，太慢。
- 真正的命名空间与 cgroup：pid、网络、IPC 隔离，资源限制，端口映射。
- 特权容器：`--privileged`、iptables、内核模块、真实的块设备与网络文件系统挂载。
- x86 镜像。

## 约束（本机实测，见 STORAGE_CAPABILITIES.md、STATUS.md）

| 约束 | 影响 |
|---|---|
| 没有 mount、命名空间、cgroup（宿主沙箱拦截 unshare，应用无权 mount） | 没有 overlayfs；mount 只能模拟；网络与宿主共用 |
| 应用不能建硬链接（各位置 EPERM/EACCES） | 层内硬链接展开为副本，运行时加 `--link-copy` |
| 应用不能 chown，文件属主都是应用 uid | 镜像记录的属主在展开时丢失；fake_id0 把宿主属主报告为 root |
| `/storage/Users` 大小写不敏感 | 镜像只能展开在大小写敏感的位置（`/data/storage/el2/base/files/...`） |
| 只有 AArch64，原生 exec 未签名 ELF 会失败 | 只接受 `linux/arm64` 镜像；所有程序都经 loader 运行（现状如此） |
| 终端环境可以 JIT（匿名页 RWX 或 RW→RX，不需要 `PR_HM_JIT`） | node、JVM、Python JIT 等可用；memfd 双映射被拒，loader 与原生一致（2026-11-01 修复） |
| 设备上 Python 3.14.7，带 `compression.zstd`；没有 skopeo/crane | 工具用纯 Python 写，gzip 与 zstd 层都能解 |

## 发行顺序

每个版本单独可用：命令完整、文档写明能做与不能做的事、在 HarmonyOS 真机上通过该版本的验收，并且四套回归
（常规与 `--isolate`）不退化。

**原则**：先做对运行性能零影响的部分，把“运行 → 管理 → 构建”这条主线打通。会让 guest 的系统调用变慢的
功能（模拟 mount、属主元数据、写时复制）放在后面，并且只在用到时才生效：不用的容器速度与前一版完全相同。

| 版本 | 内容 | 用户得到什么 | 运行性能 |
|---|---|---|---|
| R1 运行 | `pull`、`load`、`images`、`rmi`、前台 `run`/`create`/`start`、`ps -a`、`rm`、`inspect`；`--env-file`；loader 加 `--cwd`、`--user`、`--hostname` | 像 Docker 一样拉镜像、跑交互或一次性命令 | 无影响 |
| R2 管理 | `exec`、`cp`、`stop`/`kill`/`restart`/`wait`、`logs`、`run -d`（轻量守护进程）、`volume`、`tag`/`save`/`history`、`prune`、`--read-only`/`--in-place`、`--format` 常用字段、运行中追加卷 | 长时间运行的服务、多终端进入同一容器、数据卷 | 无影响 |
| R3 构建 | `build`（单阶段、多阶段、缓存、`.dockerignore`、`--build-arg`、`RUN --mount`、heredoc）、`commit`、`diff`、`push`/`login` | 用 Dockerfile 构建、迭代、发布自己的镜像 | 无影响（只在构建时扫描目录树） |
| R4 容器内 mount | 模拟 `mount --bind`、`tmpfs`、`proc`/`sysfs`/`devpts`、`umount`，伪造 `/proc/self/mounts`、`mountinfo` | 入口脚本里的 mount 不再失败 | 用到 mount 的容器：路径调用多查几条翻译表，很小；不用的不变 |
| R5 属主 | 属主元数据库：stat 报告镜像里记录的 uid/gid/模式，chown/chmod 记录下来，`build`/`commit` 打包时写回层 | postgres、sshd 等属主敏感的程序可用；构建的镜像导出到别处属主正确 | 开启的容器：每次 stat 多查一次内存表（`--isolate` 下在 broker 内，不多往返） |
| R6 层镜像与写时复制 | 层转成 erofs/squashfs 镜像、按需展开、只读层 + 可写上层的合并视图；顺带支持 `mount -t overlay`、只读镜像的 `mount -o loop` | 多个容器共享一份镜像，启动不复制，省空间 | 开启的容器：查找可能翻倍，首次打开要展开，首次写要复制上层 |
| R7 compose 与 Engine API（按需） | compose 文件解析（含 `.env` 变量替换）；docker.sock 上的 Engine API 子集 | docker compose、devcontainer、testcontainers、Docker SDK | 无影响 |

**为什么是这个顺序**：
- R1–R3 覆盖绝大多数用法（跑镜像、长期服务、构建），全部在 guest 运行路径之外实现，风险最低，可以尽早发布。
- R2 先于 R3：构建要用到 `commit`/`diff` 的层计算，也要用到 R2 的容器状态管理。
- R4 先于 R5、R6：它最小，只扩展现有翻译表；R6 的合并视图也会复用这张共享表的机制。
- R5 先于 R6：R6 的层镜像本身带属主，但合并视图之上的写入、`build` 的打包，仍需要 R5 的属主记录。
  R5 独立也有用（复制式容器）。
- R6 改动最大，单独设计；之前各版本的复制式容器一直可用，R6 只是可选的省空间方式。
- R7 只在确定要用某个具体工具时做，按它实际调用的接口实现。

## 使用

```
make build                                   # build/elfloader[-guarded] 与 build/elf-exec-helper
ln -s "$PWD/tools/oci/docker" ~/.local/bin/docker   # 或任意 PATH 中的名字
docker pull alpine
docker run --rm -it alpine sh
docker run -d --name web --restart unless-stopped -v web-data:/data myapp
docker logs -f web; docker exec -it web sh; docker stop web
docker build -t myapp --build-arg VERSION=2 --secret id=npm,src=$HOME/.npmrc .
docker save -o myapp.tar myapp; docker load -i myapp.tar
docker compose up -d; docker compose logs -f; docker compose down -v
docker engine &                              # Engine API: DOCKER_HOST=unix://$ELF_OCI_HOME/docker.sock
```

环境变量：`ELF_OCI_HOME`（存储根）、`ELF_OCI_MIRROR`（Docker Hub 镜像站，如 `https://mirror.example`）、
`ELF_LOADER` / `ELF_LOADER_GUARDED` / `ELF_EXEC_HELPER`（不用仓库 build/ 下的二进制时）、
`ELF_OCI_MAX_BYTES` / `ELF_OCI_MAX_ENTRIES`（展开上限）、`ELF_OCI_HARDLINKS=copy`（见“差异”）。
ELF 自己的参数：`run --isolate`、`--isolate-device`、`--in-place`，`build --isolate`。

网络慢时可在别处 `docker pull` 再 `docker save`，拷到设备 `docker load`（本机到 Docker Hub 实测约 40 KB/s）。

## 结构

```
tools/oci/
  docker        命令入口（Python）：按 Docker 的子命令与参数解析，输出格式与退出码照 Docker
  registry.py   registry v2 客户端（bearer/basic 认证、manifest、blob 下载续传与校验、上传）
  store.py      本地存储：blob、镜像、引用、容器、卷的目录与元数据，flock 加锁
  unpack.py     按层展开（whiteout、安全检查、硬链接）
  images.py     pull、load（docker-archive 与 OCI layout）、save、镜像入库
  runspec.py    镜像配置 + 运行参数 → elfloader argv；用户解析、容器内路径解析
  runtime.py    容器生命周期：create/start/stop/kill/wait/rm、监视进程、exec、cp、logs
  layers.py     快照、差异、层 tar（build/commit/diff 共用）
  build.py      R3：Dockerfile 解析与执行、缓存、commit、diff、push
  union.py      R6：--cow 容器的合并视图（diff、commit、cp、用户解析）
  compose.py    R7：docker compose
  yamlite.py    R7：compose 文件用到的 YAML 子集（设备上的 Python 没有 PyYAML）
  engine.py     R7：Engine API（UNIX 套接字上的 HTTP 服务）
  fmt.py        表格、时间、--format 模板子集
```

存储根 `ELF_OCI_HOME`，默认 `/data/storage/el2/base/files/elf-oci`（启动时用 probe_storage 的方法
确认大小写敏感，否则拒绝）：

```
blobs/sha256/<hex>                 压缩层、config、manifest（按内容寻址，可共享）
images/<id>/manifest.json          所选平台的 manifest
images/<id>/config.json            镜像配置
images/<id>/rootfs/                展开后的完整 rootfs（只读使用）
images/<id>/meta.json              每个路径的原始属主、模式、硬链接与跳过的条目
refs.json                          名字:标签 → 镜像 id（id = config digest）
containers/<cid>/rootfs/           容器自己的 rootfs（见“容器实例”）
containers/<cid>/volumes/<n>/      匿名卷
containers/<cid>/etc/              生成的 hosts、hostname
containers/<cid>/run.json          loader 命令行、状态、退出码、进程组
containers/<cid>/log               R2：后台容器的输出
volumes/<name>/                    R2：命名卷
build-cache/                       R3：构建缓存索引
```

## 实现与设计的差异

- **没有守护进程**：前台 `run`/`start -a` 由 docker 进程自己等待容器；`run -d`/`start` 为每个容器启动一个监视
  进程（`docker __monitor <id>`，脱离会话），负责日志、退出码与重启策略。状态都在 `run.json`，进程号带
  `/proc/<pid>/stat` 的启动时间，防止 pid 复用；等待者被杀时 `ps` 把容器记为已退出（255）。待定问题 2 因此不再需要。
- **硬链接**：指向可执行文件的硬链接展开为指向目标（guest 绝对路径）的符号链接，其余仍复制。busybox 镜像
  有约 400 个指向同一程序的硬链接，全部复制时 490 MB，现在 4.2 MB；exec 与 argv[0] 行为不变，内容仍共享；
  不同之处是 lstat 看到符号链接、删除目标后其他名字失效。`ELF_OCI_HARDLINKS=copy` 恢复全部复制。meta.json 记录原关系。
- **展开时的模式**：目录总是加上属主 rwx、文件加上属主 rw（fake root 在内核眼里是普通属主，没有这两位就写不了），
  原模式记入 meta.json；setuid/setgid 被宿主拒绝时去掉并记录。
- **首个程序**：loader 按 root 相对路径打开首个程序，不经 bind，所以 exec helper 复制在 rootfs 的 `/.elf-exec`
  （容器内 `ls -a /` 可见；build、commit、diff、save 都排除它）。helper 负责按 guest 的 PATH 查找命令（127/126 与 Docker 一致）。
- **`:ro` 卷与 `--read-only`**：使用 guarded 构建的 `--guard-path-mutations`（写方式 open、创建、删除、改名、元数据
  修改按路径拒绝，EROFS），不用 `--guard-file-mutations`：后者要求 exec 之后继承的 FD 也有已知来源，shell
  重定向后 exec 的程序就写不了标准输出。已打开的 FD 写入不受限制。加 `--isolate` 时由 broker 执行同一向量。
- **信号**：stop/kill 与前台的信号转发只发给容器主进程（与 Docker 相同）；主进程退出后，同一进程组里剩下的进程被
  SIGKILL（相当于 PID 命名空间的 init 退出）。主进程放在自己的进程组，`-it` 时设为终端前台进程组。
- **`--init`、`-p` 映射不同端口、`-P`、`--network` 非 host、cgroup 类参数**：报错退出 125（见 docker 的 UNSUPPORTED 表）。
- **R2 的运行中追加卷**：未实现。R4 的共享翻译表已有，但追加只能由容器外发起（见“外部 → 容器”），还没有入口。
- **build**：输出为传统构建器格式（`Step n/m`、`Using cache`）；完全命中缓存时镜像 id 不变（config 的时间取自缓存的层）；
  `COPY --chown` 被忽略（R5 之前文件都属于 root），`COPY --parents`、`--mount=type=ssh`、远程上下文与 git 源报错；
  `RUN --mount=type=bind` 绑的是源的副本，写入被丢弃（与 BuildKit 默认只读的效果一致）；`--output` 支持 local/tar/docker。

## R1 运行

### 取得镜像

**registry 拉取（`pull`）**：
1. 解析引用：`[registry/]name[:tag|@digest]`，默认 `registry-1.docker.io`、`library/`、`latest`；
   支持 `--registry-mirror`。
2. `GET /v2/<name>/manifests/<ref>`，Accept 同时列 Docker v2 与 OCI 的 manifest / index 类型。401 时按
   `WWW-Authenticate` 的 realm/service/scope 取匿名 bearer token；有 `~/.docker/config.json` 的
   凭据则带上（R1 只读该文件；R3 的 `login` 才写）。
3. index / manifest list：选 `os=linux, architecture=arm64`（variant 为空或 `v8`）；没有则报错并列出可用平台。
4. 下载 config 与各层 blob 到 `blobs/`，边下边算 sha256，与 digest 不符即删除并失败；支持断点续传（Range）。
5. 解压后的每层 tar 再算一次 sha256，与 config 的 `rootfs.diff_ids` 逐个核对。

只用 HTTPS；不支持 schema 1 manifest。

**离线导入（`load`）**：`docker save` 或 `skopeo copy ... oci-archive:` 得到的 tar，或 OCI layout 目录。
按其 `manifest.json` / `index.json` 找到 config 与层，之后与拉取相同（校验、入库）。

### 展开（`unpack.py`）

每个镜像展开一次，结果只读复用。按层顺序处理，每层流式读 tar（gzip / zstd / 未压缩），不先落盘。

**安全**（沿用 `test/alpine/run.py` 的 `extract_root` 规则，并改为逐级 `dir_fd` 操作）：
- 成员名不得为绝对路径、不得含 `..`；
- 写任何条目都从 rootfs 根 FD 逐级 `O_NOFOLLOW` 打开父目录，绝不经过符号链接（包括之前层留下的）；
- 符号链接原样创建（目标是 guest 路径，不解析）；
- 总大小与条目数上限（可配置，默认 8 GiB / 100 万）。

**每种条目**：

| 条目 | 处理 |
|---|---|
| 目录、普通文件、符号链接 | 创建；模式取低 12 位（setuid/setgid 若被宿主拒绝则去掉并记入 meta） |
| `.wh.<名字>` | 删除下层的 `<名字>`（递归），本身不创建 |
| `.wh..wh..opq` | 清空所在目录中下层带来的内容 |
| 硬链接 | 目标可执行：符号链接到目标；否则复制目标文件内容（宿主不允许硬链接）；meta 记录链接关系 |
| 字符/块设备、FIFO | 跳过并记入 meta（运行时从宿主绑定 `/dev`） |
| 属主 uid/gid | 不能 chown；记入 meta（R5 使用） |
| xattr（含 `security.capability`） | 忽略，记入 meta |

同一路径在后层被替换时（文件换目录、目录换文件）先删除旧的。全部层成功后才把临时目录改名为 `rootfs/`，
中途失败不留半成品。

### 容器实例

R1 只有复制方式：`containers/<cid>/rootfs` 是镜像 rootfs 的完整副本，容器随意修改，`rm` 时删除。代价是
启动时间与空间（debian-slim 约 80 MB、python-slim 约 150 MB），运行时就是普通目录。R2 加只读与原地方式，
R6 加共享镜像的写时复制（`run --cow`：镜像 rootfs 作下层，`containers/<cid>/upper` 作上层，不复制）。

### 配置映射（`runspec.py`）

| 镜像配置 / `run` 参数 | elfloader |
|---|---|
| Entrypoint + Cmd；`--entrypoint`、命令行参数 | 程序与参数（Docker 规则：参数替换 Cmd，`--entrypoint` 替换 Entrypoint） |
| Env；`-e K=V`、`--env-file` | `-e`（container 模式从空环境开始，正合 Docker 语义）；无 PATH 时补默认值 |
| WorkingDir；`-w` | **新增 `--cwd`** |
| User；`-u` | **新增 `--user`** |
| Volumes；`-v HOST:GUEST[:ro]` | `-v`；镜像声明的卷建匿名目录；`:ro` 需要 guarded 构建或 `--isolate`，否则报错而不是悄悄可写 |
| `--hostname`，默认取容器 id 前 12 位 | **新增 `--hostname`** 与生成的 `/etc/hostname`、`/etc/hosts` |
| ExposedPorts；`-p` | 无对应：网络与宿主共用，程序监听的端口就是宿主端口；`-p` 同端口时放行，不同端口时报错 |
| StopSignal | 把收到的 SIGINT/SIGTERM 转成该信号发给 guest |
| `-it`、`-t` | 终端直接继承，不分配新 pty |
| `--rm`、`--name` | 容器目录的生命周期与命名 |
| `--isolate`、`--isolate-device` | 原样传给 loader |
| `--privileged`、`--cap-add`、`--security-opt`、`--memory`、`--cpus`、`--network`（非 host） | 明确报错，不悄悄忽略 |
| Healthcheck、OnBuild、Shell、Labels | `run` 时忽略（Labels 在 `images`/`inspect` 中显示；OnBuild、Shell 在 R3 使用） |

**`--env-file` 与 `.env`**：按 Docker 规则逐行解析：`#` 开头与空行跳过；只有 `KEY` 时取宿主环境中的同名值；
值不做 shell 处理，引号原样保留。loader 的 `-e` 上限由 16 放大到 512，bind 上限由 16 放大到 64（payload ABI 22）。compose 的 `.env`
（compose 文件中的 `${VAR}` 替换）属于 R7。

**固定附加**：`--mode container --root <rootfs> --link-copy`；`-v /proc:/proc`；
`/dev/null`、`/dev/zero`、`/dev/full`、`/dev/random`、`/dev/urandom`、`/dev/tty`、`/dev/ptmx` 逐个绑定
（不绑整个 `/dev`）；`/dev/shm` 绑容器自己的目录；`/etc/resolv.conf` 用宿主的（本机存在），
`/etc/hosts`、`/etc/hostname` 用容器生成的，均以文件 bind 覆盖，不改 rootfs。

**隔离时的权限向量**（guarded 构建 + `--isolate`）：root 为 `w`（复制/原地）或 `r`（只读），镜像卷与
`-v` 为 `w`，`:ro` 为 `r`，`/proc`、只读设备为 `r`。plain 构建 + `--isolate` 时全部为 `w`，仍然有树外不可达的边界。

### loader 的新参数

- **`--cwd DIR`**（guest 路径）：初始 loader 现在总是 chdir 到 root。改为 chdir 到 DIR 按 root/bind 翻译出的
  宿主路径（loader 已有 `resolve_interp_path` 做这种词法映射）；不存在时报错退出，与 Docker 一致。
  隔离模式下发生在装过滤器之前，不经 broker。
- **`--user UID[:GID]`**：设置 fake_ids（实/有效/保存/fs 全部）与补充组。子 loader 协议里已有内部的
  `--fake-ids`、`--fake-groups`，这里只是提供用户入口；名字到数字的解析由 `docker` 读镜像的
  `/etc/passwd`、`/etc/group` 完成，loader 只收数字。
- **`--hostname NAME`**：payload 的 uname 改写 nodename（与 `--kernel-release` 同一处）；sethostname
  在没有 UTS 命名空间时无法真正生效，返回 EPERM（与非特权进程一致）。

### 命令行兼容的约定（R1 起）

- 子命令与参数名照 Docker；不支持的参数报错并说明原因，不悄悄忽略。
- 退出码：125 docker 自身出错，126 命令不能执行，127 命令找不到，其余为容器程序的退出码。
- `ps`、`images` 的表格列与 Docker 相同；`inspect` 输出 Docker 结构的 JSON，能填的字段如实填。
- 安装：`tools/oci/docker` 链接进 PATH；与真正的 Docker 同时存在时可用 `ELF_DOCKER` 之类的名字。

### R1 验收

设备：HarmonyOS 真机。脚本 `test/oci/`，`make check-oci`。
- **展开正确性**：合成镜像（脚本生成层 tar）覆盖 whiteout、不透明目录、文件与目录互换、硬链接副本、
  设备节点跳过、模式与 setuid、符号链接链；与期望树逐项比较。
- **展开安全**：绝对路径、`..`、经符号链接写入（同层与跨层）、超大条目，全部拒绝且不在 rootfs 外留下任何文件
  （哨兵目录前后哈希一致）。
- **校验**：篡改 blob 或 diff_id 不符时 pull/load 失败。
- **配置映射**：Entrypoint/Cmd/`--entrypoint` 组合、Env 与 `--env-file`、WorkingDir、User（名字与数字）、卷、
  hostname，逐项对比 guest 内看到的结果；不支持的参数报错且退出码 125。
- **loader 参数**：`--cwd`、`--user`、`--hostname` 的回归测试（`test/proot/`），常规与 `--isolate` 下通过。
- **真实镜像**（常规与 `--isolate` 各一遍）：`alpine` 跑 apk add；`debian:bookworm-slim` 跑 apt-get install；
  `python:3.13-slim` 建 venv 并 pip install；`node:lts-alpine` 跑 npm install；`busybox` 静态程序。
  记录耗时，与同一 rootfs 直接用 elfloader 运行相比不应变慢。

## R2 管理

- **`exec`**：再启动一个 loader 进程，使用同一 rootfs、环境、工作目录与卷。没有命名空间，它只是“同一文件视图里的
  另一个进程”，看得到宿主的其他进程。
- **`stop`/`kill`/`restart`/`wait`**：容器入口进程放在自己的进程组，`run.json` 记录进程组；按 StopSignal 发信号，
  超时后 SIGKILL。
- **`cp`**：在宿主路径与容器 rootfs 之间复制（按容器内路径经 root/bind 翻译）。
- **`run -d`、`logs`、`--restart`**：轻量守护进程 `daemon.py`，第一次用 `-d` 时自动启动；负责拉起容器、把输出写进
  `containers/<cid>/log`、记录退出码、按重启策略重启。前台 `run` 不需要它。日志只多一次管道转发。
- **卷**：`volume create/ls/rm/inspect`，命名卷是 `volumes/<name>/`；`-v name:/path`。
- **只读与原地**：
  - `--read-only`：直接用 `images/<id>/rootfs` 作 root，不复制。只读要靠 guarded 构建的权限向量（root 为 `r`）；
    可写的 `/tmp`、`/run`、`/var/tmp` 与卷由 `containers/<cid>/` 下的目录绑定。不加 `--isolate` 时只是进程内策略，
    加了才由 broker 执行。
  - `--in-place`：直接改镜像 rootfs，适合单人长期使用的“开发镜像”；之后该镜像与 digest 不再一致，meta 标记为 dirty，
    `images` 中显示。
- **其他**：`tag`、`save`（导出 docker-archive / oci-archive）、`history`、`prune`、`ps`/`images` 的 `--format`
  （`{{.ID}}`、`{{.Names}}`、`{{.Image}}`、`{{.Status}}` 等常用字段）。
- **运行中追加卷**（外部 → 容器，见“mount”一节）：`docker volume attach` 一类的扩展命令，由守护进程更新容器的
  共享翻译表，隔离模式下通知 broker 新增一棵树。

**R2 验收**：exec 与入口进程看到同一文件视图；stop 的信号与超时；后台容器的日志与重启；卷的持久化；
`--read-only` 在 guarded + `--isolate` 下写入失败且镜像 rootfs 哈希不变；`nginx:alpine` 改监听非特权端口后
后台运行并用 curl 取页面；追加的卷在运行中可见、隔离模式下权限不超过授权。

## R3 构建

`docker build` 从 `FROM` 取得基础镜像，逐条执行指令，每条改变文件系统的指令产出一层，最后组装成标准 OCI 镜像。

| 指令 | 做法 |
|---|---|
| `FROM`（含多阶段 `AS`） | 按 R1 拉取或使用本地镜像，展开成该阶段的工作 rootfs |
| `RUN` | 用 elfloader 在工作 rootfs 中执行（container 模式、`--link-copy`）；shell 形式经 `SHELL`（默认 `/bin/sh -c`） |
| `COPY`、`ADD` | 从构建上下文复制，遵守 `.dockerignore`；`--from=阶段`；`ADD` 支持 URL 与本地 tar 自动解压；`--chown` 在 R5 前只记录 |
| `ENV`、`ARG`、`--build-arg` | 参与后续指令的变量替换，`RUN` 时作为环境变量 |
| `WORKDIR`、`USER` | 写入配置；`RUN` 时用 `--cwd`、`--user` |
| `ENTRYPOINT`、`CMD`、`EXPOSE`、`VOLUME`、`LABEL`、`STOPSIGNAL`、`HEALTHCHECK` | 只写入镜像配置 |
| `ONBUILD` | 记录到配置，镜像被 `FROM` 时执行 |
| `RUN --mount=type=cache` / `bind` / `secret` | 绑定持久缓存目录 / 上下文目录 / 只读秘密文件；不进入任何层 |
| heredoc（`RUN <<EOF`） | 解析层面支持 |

**层计算**：没有 overlayfs，每条指令前后各扫描一遍工作 rootfs，按大小、mtime、模式比较（必要时比哈希）；新增与修改的
文件打进层 tar，删除的写成 `.wh.` 标记。大 rootfs 每步多几秒到十几秒。`commit` 与 `diff` 用同一机制。R6 之后，
指令直接写合并视图的上层，上层就是这一层，不再扫描。

**缓存**：键为“上一层 id + 指令文本 + `COPY`/`ADD` 源的内容哈希”，命中即复用。

**`push`/`login`**：registry 的 blob 上传（单体或分块）、manifest 上传；`login` 写 `~/.docker/config.json`。

**限制**：`RUN` 中需要特权的命令不行；`chown`/`useradd` 在 fake root 下“成功”但不改宿主文件，R5 之前构建出的镜像
所有文件属于 root（本机运行没问题，导出到别处给 Docker 用不对）；只能构建 arm64；`RUN` 联网用宿主网络。

**R3 验收**：合成 Dockerfile 覆盖每条指令与变量替换、`.dockerignore`、多阶段 `COPY --from`、缓存命中与失效、
删除文件产生 whiteout；构建出的镜像在本机运行结果正确，导出后能被 R1 的 `load` 重新导入且 diff_id 一致；
真实项目（Python、Node 应用的典型 Dockerfile）构建成功，记录首次与缓存命中的耗时。

## mount（R4 与 R2 的追加卷）

真正的内核 mount 不可行：需要 CAP_SYS_ADMIN，普通应用只能经 user namespace 获得，而宿主沙箱拦截 unshare；
pivot_root、chroot、新挂载 API 同样被拦。payload 现在对 mount、umount2、pivot_root、chroot 返回 ENOSYS
（`src/payload/logic/dispatch.c`），隔离过滤器也拒绝它们。能做的是以路径翻译模拟 mount 的效果。按方向分三种：

### 容器内部（R4）

容器里的程序执行 mount 时，payload 接住调用，修改容器的路径翻译表：

| guest 的 mount | 模拟方式 | 差别 |
|---|---|---|
| `mount --bind A B`（含 `-o ro`） | 加一条 B → A 的翻译 | 源 A 是容器视图里的路径，先经现有翻译，只能给已能访问的东西起别名；ro 需要 guarded 或 `--isolate` |
| `mount -t tmpfs none /x` | 绑定容器目录下新建的空目录 | 在磁盘上，size 不生效 |
| `mount -t proc` / `sysfs` / `devpts` | 绑定宿主的对应目录 | 内容是宿主的 |
| `umount` | 删除该条翻译 | — |
| `/proc/self/mounts`、`mountinfo` | 按表伪造 | `findmnt`、`df` 看到一致的结果 |
| `mount -t overlay`、只读镜像的 `mount -o loop` | R6 的合并视图与层镜像提供 | — |
| ext4 等可写镜像、块设备、NFS/CIFS、FUSE | 不支持 | — |

要点：
- **全容器可见**：真实 mount namespace 由容器内所有进程共享。翻译表现在是每进程一份（fork 复制、exec 经参数传递），
  需要改为各进程共享一块内存（memfd），带版本号；隔离模式下 broker 持有权威的表。
- **隔离模式不能借 mount 扩权**：新的 bind 由 broker 登记成树，权限不超过源对象；tmpfs 只能在容器目录中。
  按 ISOLATION_TESTING.md 的方式加验收。
- **新挂载 API**：util-linux 新版先试 fsopen/fsmount/move_mount，对它们返回 ENOSYS 让其退回 mount(2)，需在真实
  镜像中核实。
- **性能**：只有用了 mount 的容器表变长；每次路径调用多读一次共享表的版本号与几条表项，影响很小。

### 外部 → 容器

- 启动时：`-v 宿主:容器`（已支持）。
- 运行中追加（R2）：只能由容器外的守护进程发起，不能由容器内的 mount 触发，否则容器能把任意宿主目录挂进来，越过隔离。

### 容器 → 外部

模拟的 mount 没有在内核中挂载任何东西，只存在于容器的翻译表里，宿主看不到；宿主看到的是底层目录本身（如 tmpfs 对应的
`containers/<cid>/` 下的目录）。挂载传播（`bind-propagation=shared`）不支持。

## R5 属主元数据

- payload 的 stat 系列按 `meta.json`（展开时记录的 uid/gid/模式）报告镜像里的属主；chown/chmod 写入数据库而不改宿主文件
  （类似 fakeroot）；新文件的属主取当前 fake 身份。
- `build`、`commit` 打包层时按数据库写入 tar 头，导出的镜像属主正确。
- 隔离模式下数据库由 broker 持有，guest 不能改写；不加 `--isolate` 时在共享内存里（进程内策略，可被篡改）。
- 按容器开启（`--owners`），不开启的容器 stat 路径不变。
- **验收**：postgres 以 postgres 用户初始化并启动数据目录；sshd 在 StrictModes 下接受密钥；构建中 `chown`/`useradd` 后
  导出的层 tar 头属主正确。

## R6 层镜像与写时复制（实现见文末“R6 实现记录”，与下文设计的差别也写在那里）

- **层镜像**：每层转成一个 erofs 或 squashfs 文件（只读、带压缩；属主、模式、setuid、设备节点、硬链接都保存在镜像元数据中）。
  镜像是普通文件，放在大小写不敏感的存储上也没问题。ext4 读写不做（写回需要完整的日志与分配逻辑）。
- **按需展开**：guest 拿到的必须是内核 FD（read、mmap、getdents 由内核执行），所以 stat、readlink 直接读镜像回答；
  打开文件时先把它展开到缓存目录再打开；列目录时展开这一级目录的骨架（名字齐全、内容未展开）。硬链接展开后仍是副本；
  inode 编号改写为镜像中的值。
- **合并视图**：多个只读层 + 容器可写上层合并成 root：查找先上层后下层，首次写把文件复制到上层，删除写 whiteout，
  目录列表合并去重。payload 与 broker 都实现，隔离模式下由 broker 负责展开与复制，guest 碰不到层镜像。
- **收益**：多个容器共享一份镜像，启动不复制；R3 的层计算不再扫描；`mount -t overlay` 与只读镜像的 `mount -o loop` 可用；
  属主天然随层保存。
- **代价**：查找最多翻倍；大文件首次打开要展开；首次写要复制整个文件。按容器开启，复制式容器继续可用。

## R7 compose 与 Engine API（实现见文末“R7 实现记录”）

- **compose**：解析 `compose.yaml` 与 `.env`（`${VAR}` 替换），按依赖顺序调用 R2 的命令。只能共用宿主网络：服务之间以
  `localhost:端口` 互访，服务名解析写进各容器的 `/etc/hosts` 指向 127.0.0.1；端口冲突的服务不能同时运行。
- **Engine API**：守护进程监听 UNIX 套接字，实现所需工具实际调用的子集（镜像创建与列表、容器 create/start/wait/logs/json、
  exec、attach 流）。
- **安全**：把这个套接字绑进容器等于让容器以宿主身份创建任意容器、绑定任意宿主目录；`--isolate` 下默认禁止，需要显式授权。

## 已知限制（所有版本）

- **属主**：不加 `--owners` 时所有文件在 guest 中显示为 root（fake_id0），postgres、sshd StrictModes 等会失败或要配置；
  加 `--owners` 见 R5。
- **特权操作**：iptables、sysctl、modprobe、创建设备节点、真实挂载不能用；需要 `--privileged` 的镜像不行。
- **进程模型**：没有 pid 命名空间，入口程序不是 pid 1；镜像自带的 tini/dumb-init 能 wait 自己的子进程，但收养不了孙进程。
  `exec` 进入的进程看得到宿主的其他进程。
- **网络**：共用宿主网络；不能隔离、不能端口映射；数据报 UNIX 套接字在 `--isolate` 下不可用（见 STATUS.md）。
- **资源**：没有 cgroup，`--memory`、`--cpus` 不可用，`stats` 只能粗略汇总宿主进程的数据。
- **空间**：复制式容器每个一份 rootfs；`--cow` 容器只占上层（改过与新建的文件）；设备 `/data` 目前剩余 65 GB。

## 待定问题

1. ~~R5 的属主数据库在不加 `--isolate` 时是否值得做~~：做了，两种模式都在共享内存里，不作安全边界（见“R4–R5 实现记录”）。
2. ~~守护进程何时引入~~：R1–R3 都不需要（每容器监视进程）；R7 的 Engine API 需要时再定。
3. `docker` 命令名与真正的 Docker 冲突时的安装方式。
4. ~~R6 选 erofs 还是 squashfs~~：暂不做层镜像。展开后的镜像 rootfs 本来就只有一份、可作所有容器的共享下层，写时复制
   不依赖镜像文件；层镜像只在要放到大小写不敏感的存储上或要省展开空间时才有用（见“R6 实现记录”）。

## R1–R3 实现记录（2026-11-01，HarmonyOS 真机）

**验收 `make check-oci`**（`test/oci/run.py`，独立存储 `/data/storage/el2/base/files/elf-oci-test`）73 项全部通过：
- 展开：合成层覆盖 whiteout、不透明目录（同层新写入的保留）、文件与目录互换、硬链接（可执行文件为符号链接，其余复制）、
  设备节点与 FIFO 跳过、setuid 模式、符号链接链、只读目录；meta.json 记录硬链接、属主、跳过的条目与原模式。
- 展开安全：绝对路径、`..`、经同层与前一层符号链接写入、指向树外的硬链接、超过大小上限，全部拒绝或留在 rootfs 内，
  哨兵目录前后一致，失败不留临时树。
- 校验：篡改的 blob 与不符的 diff_id 使 pull/load 失败；测试 registry 上 bearer token、多平台索引选 arm64、断点续传；
  login（错误密码拒绝、凭据文件 0600）、push 后删除本地镜像再 pull 回来。
- 配置映射（常规与 `--isolate` 各一遍）：Entrypoint/Cmd、参数替换 Cmd、`--entrypoint`、Env/`-e`/`--env-file`（注释、
  空行、只写名字取宿主值、引号原样）、WorkingDir/`-w`、User 名字与 `uid:gid`、`-h`、rw 与 `:ro` 卷、127 与退出码、
  `--privileged`/`--memory`/`-p` 不同端口/`--network none` 以 125 拒绝。
- 生命周期（同上两种）：`run -d`、ps、exec、cp 进出、stop 发镜像的 StopSignal 并保留日志、忽略信号时超时后 SIGKILL（137）、
  `--restart on-failure:2` 与 wait、命名卷持久、`--read-only`（写 /etc 被拒、镜像 rootfs 不变、/tmp 可写、缺失的
  WorkingDir 由私有目录代替）、`--in-place` 标记镜像已修改、system prune。
- 构建：多阶段 Dockerfile 覆盖每条指令、ARG/`--build-arg`、ENV 续行与替换、`.dockerignore`、通配符、`COPY --from`、
  heredoc（RUN 与 COPY）、`--chmod`、ADD 本地 tar、`RUN --mount` cache/bind/secret（bind 不写回上下文）、RUN 删除文件
  产生 whiteout、配置中的 LABEL/EXPOSE/VOLUME/STOPSIGNAL/HEALTHCHECK/ONBUILD；全命中缓存镜像 id 不变；源变化使缓存失效、
  cache 挂载保留；子构建执行 ONBUILD；失败的 RUN 报出退出码；save 再 load 的 diff_id 一致；diff 的 A/C/D 与 commit `-c`。

**真实镜像**（`test/oci/images.py`；镜像在开发机 pull 后 save/load 到设备）：busybox、alpine `apk add curl` 后访问 HTTPS、
debian `apt-get install tree`、python venv + `pip install requests`、node `npm install lodash`，常规与 `--isolate`
下全部成功。联网的几项耗时取决于镜像站（同一命令在几分钟内 8 s 到 300 s 不等，常规与隔离都出现），不能用来比较运行时。
离线负载（2000 次创建/stat/删除文件 + 50 MB sha256）：

| 镜像 | `docker run` | `docker run --isolate` | elfloader 直接运行同一 rootfs |
|---|---|---|---|
| busybox | 0.8 s | 0.8 s | 0.0 s |
| python:3.13-slim（离线负载） | 2.0 s | 2.0 s | 0.6 s |

guest 执行时间相同；docker 自身的固定开销约 0.8 s（Python 启动与容器记录）加上复制 rootfs（python 镜像 144 MB 约 1.2 s），
这正是 R6 写时复制要去掉的部分。交互 `-it` 已在 ssh 伪终端中验证（提示符、`tty` 显示 `/dev/pts/N`：宿主不允许列出
/dev/pts，runspec 单独绑定继承的终端设备）。

## R4–R5 实现记录（2026-11-01，HarmonyOS 真机）

验收：`test/proot/test_mounts.py`、`test/proot/test_owners.py`（`make check`，两种构建 × 常规与 `--isolate`）；
`make check-oci` 87 项（新增容器内 tmpfs/bind/umount、`docker exec` 加入挂载、`--owners` 的镜像属主与模式、
chown/chmod/用户新文件/EPERM、diff、commit 与 build 的层 tar 头）全部通过。

### R4 容器内 mount

- **共享表**：`src/payload/include/container_state.h`。48 个槽，每槽 guest 挂载点、宿主路径、source、fstype、
  MS_* 标志、创建序号、guarded 访问级别；写者持锁并把版本号置奇，读者复制后核对版本。loader 的 `--emulate-mounts`
  新建一张（memfd），`--mount-table FILE` 打开或新建一个文件（docker 用 `containers/<id>/mounts.table`，`docker exec`
  打开同一文件即加入容器的挂载；每次 start 删掉重建）。表以 FD 901 继承，子 loader 收 `--mount-table-fd`。
  guest 不能关闭、dup 覆盖或 F_SETFD 这个 FD（与隔离模式的保留 FD 同一套守卫，现在不加 `--isolate` 也生效），
  closefrom 循环和 /proc/self/fd 列表里看不到它。
- **翻译**：每次路径调用把表追加在配置的 bind 之后：槽 i 的挂载编号固定为 bind 数 + 1 + i，空槽和被遮住的槽占位但
  不匹配任何路径，所以 FD 与 cwd 记录的挂载编号在别的挂载变化后仍然有效。新挂载遮住它之下（含同一点）所有较早的挂载，
  包括配置的 bind（内核挂载栈的语义），umount 后重新露出。
- **支持**：`mount --bind`（含 `--rbind`：源之下的挂载复制到目标之下；`-o ro` 用 remount）、tmpfs/ramfs（挂载 scratch
  下新建目录，`mode=`、`uid=`、`gid=` 生效，size 不生效）、proc、sysfs、devpts、mqueue、cgroup、cgroup2 等（宿主的
  对应目录；宿主没有时给空目录）、MS_MOVE、MS_REMOUNT（只对容器内的挂载）、传播类型（接受，无事可做）、umount2
  （有子挂载时 EBUSY，MNT_DETACH 一并卸下）。不支持的类型（ext4、overlay、nfs、fuse…）ENODEV；挂载点不存在
  ENOENT；umount 非挂载点 EINVAL，root 与配置的 bind EBUSY。fsopen/fsmount/move_mount/open_tree/mount_setattr 等
  新 API 返回 ENOSYS（util-linux 与 busybox 回退到 mount(2)）。
- **/proc/<pid>/mounts、mountinfo**（含 /proc/mounts、self、thread-self、task/<tid>）：按 root、配置的 bind、
  容器内挂载（创建顺序）生成到 memfd；mountinfo 的父编号取覆盖它的最近一条，设备号取宿主目录的 st_dev。
  别的进程只有在它也是 loader 运行的进程时才伪造。
- **只读**：guarded 构建里每个槽带访问级别（bind 取源所在挂载的级别，tmpfs 可写，宿主类取挂载点所在挂载的级别，
  `ro` 降为只读），路径修改保护照此执行，`--read-only` 容器里的 tmpfs 仍可写；普通构建只显示 `ro` 不执行。
- **隔离模式**：broker 不读这张表，挂载只能给 broker 已允许的树起别名；tmpfs 的 scratch 目录是 broker 的一棵可写树。
  所以容器内 mount 不能扩权。普通构建加 `--isolate` 时 `-o ro` 不执行（broker 按自己的树判断）。
- **差别**：loader 自己解析 PT_INTERP 与 `--cwd` 只看配置的 bind（挂在 /lib 上的 bind 不影响动态链接器的查找）；
  `docker cp` 不经容器内的挂载；挂载传播不存在。

### R5 属主

- **数据库**：同一头文件，开放寻址散列，键为宿主文件的 (st_dev, st_ino)，记录 uid/gid（OWNER_IDS）与完整模式
  （OWNER_MODE），删除留墓碑。`tools/oci/owners.py` 写同样的格式：`docker create --owners` 时按镜像 meta.json 的
  属主与模式建 `containers/<id>/owners.db`（容量 2^16 起，负载不超过 7/8，满了 chown 返回 ENOSPC）。loader
  `--owner-db FILE` 打开它并以 FD 902 继承（`--owner-db-fd`），同样受保留 FD 守卫。
- **payload**：stat/fstat/newfstatat/statx 结果按记录改写 uid/gid 与权限位；没有记录时用户自己的文件报告为
  root（不再是 fake 保存 uid，所以 `--user` 下镜像文件仍属 root）。chown/fchown/fchownat/lchown 只写记录，非特权的
  fake 用户不能把文件给别人、只能把组改成自己的组（EPERM）；chmod 在宿主上保留属主 rw（目录 rwx），宿主拒绝的
  setuid/sticky 去掉，guest 的模式与宿主不同才记录。新建的文件、目录、符号链接、设备节点、tmpfs 归当前 fake
  fs uid/gid（root 时清掉旧记录，防止复用的 inode 带着旧属主）；unlink、rmdir 与替换目标的 rename 取走最后一个名字时
  删除记录。setuid/setgid 程序按记录的属主与模式切换 fake 身份。
- **build/commit/diff**：`build` 的 RUN 总是带数据库运行（按阶段的 meta 建立，结束后读回），`COPY --chown` 写进
  meta（不带组时 GID = UID，名字从镜像的 /etc/passwd 解析）；只改了属主或模式的路径也算变化。层 tar 头的
  uid/gid/mode 取 meta；`commit` 与 `diff` 读容器的数据库。缓存命中的层把自己的属主并回阶段 meta；展开时后面的层
  覆盖前面层的记录。
- **不是安全边界**：两张表都在 guest 可写的共享内存里，改写它们只改变 guest 看到的视图与报告的属主，碰不到
  别的文件（隔离模式下 broker 只按自己的树判断）。待定问题 1 因此按“值得做”处理。
- **差别**：宿主之外复制或解包产生的新 inode（例如 `docker cp` 进来的文件）没有记录，显示为 root；硬链接复制
  （`--link-copy`）得到的新文件归创建者，不继承源的属主；chown 不清 setuid 位。

## R6 实现记录（2026-11-01，HarmonyOS 真机）

验收：`test/proot/test_union.py`（`make check`，两种构建 × 常规与 `--isolate`；Alpine 作下层，复制上层、whiteout、不透明
目录、目录改名 EXDEV 回退复制、合并列表、下层 cwd、容器内 overlay 挂载，结束时逐字节核对下层未变）；`make check-oci`
87→99 项（新增 `--cow` 的写入只进上层且镜像 rootfs 不变、另一个容器看不到、diff、cp 进出、commit，常规与 `--isolate`
各一遍；`--cow --owners`；与 `--read-only` 互斥）全部通过。

### 合并视图（payload）

- **loader**：`--root UPPER --lower LOWER`（可重复，最上层在前，最多 8 层）。根就是上层，下层只读。子 loader 收到同样的
  `--lower`；loader 自己打开的首个程序、PT_INTERP 与 `--cwd` 在上层没有时取最上面有它的下层。payload ABI 24。
- **格式**：上层就是 OCI 层 diff：复制上来的与新建的条目、`.wh.<名字>` whiteout、`.wh..wh..opq` 不透明目录。所以一份
  展开的层目录也能直接作下层。以 `.wh.` 开头的名字在视图里永远不可见，guest 也不能创建（EPERM）。
- **查找**（`src/payload/logic/union_view.c`）：每个分量取最上面有它的层；非目录或不透明目录截断下面的层；whiteout 隐藏
  下面的层。路径翻译对每个前缀映射一次，同一次调用复用公共前缀的结果，所以每个分量多 1–3 次 lstat（设计说的“查找最多翻倍”）。
- **写**：改内容（写方式或截断 open）、chmod、utimensat、truncate、xattr、link 的源先复制上来（父目录一并；普通文件写到隐藏
  的临时名再改名，并发安全；保留模式与时间，属主数据库的记录随之转到新 inode）；创建先在上层补齐父目录并去掉 whiteout，
  在 whiteout 处新建的目录设为不透明；unlink/rmdir 删上层的并在下层有时留 whiteout，合并后非空的目录 ENOTEMPTY；rename
  复制源、目标处理同上，下层有的目录改名 EXDEV（与不开 redirect_dir 的 overlayfs 相同，mv 会退回复制）。FD 上的 fchmod 与
  `utimensat(fd, NULL)` 按 FD 的路径复制上来再改。开了属主数据库时，下层对象的 chown/chmod 只记录，不复制也不碰共享的文件。
- **列目录**：内核先列 FD 自己那一层（去掉 `.wh.` 名字）；读完后 payload 用自己的 FD 依次读下面的层，去掉上层已有或被
  whiteout 的名字。rewind 后内核重新返回条目，状态随之重置。
- **反向映射**：内核给出的下层路径（cwd、`/proc/self/fd`）按根的上层命名；目录被复制上来之后，旧 FD/cwd 仍得到同一个 guest 名字。
- **隔离模式**：broker 把下层登记为只读树，即使绕过 payload 的视图逻辑也写不到下层；合并视图本身不是安全边界。合并视图要
  自己查找，所以开启时不走乐观的词法解析。
- **容器内 `mount -t overlay`**（R4 的表）：`lowerdir=A:B,upperdir=U,workdir=W` 在目标处建立同样的合并视图（下层路径存在
  挂载表的附加区，不进入每次路径调用复制的槽快照）；没有 upperdir 时只读。宿主路径属于上层最长匹配的视图，所以对合并目录的
  bind 也是合并的；直接访问 lowerdir 本身看到的是它自己。

### docker

- `run`/`create --cow`（HostConfig `Cow`）：不复制 rootfs，镜像 rootfs 作下层、`containers/<id>/upper` 作上层；exec helper
  与缺失的 WorkingDir 建在上层。与 `--read-only`、`--in-place` 互斥（125）。`--owners` 的数据库按镜像 rootfs 的 inode 建立，
  复制上来时记录随之转移。
- `diff`、`commit`、`cp`、用户解析用 `tools/oci/union.py` 读同一个合并视图：diff 比较镜像与合并后的快照；commit 的层从
  显示该文件的那一层读取，新镜像的 rootfs 是镜像副本应用上层；`cp` 进容器写到上层（下层目录先在上层建立）；`inspect` 的
  GraphDriver 多出 UpperDir、LowerDir。复制式容器照旧可用，仍是默认。

### 与设计的差别

- **没有层镜像**（erofs/squashfs、按需展开）与 `mount -o loop`：共享与写时复制只需要已展开的镜像 rootfs，它本来就只有一份；
  层镜像要在 payload 与 broker 里各实现一个文件系统读取器加按需展开的缓存，收益只是能放在大小写不敏感的存储上、少占展开
  空间。需要时再做。
- **build 仍按扫描计算层**：RUN 还在复制式工作 rootfs 上执行；改成直接写合并视图的上层留待之后。
- **下层不按层拆分**：docker 的下层是展开后的整个镜像 rootfs（一层）；loader 支持多层，`build` 与按层共享还没有用上。
- **inode**：复制上来后 st_ino 改变（overlayfs 会保持）；已打开的下层 FD 继续读旧内容；硬链接复制后各自独立（本机本来就
  不能建硬链接）。overlay 挂载的上层里的 whiteout 在根的视图里看不见（真实 overlayfs 里是字符设备，可见）。
- **guarded 的安全遍历**：路径落在下层时不经 mount 根的逐级 O_NOFOLLOW 遍历（下层只读，guest 不能在里面放符号链接）。

## R7 实现记录（2026-11-01，HarmonyOS 真机）

验收：`make check-oci` 99→121 项（compose 9 项、Engine API 13 项）全部通过；另用 docker-py 7.2.0（官方 Python SDK）
对 `docker engine` 跑通 `containers.run`（前台取输出、非零退出码的 ContainerError）、后台运行、`exec_run`（含
stdout/stderr 分流）、`put_archive`/`get_archive`、按标签过滤列表、流式 logs、wait、stop、remove、镜像列表、卷。

### compose（`tools/oci/compose.py`）

- **文件**：`compose.yaml`/`compose.yml`/`docker-compose.y(a)ml`，同目录的 override 文件，多个 `-f`（合并：映射合并，
  ports/volumes 等列表追加，其余替换），`extends`。YAML 由 `yamlite.py` 解析（块映射与序列、引号与块标量、行内集合、
  锚点/别名/`<<`；按 YAML 1.2，`yes` 是字符串，`0755` 按八进制），与 PyYAML 对拍过。
- **变量**：`.env`（或 `--env-file`）、环境变量；`${VAR}`、`:-`、`-`、`:?`、`?`、`:+`、`+`、`$$`。项目名取 `-p`、
  `COMPOSE_PROJECT_NAME`、`name`、目录名（规范为小写）。profiles（`--profile`、`COMPOSE_PROFILES`）。
- **服务**：每个服务经与 `docker create` 相同的路径建成容器 `{项目}-{服务}-1`，带 `com.docker.compose.*` 标签（项目、
  服务、编号、配置哈希）；由监视进程运行，与 `run -d` 相同。支持 image、build（context、dockerfile、
  dockerfile_inline、args、target、labels、secrets）、command/entrypoint（字符串按 shell 规则拆分）、environment、
  env_file、volumes（短/长写法；命名卷是 `{项目}_{名字}`，external 与 name 照规范）、tmpfs、ports、working_dir、user、
  hostname、container_name、restart、labels、extra_hosts、dns、stop_signal、stop_grace_period、read_only、tty、
  stdin_open、secrets 与 configs（file、environment、content）、healthcheck，以及扩展 `x-elf: {isolate, cow, owners}`。
  需要命名空间或 cgroup 的键（networks、cap_add、mem_limit、deploy、init……）警告后忽略。
- **网络**：与宿主共用。每个容器的 `/etc/hosts` 把所有服务名（和 container_name）指向 127.0.0.1，所以
  `http://db:端口/` 可用；同一端口只能有一个服务监听。
- **依赖**：按 depends_on 拓扑排序（有环报错）；`service_healthy` 由 compose 自己按 healthcheck（服务的或镜像的）
  在容器里反复执行检查命令，`service_completed_successfully` 等待退出码 0。
- **命令**：up（`-d`、`--build`、`--force-recreate`、`--no-recreate`、`--no-deps`、`--remove-orphans`、`--wait`、
  前台模式带前缀输出、`--abort-on-container-exit`、`--exit-code-from`，Ctrl-C 停止）、create、down（`-v`、`--rmi`）、
  ps、logs（`-f`、`--tail`）、exec、run（`--rm`、`--no-deps`、一次性容器）、start/stop/restart/kill/rm、build、
  pull、config（`--services`、`--format json`）、images、port、top、ls、version。配置哈希不变的服务 up 时保留，改了才重建。
- **差别**：没有项目网络、网络别名与服务间隔离；`deploy.replicas`/`scale` 只建一个；healthcheck 只在 compose 等待
  依赖或 `--wait` 时执行（容器没有持续的健康状态，ps 不显示 healthy）。

### Engine API（`tools/oci/engine.py`）

- `docker engine [-H unix:///path]`：ThreadingUnixStreamServer 上的 HTTP/1.1，默认 `$ELF_OCI_HOME/docker.sock`，
  0600；只接受 unix://（TCP 会把 API 暴露给网络）。SIGTERM/SIGINT 退出并删除套接字。路径前缀 `/v1.xx` 都接受，报告
  API 1.43。
- **接口**：`_ping`、`version`、`info`；images（json、`{name}/json`、create 即 pull、tag、DELETE）；containers
  （create、json 带 all/filters(label、name、id、status、ancestor)/limit、`{id}/json`、start、stop、restart、kill、
  wait（condition）、DELETE（force、v）、rename、logs（tail、follow）、attach、top、resize、archive 的 GET/HEAD/PUT）；
  exec（create、start（Detach、Tty、AttachStdin）、json、resize）；volumes（列表、create、inspect、DELETE）；networks
  （只有 host 与 bridge 两个名字，都是宿主网络；create 返回 501）。
- **流**：没有 TTY 时用多路复用帧（8 字节头，stdout 1、stderr 2）；客户端请求 `Connection: Upgrade` 时以 101 劫持连接
  （attach、exec start），否则以关闭连接结束响应。容器日志里 stdout 与 stderr 已合并，logs 都作为 stdout 帧；exec 的
  两路分开。
- **创建**：JSON 翻译成 `docker create` 的选项后走同一路径（校验、镜像配置、runtime.create），Cmd/Entrypoint 原样使用；
  PortBindings 的 HostPort 为空或等于容器端口（发布为端口本身，inspect 的 NetworkSettings.Ports 照此报告），不同则 400；
  Privileged 400；CapAdd、Memory 等进 Warnings；HostConfig 的 `Isolate`、`Cow`、`Owners` 是 ELF 的扩展。
- **安全**：把引擎套接字（默认路径、`DOCKER_HOST`、正在服务的路径）绑进 `--isolate` 容器会被拒绝（API 与命令行都是），
  除非设 `ELF_OCI_ALLOW_ENGINE_SOCKET=1`。不加 `--isolate` 的容器本来就以应用身份运行，绑进去不额外扩权。
- **差别**：没有 build、commit、events、stats、export/import、swarm、plugins、networks 的创建；attach 只有输出（没有
  向容器主进程写 stdin）；exec 实例只在引擎进程内存里。

