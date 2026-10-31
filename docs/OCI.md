# Docker/OCI 镜像支持（设计，未实现）

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

## 结构

```
tools/oci/
  docker        命令入口（Python）：按 Docker 的子命令与参数解析
  registry.py   registry v2 客户端（token 认证、manifest、blob 下载上传与校验）
  store.py      本地存储：blob、镜像、容器、卷的目录与元数据
  unpack.py     按层展开（whiteout、安全检查、硬链接副本）
  runspec.py    镜像配置 + 运行参数 → elfloader argv
  daemon.py     R2：轻量守护进程（后台容器、日志、重启策略）
  build.py      R3：Dockerfile 解析与执行、层计算、缓存
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
| 硬链接 | 复制目标文件内容（宿主不允许硬链接），meta 记录链接关系 |
| 字符/块设备、FIFO | 跳过并记入 meta（运行时从宿主绑定 `/dev`） |
| 属主 uid/gid | 不能 chown；记入 meta（R5 使用） |
| xattr（含 `security.capability`） | 忽略，记入 meta |

同一路径在后层被替换时（文件换目录、目录换文件）先删除旧的。全部层成功后才把临时目录改名为 `rootfs/`，
中途失败不留半成品。

### 容器实例

R1 只有复制方式：`containers/<cid>/rootfs` 是镜像 rootfs 的完整副本，容器随意修改，`rm` 时删除。代价是
启动时间与空间（debian-slim 约 80 MB、python-slim 约 150 MB），运行时就是普通目录。R2 加只读与原地方式，
R6 加共享镜像的写时复制。

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
值不做 shell 处理，引号原样保留。loader 的 `-e` 上限（现为 16）放大到足够容纳常见的环境文件。compose 的 `.env`
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

## R6 层镜像与写时复制（需单独详细设计）

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

## R7 compose 与 Engine API（按需）

- **compose**：解析 `compose.yaml` 与 `.env`（`${VAR}` 替换），按依赖顺序调用 R2 的命令。只能共用宿主网络：服务之间以
  `localhost:端口` 互访，服务名解析写进各容器的 `/etc/hosts` 指向 127.0.0.1；端口冲突的服务不能同时运行。
- **Engine API**：守护进程监听 UNIX 套接字，实现所需工具实际调用的子集（镜像创建与列表、容器 create/start/wait/logs/json、
  exec、attach 流）。
- **安全**：把这个套接字绑进容器等于让容器以宿主身份创建任意容器、绑定任意宿主目录；`--isolate` 下默认禁止，需要显式授权。

## 已知限制（所有版本）

- **属主**：R5 之前所有文件在 guest 中显示为 root（fake_id0），postgres、sshd StrictModes 等会失败或要配置。
- **特权操作**：iptables、sysctl、modprobe、创建设备节点、真实挂载不能用；需要 `--privileged` 的镜像不行。
- **进程模型**：没有 pid 命名空间，入口程序不是 pid 1；镜像自带的 tini/dumb-init 能 wait 自己的子进程，但收养不了孙进程。
  `exec` 进入的进程看得到宿主的其他进程。
- **网络**：共用宿主网络；不能隔离、不能端口映射；数据报 UNIX 套接字在 `--isolate` 下不可用（见 STATUS.md）。
- **资源**：没有 cgroup，`--memory`、`--cpus` 不可用，`stats` 只能粗略汇总宿主进程的数据。
- **空间**：R6 之前每个容器一份 rootfs；设备 `/data` 目前剩余 65 GB。

## 待定问题

1. R5 的属主数据库在不加 `--isolate` 时是否值得做（进程内可被篡改，但对兼容性仍有用）。
2. 守护进程是否在 R1 就引入（统一状态管理），还是保持 R1 无常驻进程、R2 再引入（当前方案）。
3. `docker` 命令名与真正的 Docker 冲突时的安装方式。
4. R6 选 erofs 还是 squashfs：erofs 随机读更快、格式更简单，squashfs 工具更普及；需要各写一个读取器原型比较。
