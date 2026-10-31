# Docker/OCI 镜像支持（设计，未实现）

## 目标

在 HarmonyOS 应用沙箱内，不依赖 Docker 守护进程，直接运行 arm64 的 Docker/OCI 镜像：

```
tools/oci/oci.py pull python:3.13-slim
tools/oci/oci.py run --rm -v ~/work:/work -w /work python:3.13-slim python -m pip install requests
tools/oci/oci.py run --isolate debian:bookworm-slim bash
```

镜像本质上是“一个 rootfs + 一份启动配置”。本设计做三件事：取得镜像、把各层展开成 rootfs、
把镜像配置与 `docker run` 风格的参数翻译成 elfloader 的命令行。运行时仍然是现有的 loader
（PRoot 语义，可选 `--isolate`），不引入新的执行机制。

**不是目标**：容器构建（Dockerfile）、编排、`docker` CLI 的完整兼容、x86 镜像。

## 约束（本机实测，见 STORAGE_CAPABILITIES.md、STATUS.md）

| 约束 | 影响 |
|---|---|
| 没有 mount、命名空间、cgroup（宿主沙箱拦截 unshare，应用无权 mount） | 没有 overlayfs，没有 pid/网络/IPC 隔离与资源限制；网络与宿主共用 |
| 应用不能建硬链接（各位置 EPERM/EACCES） | 层内硬链接展开为副本，运行时加 `--link-copy` |
| 应用不能 chown，文件属主都是应用 uid | 镜像记录的属主在展开时丢失；fake_id0 把宿主属主报告为 root |
| `/storage/Users` 大小写不敏感 | 镜像只能展开在大小写敏感的位置（`/data/storage/el2/base/files/...`） |
| 只有 AArch64，原生 exec 未签名 ELF 会失败 | 只接受 `linux/arm64` 镜像；所有程序都经 loader 运行（现状如此） |
| 设备上 Python 3.14.7，带 `compression.zstd`；没有 skopeo/crane | 工具用纯 Python 写，gzip 与 zstd 层都能解 |

## 结构

```
tools/oci/
  oci.py        命令入口：pull / import / images / rmi / create / run / ps / rm / prune
  registry.py   registry v2 客户端（token 认证、manifest、blob 下载与校验）
  store.py      本地存储：blob、镜像、容器的目录与元数据
  unpack.py     按层展开（whiteout、安全检查、硬链接副本）
  runspec.py    镜像配置 + 运行参数 → elfloader argv
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
containers/<cid>/etc/              生成的 resolv.conf、hosts、hostname
containers/<cid>/run.json          最终的 loader 命令行、状态、退出码
```

## 取得镜像

### registry 拉取（`pull`）

1. 解析引用：`[registry/]name[:tag|@digest]`，默认 `registry-1.docker.io`、`library/`、`latest`；
   支持 `--registry-mirror`。
2. `GET /v2/<name>/manifests/<ref>`，Accept 同时列 Docker v2 与 OCI 的 manifest / index 类型。401 时按
   `WWW-Authenticate` 的 realm/service/scope 取匿名 bearer token；有 `~/.docker/config.json` 的
   凭据则带上（只读该文件，不写）。
3. index / manifest list：选 `os=linux, architecture=arm64`（variant 为空或 `v8`）；没有则报错并列出可用平台。
4. 下载 config 与各层 blob 到 `blobs/`，边下边算 sha256，与 digest 不符即删除并失败；支持断点续传（Range）。
5. 解压后的每层 tar 再算一次 sha256，与 config 的 `rootfs.diff_ids` 逐个核对。

只用 HTTPS；不支持 schema 1 manifest。

### 离线导入（`import`）

在别处 `docker save` 或 `skopeo copy ... oci-archive:` 得到的 tar，或 OCI layout 目录。按其
`manifest.json` / `index.json` 找到 config 与层，之后与拉取相同（校验、入库）。设备没联网或要用私有镜像时
走这条路。

## 展开（`unpack.py`）

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
| 属主 uid/gid | 不能 chown；记入 meta |
| xattr（含 `security.capability`） | 忽略，记入 meta |

同一路径在后层被替换时（文件换目录、目录换文件）先删除旧的。全部层成功后才把临时目录改名为 `rootfs/`，
中途失败不留半成品。

## 容器实例

没有 overlayfs，提供三种方式（`run` / `create` 的选项）：

1. **复制（默认）**：`containers/<cid>/rootfs` 是镜像 rootfs 的完整副本，容器随意修改，`rm` 时删除。
   代价是时间与空间（debian-slim 约 80 MB、python-slim 约 150 MB）。
2. **只读**（`--read-only`）：直接用 `images/<id>/rootfs` 作 root，不复制。plain 构建中所有树都可写，
   所以只读要靠 guarded 构建的权限向量（root 为 `r`）；可写的 `/tmp`、`/run`、`/var/tmp` 与卷由
   `containers/<cid>/` 下的目录绑定。不加 `--isolate` 时这只是进程内策略，加了才由 broker 执行。
3. **原地**（`--in-place`）：直接改镜像 rootfs，适合单人长期使用的“开发镜像”，之后该镜像不再与 digest 一致
   （meta 标记为 dirty，`images` 中显示）。

真正的写时复制（下层只读、上层可写的路径合并）需要在 payload 与 broker 里加一层合并视图，见“分阶段”第 4 步。

## 配置映射（`runspec.py`）

| 镜像配置 / `run` 参数 | elfloader |
|---|---|
| Entrypoint + Cmd；`--entrypoint`、命令行参数 | 程序与参数（Docker 规则：参数替换 Cmd，`--entrypoint` 替换 Entrypoint） |
| Env；`-e K=V`、`--env-file` | `-e`（container 模式从空环境开始，正合 Docker 语义）；无 PATH 时补默认值 |
| WorkingDir；`-w` | **新增 `--cwd`**（见下） |
| User；`-u` | **新增 `--user`**（见下） |
| Volumes；`-v HOST:GUEST[:ro]` | `-v`；镜像声明的卷建匿名目录；`:ro` 需要 guarded 构建或 `--isolate`，否则报错而不是悄悄可写 |
| `--hostname`，默认取容器 id 前 12 位 | **新增 `--hostname`**（uname 的 nodename）与生成的 `/etc/hostname`、`/etc/hosts` |
| ExposedPorts；`-p` | 无对应：网络与宿主共用，程序监听的端口就是宿主端口；`-p` 给警告，同端口映射时忽略，不同端口时报错 |
| StopSignal | `oci.py` 把收到的 SIGINT/SIGTERM 转成该信号发给 guest |
| `-it`、`-t` | 终端直接继承，不分配新 pty |
| `--rm`、`--name` | 容器目录的生命周期与命名 |
| `--isolate`、`--isolate-device` | 原样传给 loader |
| Healthcheck、OnBuild、Shell、Labels | 忽略（Labels 在 `images` 中显示） |

**固定附加**：`--mode container --root <rootfs> --link-copy`；`-v /proc:/proc`；
`/dev/null`、`/dev/zero`、`/dev/full`、`/dev/random`、`/dev/urandom`、`/dev/tty`、`/dev/ptmx` 逐个绑定
（不绑整个 `/dev`）；`/dev/shm` 绑容器自己的目录；`/etc/resolv.conf` 用宿主的（本机存在），
`/etc/hosts`、`/etc/hostname` 用容器生成的，均以文件 bind 覆盖，不改 rootfs。

**隔离时的权限向量**（guarded 构建 + `--isolate`）：root 为 `w`（复制/原地）或 `r`（只读），镜像卷与
`-v` 为 `w`，`:ro` 为 `r`，`/proc`、只读设备为 `r`。plain 构建 + `--isolate` 时全部为 `w`，仍然有树外不可达的边界。

## loader 需要的新参数

现在的 loader 缺三样东西，都是小改动：

- **`--cwd DIR`**（guest 路径）：初始 loader 现在总是 chdir 到 root。改为 chdir 到 DIR 按 root/bind 翻译出的
  宿主路径（loader 已有 `resolve_interp_path` 做这种词法映射）；不存在时报错退出，与 Docker 一致。
  隔离模式下发生在装过滤器之前，不经 broker。
- **`--user UID[:GID]`**：设置 fake_ids（实/有效/保存/fs 全部）与补充组。子 loader 协议里已有内部的
  `--fake-ids`、`--fake-groups`，这里只是提供用户入口；名字到数字的解析由 `oci.py` 读镜像的
  `/etc/passwd`、`/etc/group` 完成，loader 只收数字。
- **`--hostname NAME`**：payload 的 uname 改写 nodename（与 `--kernel-release` 同一处）；sethostname
  在没有 UTS 命名空间时无法真正生效，先返回 EPERM（与非特权进程一致），有需要再考虑记录在本进程树内。

每项加回归测试（`test/proot/`），并在 `ELF_LOADER_OPTIONS=--isolate` 下通过。

## 已知限制

- **属主**：所有文件在 guest 中显示为 root（fake_id0）。对属主敏感的程序会失败或要配置：postgres 要求
  数据目录属于自己的用户，sshd 的 StrictModes，某些包管理器的属主检查。第 3 步的“属主元数据”可改善。
- **特权操作**：mount、iptables、sysctl、modprobe、创建设备节点的镜像不能用；需要 `--privileged` 的不行。
- **进程模型**：没有 pid 命名空间，入口程序不是 pid 1；依赖 pid 1 收养僵尸进程的镜像可以靠镜像自带的
  tini/dumb-init（它们作为普通进程照样会 wait 子进程，但收养不了孙进程）。
- **网络**：共用宿主网络；不能隔离、不能端口映射；数据报 UNIX 套接字在 `--isolate` 下不可用（见 STATUS.md）。
- **空间**：复制方式每个容器一份 rootfs；设备 `/data` 目前剩余 65 GB。

## 分阶段

1. **离线导入 + 展开 + 运行**：`import`、`unpack.py`、`runspec.py`、`run`（复制方式），loader 加 `--cwd`、
   `--user`、`--hostname`。验收见下。
2. **registry 拉取与本地管理**：`pull`（匿名与凭据、镜像源、断点续传）、`images`/`rmi`/`ps`/`rm`/`prune`，
   `--read-only` 与 `--in-place`。
3. **属主元数据**（可选）：payload 的 stat 系列按 `meta.json` 报告镜像记录的 uid/gid/模式，chown 写回 meta
   （类似 fakeroot 的数据库）；隔离模式下由 broker 持有该数据库，guest 不能改写。
4. **写时复制视图**（可选）：payload 与 broker 把“镜像 rootfs（只读）+ 容器上层目录（可写）”合并成一个
   root：读找上层再找下层，写时把文件复制到上层，删除用上层的 whiteout 标记，目录列表合并两层。
   多个容器共享一份镜像，启动不再复制。这一步改动大，需单独设计。

## 验收（第 1、2 步）

设备：HarmonyOS 真机。脚本 `test/oci/`，`make check-oci`。

- **展开正确性**：用合成镜像（脚本生成层 tar）覆盖：whiteout、不透明目录、文件与目录互换、硬链接副本、
  设备节点跳过、模式与 setuid、符号链接链；与期望树逐项比较。
- **展开安全**：绝对路径、`..`、经符号链接写入（同层与跨层）、超大条目，全部拒绝且不在 rootfs 外留下任何文件
  （哨兵目录前后哈希一致）。
- **校验**：篡改 blob 或 diff_id 不符时拉取/导入失败。
- **配置映射**：Entrypoint/Cmd/`--entrypoint` 组合、Env 覆盖、WorkingDir、User（名字与数字）、卷、
  hostname，逐项对比 guest 内看到的结果。
- **真实镜像**（常规与 `--isolate` 各一遍）：`alpine` 跑 apk add；`debian:bookworm-slim` 跑 apt-get install；
  `python:3.13-slim` 建 venv 并 pip install；`node:lts-alpine` 跑 npm install；`nginx:alpine` 改监听非特权端口
  后用 curl 取页面；`busybox` 静态程序。记录耗时与原生（如有）对比。
- **卷与只读**：`-v` 写入在宿主可见；`:ro` 与 `--read-only` 在 guarded + `--isolate` 下写入失败，镜像 rootfs
  哈希不变。

## 待定问题

1. 复制方式是否值得用硬链接以外的手段省空间（本机不支持 reflink 与硬链接，暂无）。
2. 第 3 步的属主元数据放在 payload（进程内，可被篡改）还是只在 `--isolate` 下由 broker 提供。
3. `oci.py` 是否需要常驻进程（容器列表、日志）；第 1 步按无状态命令实现，状态都在 `containers/<cid>/run.json`。
