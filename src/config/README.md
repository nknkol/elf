### 1\. 配置文件设计 (`Appfile`)

采用\*\*“单文件、双视图”\*\*策略。Loader 和 Init 读取同一个文件，但各自只解析自己关心的指令，忽略未知的指令。

**语法规范：**

```dockerfile
# ==========================================
# [Host Layer] 基础设施配置
# 执行者：Loader (elfloader)
# 作用域：宿主视角，决定容器如何“坐落”在宿主机上
# ==========================================
ROOT ./alpine-rootfs         # 容器物理根目录
BIND ./data:/var/lib/mysql   # 挂载数据卷 (Host:Guest)
DEBUG on                     # 开启 Loader 调试日志
PAYLOAD ./payload.elf         # 指定 Payload 路径

# ==========================================
# [Guest Layer] 运行环境配置
# 执行者：Init (tiny-init)
# 作用域：容器视角，决定应用如何运行
# ==========================================
ENV PORT=8080                # 设置环境变量
ENV JAVA_HOME=/opt/java
WORKDIR /app                 # 切换工作目录
RUN mkdir -p logs            # 初始化命令 (阻塞)
DAEMON /bin/redis-server     # 后台服务 (非阻塞，Init 负责收尸)
CMD /bin/python3 main.py     # 主进程
```

-----

### 2\. 组件职责划分

#### A. Loader (`elfloader`) —— “建筑师”

  * **角色**：宿主环境下的引导程序，静态链接，无 libc。
  * **职责**：
    1.  **解析 Host 配置**：读取 `Appfile`，解析 `ROOT`, `BIND`, `DEBUG`。
    2.  **创建隔离**：调用 `unshare` 创建 User/Mount Namespace。
    3.  **清洗环境**：清空宿主环境变量，构建极简环境（仅包含 CLI 传入的 `-e`）。
    4.  **配置传递**：将 `Appfile` 的文件描述符（FD）保留，通过 `memfd` 或直接传递 FD 编号给 Init。
    5.  **加载 Init**：将嵌入在自身的 `tiny-init` 二进制提取到内存（`memfd`），并作为目标程序加载。

#### B. Payload (`payload.so`) —— “虚拟层”

  * **角色**：注入到进程内的 Hook 库，使用 `mini_libc`。
  * **职责**：
    1.  **拦截 Syscall**：Hook `openat`, `execve`, `connect` 等。
    2.  **路径重写**：根据 Loader 解析的 `ROOT` 和 `BIND` 规则，将容器内路径翻译为宿主物理路径。
    3.  **透明化**：对上层应用透明，应用感觉自己运行在标准 Linux 中。

#### C. Init (`tiny-init`) —— “管家”

  * **角色**：容器内的 PID 1，静态链接，使用标准 libc。
  * **职责**：
    1.  **解析 Guest 配置**：从 Loader 传入的 FD 读取 `Appfile`，解析 `ENV`, `WORKDIR`, `RUN`, `CMD`。
    2.  **装修环境**：设置默认 `PATH`、`HOME`，执行 `RUN` 里的初始化命令。
    3.  **进程管理**：
          * `fork+exec` 启动用户主进程。
          * **收尸**：无限循环 `waitpid` 回收孤儿进程。
          * **信号转发**：捕获 `SIGTERM/INT` 并转发给主进程。

-----

### 3\. 启动工作流 (The Workflow)

1.  **用户执行**：`./elfloader -c Appfile`
2.  **Loader 启动**：
      * 读取 `Appfile`，配置好 Bind 映射表。
      * 打开 `Appfile` 得到 `fd=3`。
      * 从内存加载 `tiny-init`。
      * 构建栈，跳转入口，**保留 `fd=3`**。
3.  **Init 启动** (PID 1)：
      * 检测到配置 FD (e.g. `--config-fd 3`)。
      * 读取 `fd=3`，执行 `export ENV`, `chdir`, `system(RUN)`。
      * 关闭 `fd=3`。
      * `fork()` 并 `exec()` 用户定义的 `CMD` 程序。
4.  **用户程序运行** (PID 2)：
      * 在隔离且配置好的环境中运行。
      * 任何系统调用被 Payload 拦截并修正。