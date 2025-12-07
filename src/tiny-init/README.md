## 当前实现（已完成）
- 内嵌到 elfloader，通过 memfd 写入后直接 exec，无需容器内文件。
- 默认环境填充：缺省时设置 PATH/HOME/TERM/USER/LOGNAME，读取 `/etc/environment`。
- 信号转发：PID1 捕获 SIGTERM/SIGINT/SIGQUIT/SIGHUP，转发给主子进程。
- 僵尸回收：循环 waitpid(-1)，回收孤儿；主子进程退出后按退出码/信号退出 init。
- 进程启动：fork 子进程，子进程恢复默认信号后 `execvp(argv[1], &argv[1])`。
- 静态构建：默认尝试 `-static` 以减少依赖。
- 名义路径为相对 `tiny-init`，仅作 argv/AT_EXECFN 占位，不依赖容器内同名文件。

## 未实现（待补充）
- 环境文件扩展：加载 `/etc/profile`、`.env` 等更多登陆环境。
- 主机名/用户配置：支持设定 HOSTNAME/UID/GID/补充组/能力降级。
- 前台进程组管理：显式设置进程组/终端控制，完善 Ctrl+C 等 TTY 行为。
- 日志/输出控制：可选重定向、日志文件滚动、前后台切换。

## 设计目标（需求清单）
- 保持极简、稳定的 PID1 管家：始终回收僵尸、转发信号、退出与主进程绑定。
- 提供可选的环境装修：默认安全基线 + 配置/CLI 覆盖，允许空环境场景下的最小可用性。
- 可选降权/隔离开关：支持在进入用户命令前设置 uid/gid/组/能力。
- 不中断 loader/payload 的无依赖特性：仍以内嵌资源+静态链接交付，避免额外挂载。
