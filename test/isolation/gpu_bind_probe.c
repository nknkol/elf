/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Which /dev/hvgr0 FDs does the HarmonyOS GPU driver accept (docs/ISOLATION.md,
 * "GPU 设备")? Runs natively; the driver's own openat calls are trapped with an
 * in-process seccomp filter and answered with FDMODE's FD:
 *   self    the driver opens the device itself (control)
 *   peer    another process opens it and passes it with SCM_RIGHTS (the broker)
 *   inherit opened by the parent before fork
 *   early1  opened by this process beforehand, one FD dup'd for every open
 *   earlyN  opened by this process beforehand, a fresh FD for every open
 *   exec    opened, then this program re-executes itself keeping the FD
 * Build on the device (Vulkan headers from the OpenHarmony SDK sysroot):
 *   clang -O1 -idirafter $SDK/native/sysroot/usr/include -o gpu_bind_probe \
 *     gpu_bind_probe.c -L/system/lib64 -lvulkan -Wl,--allow-shlib-undefined
 * 2026-10-31 on a Maleoon 916: self and earlyN succeed, every other mode fails
 * in vkCreateDevice. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <vulkan/vulkan_core.h>

static int given = -1, opens, seen, pool[8], npool, used;
#include <signal.h>
#include <ucontext.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
extern char gadget_svc[];
__asm__(".globl gadget_svc\n gadget: mov x8, x6\n gadget_svc: svc #0\n ret\n");
static long raw6(long a, long b, long c, long d, long e, long f, long nr)
{
	register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c,
		x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f, x6 __asm__("x6") = nr;
	__asm__ volatile("bl gadget" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6) : "x8", "x30", "memory");
	return x0;
}
static void on_sys(int sig, siginfo_t *si, void *uc_)
{
	ucontext_t *uc = uc_; unsigned long long *x = uc->uc_mcontext.regs;
	const char *p = (const char *)x[1];
	if (p && !strcmp(p, "/dev/hvgr0") && (given >= 0 || npool)) {
		opens++;
		int src = npool ? pool[used++ % npool] : given;
		x[0] = raw6(src, F_DUPFD_CLOEXEC, 3, 0, 0, 0, SYS_fcntl);
		return;
	}
	if (p && !strncmp(p, "/dev/", 5)) seen++;
	x[0] = raw6(x[0], x[1], x[2], x[3], 0, 0, SYS_openat);
}
static void trap_openat(void)
{
	unsigned long ip = (unsigned long)gadget_svc + 4;
	struct sigaction sa = {0}; sa.sa_sigaction = on_sys; sa.sa_flags = SA_SIGINFO | SA_NODEFER; sigaction(SIGSYS, &sa, 0);
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 8),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)ip, 0, 2),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 12),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)(ip >> 32), 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog pr = {sizeof f / sizeof f[0], f};
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &pr)) perror("seccomp");
}

static int recv_fd(int s)
{
	char c; struct iovec io = {&c, 1}; char cb[CMSG_SPACE(sizeof(int))];
	struct msghdr m = {0}; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
	if (recvmsg(s, &m, 0) != 1) return -1;
	int fd; memcpy(&fd, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof fd); return fd;
}
static void send_fd(int s, int fd)
{
	char c = 'f'; struct iovec io = {&c, 1}; char cb[CMSG_SPACE(sizeof(int))] = {0};
	struct msghdr m = {0}; m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
	struct cmsghdr *h = CMSG_FIRSTHDR(&m); h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(h), &fd, sizeof fd); sendmsg(s, &m, 0);
}

static int work(void)
{
	VkApplicationInfo app = {VK_STRUCTURE_TYPE_APPLICATION_INFO, 0, "b", 1, "b", 1, VK_API_VERSION_1_1};
	VkInstanceCreateInfo ii = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, 0, 0, &app};
	VkInstance inst; VkResult r = vkCreateInstance(&ii, 0, &inst);
	printf("  createInstance %d\n", r); if (r) return 1;
	uint32_t n = 1; VkPhysicalDevice pd; r = vkEnumeratePhysicalDevices(inst, &n, &pd);
	printf("  physical devices %u rc %d\n", n, r); if (r < 0 || !n) return 1;
	float prio = 1; VkDeviceQueueCreateInfo q = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, 0, 0, 0, 1, &prio};
	VkDeviceCreateInfo di = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, 0, 0, 1, &q};
	VkDevice dev; r = vkCreateDevice(pd, &di, 0, &dev);
	printf("  createDevice %d\n", r); if (r) return 1;
	VkPhysicalDeviceMemoryProperties mp; vkGetPhysicalDeviceMemoryProperties(pd, &mp);
	uint32_t t = 0; while (t < mp.memoryTypeCount && !(mp.memoryTypes[t].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)) t++;
	VkMemoryAllocateInfo ai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, 1 << 20, t};
	VkDeviceMemory mem; r = vkAllocateMemory(dev, &ai, 0, &mem);
	printf("  allocateMemory %d\n", r); if (r) return 1;
	void *p; r = vkMapMemory(dev, mem, 0, VK_WHOLE_SIZE, 0, &p);
	printf("  mapMemory %d\n", r); if (r) return 1;
	memset(p, 0x5a, 1 << 20); vkUnmapMemory(dev, mem); vkFreeMemory(dev, mem, 0);
	vkDestroyDevice(dev, 0); vkDestroyInstance(inst, 0);
	return 0;
}

int main(void)
{
	const char *mode = getenv("FDMODE") ? getenv("FDMODE") : "self";
	if (!strcmp(mode, "peer")) {
		int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
		if (!fork()) { int fd = syscall(SYS_openat, AT_FDCWD, "/dev/hvgr0", O_RDWR | O_CLOEXEC, 0); send_fd(sv[1], fd); sleep(20); _exit(0); }
		given = recv_fd(sv[0]);
	} else if (!strcmp(mode, "inherit")) {
		int fd = syscall(SYS_openat, AT_FDCWD, "/dev/hvgr0", O_RDWR, 0);
		if (fork()) { int st; wait(&st); return WEXITSTATUS(st); }
		given = fd;
	}
	if (!strcmp(mode, "early1"))
		given = open("/dev/hvgr0", O_RDWR | O_CLOEXEC);
	if (!strcmp(mode, "earlyN"))
		for (npool = 0; npool < 4; npool++) pool[npool] = open("/dev/hvgr0", O_RDWR | O_CLOEXEC);
	if (!strcmp(mode, "exec")) {
		int fd = open("/dev/hvgr0", O_RDWR);
		char b[16]; snprintf(b, sizeof b, "%d", fd); setenv("GIVEN", b, 1); setenv("FDMODE", "given", 1);
		execl("/proc/self/exe", "vkbind", (char *)0); perror("exec"); return 9;
	}
	if (!strcmp(mode, "given"))
		given = atoi(getenv("GIVEN"));
	trap_openat();
	printf("mode %s given fd %d\n", mode, given);
	int rc = work();
	printf("mode %s: %s (intercepted opens %d, other /dev %d)\n", mode, rc ? "FAIL" : "ok", opens, seen);
	fflush(stdout);
	_exit(rc);
}
