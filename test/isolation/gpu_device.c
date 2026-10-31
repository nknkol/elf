/* SPDX-License-Identifier: GPL-2.0-or-later */
/* --isolate-device acceptance, positive side (docs/ISOLATION.md, "GPU 设备"):
 * the Vulkan driver opens /dev/hvgr0 itself and must create a device,
 * allocate, map and write memory, in each of
 *   init    the first guest process
 *   fork    a forked child
 *   exec    the program after executing itself (argv[0], absolute)
 *   thread  the main thread while a second thread opens the device too
 * Prints "RESULT <mode> ok|fail". Native HarmonyOS program (musl, the
 * system's libvulkan); build on the device:
 *   clang -O1 -idirafter $SDK/sysroot/usr/include -o gpu_device gpu_device.c \
 *     -L/system/lib64 -lvulkan -lpthread -Wl,--allow-shlib-undefined */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <vulkan/vulkan_core.h>

static int work(void)
{
    VkApplicationInfo app = {VK_STRUCTURE_TYPE_APPLICATION_INFO, 0, "d", 1, "d", 1, VK_API_VERSION_1_1};
    VkInstanceCreateInfo ii = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, 0, 0, &app};
    VkInstance inst;
    VkResult r = vkCreateInstance(&ii, 0, &inst);
    if (r) { printf("  createInstance %d\n", r); return 1; }
    uint32_t n = 1;
    VkPhysicalDevice pd;
    r = vkEnumeratePhysicalDevices(inst, &n, &pd);
    if (r < 0 || !n) { printf("  physical devices %u rc %d\n", n, r); return 1; }
    float prio = 1;
    VkDeviceQueueCreateInfo q = {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, 0, 0, 0, 1, &prio};
    VkDeviceCreateInfo di = {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, 0, 0, 1, &q};
    VkDevice dev;
    r = vkCreateDevice(pd, &di, 0, &dev);
    if (r) { printf("  createDevice %d\n", r); return 1; }
    VkPhysicalDeviceMemoryProperties mp;
    vkGetPhysicalDeviceMemoryProperties(pd, &mp);
    uint32_t t = 0;
    while (t < mp.memoryTypeCount && !(mp.memoryTypes[t].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT))
        t++;
    VkMemoryAllocateInfo ai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, 1 << 20, t};
    VkDeviceMemory mem;
    r = vkAllocateMemory(dev, &ai, 0, &mem);
    if (r) { printf("  allocateMemory %d\n", r); return 1; }
    void *p;
    r = vkMapMemory(dev, mem, 0, VK_WHOLE_SIZE, 0, &p);
    if (r) { printf("  mapMemory %d\n", r); return 1; }
    memset(p, 0x5a, 1 << 20);
    int ok = ((unsigned char *)p)[12345] == 0x5a;
    vkUnmapMemory(dev, mem);
    vkFreeMemory(dev, mem, 0);
    vkDestroyDevice(dev, 0);
    vkDestroyInstance(inst, 0);
    return !ok;
}

/* On this device the driver itself crashes in any thread but the main one
 * (natively too: a jump to a non-code address from ld-musl), so the thread
 * flow opens the device from a second thread while the main thread creates
 * a Vulkan device. */
struct opener { int stop, opened; };

static void *opener_main(void *arg)
{
    struct opener *o = arg;
    do {
        int fd = open("/dev/hvgr0", O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            o->opened++;
            close(fd);
        }
        usleep(1000);
    } while (!__atomic_load_n(&o->stop, __ATOMIC_RELAXED));
    return 0;
}

static int result(const char *mode, int rc)
{
    printf("RESULT %s %s\n", mode, rc ? "fail" : "ok");
    fflush(stdout);
    return rc;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "init";
    if (!strcmp(mode, "init"))
        return result(mode, work());
    if (!strcmp(mode, "fork")) {
        pid_t pid = fork();
        if (!pid)
            _exit(work());
        int status = 0;
        waitpid(pid, &status, 0);
        return result(mode, !WIFEXITED(status) || WEXITSTATUS(status));
    }
    if (!strcmp(mode, "exec")) {
        execl(argv[0], argv[0], "after-exec", (char *)0);
        perror("exec");
        return result(mode, 1);
    }
    if (!strcmp(mode, "after-exec"))
        return result("exec", work());
    if (!strcmp(mode, "thread")) {
        /* The device is created while a second thread opens it too. */
        pthread_t th;
        struct opener o = {0, 0};
        if (pthread_create(&th, 0, opener_main, &o))
            return result(mode, 1);
        int rc = work();
        __atomic_store_n(&o.stop, 1, __ATOMIC_RELAXED);
        pthread_join(th, 0);
        printf("  thread opened the device %d times\n", o.opened);
        return result(mode, rc || !o.opened);
    }
    return 2;
}
