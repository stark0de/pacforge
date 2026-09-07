#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

typedef int (*callback_fn)(void *ctx, int argc, const char **argv);

struct vtable {
    callback_fn init;
    callback_fn process;
    callback_fn cleanup;
    void (*notify)(int code);
};

struct plugin {
    const char *name;
    struct vtable *ops;
    void *handle;
    int refcount;
};

static jmp_buf recovery_point;
static volatile sig_atomic_t got_signal = 0;

void signal_handler(int sig) {
    got_signal = 1;
    longjmp(recovery_point, sig);
}

int default_init(void *ctx, int argc, const char **argv) {
    printf("init: ctx=%p argc=%d\n", ctx, argc);
    return 0;
}

int default_process(void *ctx, int argc, const char **argv) {
    if (!ctx || argc < 0) return -1;
    char buf[256];
    for (int i = 0; i < argc && i < 10; i++) {
        snprintf(buf, sizeof(buf), "arg[%d]=%s", i, argv[i] ? argv[i] : "(null)");
        puts(buf);
    }
    return argc;
}

int default_cleanup(void *ctx, int argc, const char **argv) {
    free(ctx);
    return 0;
}

void default_notify(int code) {
    printf("notify: %d\n", code);
}

static struct vtable default_ops = {
    .init = default_init,
    .process = default_process,
    .cleanup = default_cleanup,
    .notify = default_notify,
};

int dispatch_callback(struct plugin *p, int op, void *ctx, int argc, const char **argv) {
    if (!p || !p->ops) return -1;
    switch (op) {
        case 0: return p->ops->init(ctx, argc, argv);
        case 1: return p->ops->process(ctx, argc, argv);
        case 2: return p->ops->cleanup(ctx, argc, argv);
        default: return -1;
    }
}

void indirect_notify(struct plugin *p, int code) {
    if (p && p->ops && p->ops->notify)
        p->ops->notify(code);
}

struct plugin *load_plugin(const char *path) {
    void *handle = dlopen(path, RTLD_LAZY);
    if (!handle) return NULL;

    struct vtable *ops = dlsym(handle, "plugin_ops");
    if (!ops) {
        dlclose(handle);
        return NULL;
    }

    struct plugin *p = calloc(1, sizeof(*p));
    p->name = path;
    p->ops = ops;
    p->handle = handle;
    p->refcount = 1;
    return p;
}

void *worker_thread(void *arg) {
    struct plugin *p = arg;
    const char *args[] = {"thread_work", NULL};
    dispatch_callback(p, 1, arg, 1, args);
    return NULL;
}

int run_forked(struct plugin *p) {
    pid_t pid = fork();
    if (pid == 0) {
        const char *args[] = {"child", NULL};
        dispatch_callback(p, 0, NULL, 1, args);
        _exit(0);
    }
    return pid;
}

int try_with_recovery(struct plugin *p) {
    signal(SIGSEGV, signal_handler);
    if (setjmp(recovery_point) == 0) {
        const char *args[] = {"risky_op", NULL};
        return dispatch_callback(p, 1, NULL, 1, args);
    }
    printf("recovered from signal\n");
    return -1;
}

void *alloc_exec_page(size_t sz) {
    void *page = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) return NULL;
    mprotect(page, sz, PROT_READ | PROT_EXEC);
    return page;
}

int deep_call_chain(int n, struct plugin *p) {
    if (n <= 0) {
        const char *args[] = {"leaf", NULL};
        return dispatch_callback(p, 1, NULL, 1, args);
    }
    return deep_call_chain(n - 1, p) + 1;
}

int security_check(const char *password, size_t len) {
    char expected[] = "secret123";
    if (len != strlen(expected)) return 0;
    return memcmp(password, expected, len) == 0;
}

int main(int argc, char *argv[]) {
    struct plugin p = {
        .name = "builtin",
        .ops = &default_ops,
        .handle = NULL,
        .refcount = 1,
    };

    if (argc > 1 && strcmp(argv[1], "--fork") == 0) {
        run_forked(&p);
    }

    if (argc > 1 && strcmp(argv[1], "--thread") == 0) {
        pthread_t t;
        pthread_create(&t, NULL, worker_thread, &p);
        pthread_join(t, NULL);
    }

    if (argc > 1 && strcmp(argv[1], "--recover") == 0) {
        try_with_recovery(&p);
    }

    if (argc > 1 && strcmp(argv[1], "--plugin") == 0 && argc > 2) {
        struct plugin *ext = load_plugin(argv[2]);
        if (ext) {
            const char *args[] = {"hello", NULL};
            dispatch_callback(ext, 0, NULL, 1, args);
            dispatch_callback(ext, 1, NULL, 1, args);
            dispatch_callback(ext, 2, NULL, 0, NULL);
        }
    }

    deep_call_chain(5, &p);
    indirect_notify(&p, 42);

    void *exec = alloc_exec_page(4096);
    if (exec) munmap(exec, 4096);

    return 0;
}
