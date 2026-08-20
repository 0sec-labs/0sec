/* freestanding aarch64 benchmark: gated stack-buffer overflow (no libc). */
typedef unsigned long size_t;
typedef long ssize_t;

static long sys3(long n, long a, long b, long c) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static ssize_t sys_read(int fd, void *buf, size_t n)  { return sys3(63, fd, (long)buf, n); }
static ssize_t sys_write(int fd, const void *buf, size_t n) { return sys3(64, fd, (long)buf, n); }
static void sys_exit(int c) { sys3(93, c, 0, 0); }

static void my_memcpy(char *d, const char *s, size_t n) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }

__attribute__((noinline))
static void parse_record(const char *data, int len) {
    char buf[16];
    if (len >= 4 && data[0] == 'A' && data[1] == 'R' && data[2] == 'M' && data[3] == '!') {
        my_memcpy(buf, data + 4, (size_t)(len - 4));   /* tainted-size stack OOB */
        sys_write(1, buf, 1);
    }
}

void _start(void) {
    static char input[4096];
    ssize_t n = sys_read(0, input, sizeof(input));
    if (n < 0) n = 0;
    parse_record(input, (int)n);
    sys_exit(0);
}
