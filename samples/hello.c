/* hello.c — the "malicious" payload placed in a monitored directory.
 * needre flags any execve whose path starts with a configured directory. */
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc;
    printf("hello world (argv0=%s pid=%d ppid=%d)\n",
           argv[0], getpid(), getppid());
    return 0;
}
