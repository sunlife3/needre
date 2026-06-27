/* hello.c — the "malicious" payload that runs from /tmp.
 * needre flags any execve whose path starts with /tmp. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("hello world from /tmp (pid=%d ppid=%d)\n", getpid(), getppid());
    return 0;
}
