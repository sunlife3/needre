/* forker.c — produces a 3-level process tree, then execs a payload.
 *
 *   level0 (forker)  --fork-->  level1  --fork-->  level2  --exec-->  payload
 *
 * The payload path is taken from argv[1] (default: /tmp/hello), so the same
 * binary can drive detections from any monitored directory.
 *
 * Each parent waits for its child, so the tree is fully alive at the moment
 * the execve fires. needre should report the ancestry chain:
 *
 *   pid=L2(payload) <- pid=L1(forker) <- pid=L0(forker)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    const char *payload = (argc > 1) ? argv[1] : "/tmp/hello";

    printf("[forker] level0 pid=%d payload=%s\n", getpid(), payload);

    pid_t p1 = fork();
    if (p1 < 0) { perror("fork1"); exit(1); }
    if (p1 > 0) {
        int st;
        waitpid(p1, &st, 0);
        return 0;
    }

    /* level1 */
    printf("[forker] level1 pid=%d ppid=%d\n", getpid(), getppid());

    pid_t p2 = fork();
    if (p2 < 0) { perror("fork2"); exit(1); }
    if (p2 > 0) {
        int st;
        waitpid(p2, &st, 0);
        return 0;
    }

    /* level2 — exec the payload */
    printf("[forker] level2 pid=%d ppid=%d -> exec %s\n",
           getpid(), getppid(), payload);
    execl(payload, "hello", (char *)NULL);

    perror("execl payload");
    return 1;
}
