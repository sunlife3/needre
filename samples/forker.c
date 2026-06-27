/* forker.c — produces a 3-level process tree, then execs the /tmp payload.
 *
 *   level0 (forker)  --fork-->  level1  --fork-->  level2  --exec-->  /tmp/hello
 *
 * Each parent waits for its child, so the tree is fully alive at the moment
 * the execve fires. needre should report the ancestry chain:
 *
 *   pid=L2(/tmp/hello) <- pid=L1(forker) <- pid=L0(forker)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    printf("[forker] level0 pid=%d\n", getpid());

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

    /* level2 — exec the payload in /tmp */
    printf("[forker] level2 pid=%d ppid=%d -> exec /tmp/hello\n",
           getpid(), getppid());
    execl("/tmp/hello", "hello", (char *)NULL);

    perror("execl /tmp/hello");
    return 1;
}
