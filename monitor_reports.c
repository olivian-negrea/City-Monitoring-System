// monitor_reports.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

volatile sig_atomic_t keep_running = 1;

void handle_signal(int sig) {
    if (sig == SIGINT) {
        keep_running = 0;
    } else if (sig == SIGUSR1) {
        // write() is async-signal-safe, printf() is not!
        const char *msg = "Monitor: New report has been added to a district!\n";
        write(STDOUT_FILENO, msg, strlen(msg));
    }
}

int main() {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    int fd = open(".monitor_pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Failed to create .monitor_pid");
        return 1;
    }

    char pid_str[32];
    pid_t my_pid = getpid();
    snprintf(pid_str, sizeof(pid_str), "%d", my_pid);
    write(fd, pid_str, strlen(pid_str));
    close(fd);

    printf("Monitor started with PID: %d. Waiting for events...\n", my_pid);

    while (keep_running) {
        pause();
    }

    printf("\nMonitor received SIGINT. Shutting down and cleaning up...\n");
    unlink(".monitor_pid");

    return 0;
}