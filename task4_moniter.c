#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <sys/types.h>
#include <signal.h>
#include "alerts.h"
#include <ctype.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

// Function to monitor files and detect changes
void monitor_files(const char *path) {
    int length, i = 0;
    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init failed");
        return;
    }

    int wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_MODIFY);
    if (wd == -1) {
        perror("inotify_add_watch failed");
        close(fd);
        return;
    }

    char buffer[EVENT_BUF_LEN];
    while (1) {
        length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read failed");
            break;
        }

        i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            char details[256];

            if (event->len) {
                if (event->mask & IN_CREATE) {
                    snprintf(details, sizeof(details), "File created: %s", event->name);
                    display_alert("File Creation", details);
                    log_suspicious_activity("File Creation", details);
                }
                if (event->mask & IN_DELETE) {
                    snprintf(details, sizeof(details), "File deleted: %s", event->name);
                    display_alert("File Deletion", details);
                    log_suspicious_activity("File Deletion", details);
                }
                if (event->mask & IN_MODIFY) {
                    snprintf(details, sizeof(details), "File modified: %s", event->name);
                    display_alert("File Modification", details);
                    log_suspicious_activity("File Modification", details);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

// Function to simulate suspicious process detection
int is_suspicious_process(const char *command) {
    // Add any suspicious commands here
    return (strstr(command, "sleep") != NULL);
}


int is_numeric(const char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) return 0;
    }
    return 1;
}

void monitor_processes() {
    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("opendir failed");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        // Check if the directory name is numeric (indicating a PID directory)
        if (is_numeric(entry->d_name)) {
            int pid = atoi(entry->d_name);
            char cmdline_path[256];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

            FILE *cmdline_file = fopen(cmdline_path, "r");
            if (cmdline_file) {
                char command[256];
                if (fgets(command, sizeof(command), cmdline_file)) {
                    if (is_suspicious_process(command)) {
                        char details[512];
                        snprintf(details, sizeof(details), "PID: %d, Command: %.200s", pid, command);
                        display_alert("Suspicious Process", details);
                        log_suspicious_activity("Suspicious Process", details);
                    }
                }
                fclose(cmdline_file);
            }
        }
    }

    closedir(proc_dir);
}

int main() {
    const char *path = "/home/abhishek/Desktop/OS/FolderForTask2";

    if (fork() == 0) {
        monitor_files(path);
    } else {
        monitor_processes();
    }

    return 0;
}
