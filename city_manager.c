// city_manager.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#define MAX_STR 50
#define MAX_DESC 255

typedef struct {
    int id;
    char inspector[MAX_STR];
    float lat;
    float lon;
    char category[MAX_STR];
    int severity;
    time_t timestamp;
    char description[MAX_DESC];
} Report;

char current_role[MAX_STR] = "";
char current_user[MAX_STR] = "";

void mode_to_string(mode_t mode, char *str) {
    strcpy(str, "---------");
    if (mode & S_IRUSR) str[0] = 'r';
    if (mode & S_IWUSR) str[1] = 'w';
    if (mode & S_IXUSR) str[2] = 'x';
    if (mode & S_IRGRP) str[3] = 'r';
    if (mode & S_IWGRP) str[4] = 'w';
    if (mode & S_IXGRP) str[5] = 'x';
    if (mode & S_IROTH) str[6] = 'r';
    if (mode & S_IWOTH) str[7] = 'w';
    if (mode & S_IXOTH) str[8] = 'x';
}

int check_permission(const char *filepath, int requested_access) {
    struct stat file_stat;
    if (stat(filepath, &file_stat) < 0) return 1;

    int can_access = 0;
    if (strcmp(current_role, "manager") == 0) {
        if (requested_access == R_OK && (file_stat.st_mode & S_IRUSR)) can_access = 1;
        if (requested_access == W_OK && (file_stat.st_mode & S_IWUSR)) can_access = 1;
    } else if (strcmp(current_role, "inspector") == 0) {
        if (requested_access == R_OK && (file_stat.st_mode & S_IRGRP)) can_access = 1;
        if (requested_access == W_OK && (file_stat.st_mode & S_IWGRP)) can_access = 1;
    }

    if (!can_access) {
        fprintf(stderr, "Access Denied: Role '%s' does not have permission.\n", current_role);
        exit(1);
    }
    return 1;
}

void log_action(const char *district, const char *action) {
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s/logged_district", district);
    check_permission(log_path, W_OK);

    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;

    char log_entry[512];
    time_t now = time(NULL);
    snprintf(log_entry, sizeof(log_entry), "%ld\t%s\t%s\t%s\n",
             now, current_user, current_role, action);

    write(fd, log_entry, strlen(log_entry));
    close(fd);
}

void init_district(const char *district) {
    struct stat st;
    if (stat(district, &st) == -1) {
        mkdir(district, 0750);
        chmod(district, 0750); // Explicit chmod required by prompt

        char file_path[256];

        snprintf(file_path, sizeof(file_path), "%s/reports.dat", district);
        int fd = open(file_path, O_CREAT | O_RDWR, 0664);
        if (fd >= 0) { close(fd); chmod(file_path, 0664); }

        snprintf(file_path, sizeof(file_path), "%s/district.cfg", district);
        fd = open(file_path, O_CREAT | O_RDWR, 0640);
        if (fd >= 0) { write(fd, "threshold=2\n", 12); close(fd); chmod(file_path, 0640); }

        snprintf(file_path, sizeof(file_path), "%s/logged_district", district);
        fd = open(file_path, O_CREAT | O_RDWR, 0644);
        if (fd >= 0) { close(fd); chmod(file_path, 0644); }
    }

    char symlink_name[256], target_path[256];
    snprintf(symlink_name, sizeof(symlink_name), "active_reports-%s", district);
    snprintf(target_path, sizeof(target_path), "%s/reports.dat", district);

    struct stat lst;
    if (lstat(symlink_name, &lst) == -1) {
        symlink(target_path, symlink_name);
    } else {
        if (stat(symlink_name, &st) == -1) {
            printf("Warning: Symlink %s is dangling (target reports.dat is missing).\n", symlink_name);
        }
    }
}

int parse_condition(const char *input, char *field, char *op, char *value) {
    char temp[256];
    strncpy(temp, input, sizeof(temp));
    char *token = strtok(temp, ":");
    if (!token) return 0; strcpy(field, token);
    token = strtok(NULL, ":");
    if (!token) return 0; strcpy(op, token);
    token = strtok(NULL, ":");
    if (!token) return 0; strcpy(value, token);
    return 1;
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {
    if (strcmp(field, "severity") == 0) {
        int sev_val = atoi(value);
        if (strcmp(op, "==") == 0) return r->severity == sev_val;
        if (strcmp(op, "!=") == 0) return r->severity != sev_val;
        if (strcmp(op, "<") == 0) return r->severity < sev_val;
        if (strcmp(op, "<=") == 0) return r->severity <= sev_val;
        if (strcmp(op, ">") == 0) return r->severity > sev_val;
        if (strcmp(op, ">=") == 0) return r->severity >= sev_val;
    } else if (strcmp(field, "category") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->category, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->category, value) != 0;
    } else if (strcmp(field, "inspector") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->inspector, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->inspector, value) != 0;
    } else if (strcmp(field, "timestamp") == 0) {
        time_t ts_val = (time_t)atol(value);
        if (strcmp(op, "==") == 0) return r->timestamp == ts_val;
        if (strcmp(op, "<") == 0) return r->timestamp < ts_val;
        if (strcmp(op, "<=") == 0) return r->timestamp <= ts_val;
        if (strcmp(op, ">") == 0) return r->timestamp > ts_val;
        if (strcmp(op, ">=") == 0) return r->timestamp >= ts_val;
    }
    return 0;
}

void cmd_add(const char *district) {
    char path[256];
    snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, W_OK);

    Report r;
    r.id = (int)time(NULL);
    strncpy(r.inspector, current_user, MAX_STR);
    r.timestamp = time(NULL);

    printf("X: "); if (scanf("%f", &r.lat) != 1) return;
    printf("Y: "); if (scanf("%f", &r.lon) != 1) return;
    printf("Category (road/lighting/flooding/other): "); if (scanf("%49s", r.category) != 1) return;
    printf("Severity level (1/2/3): "); if (scanf("%d", &r.severity) != 1) return;

    int c; while ((c = getchar()) != '\n' && c != EOF);
    printf("Description:");
    if (fgets(r.description, MAX_DESC, stdin) != NULL) {
        r.description[strcspn(r.description, "\n")] = 0;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0664);
    if (fd >= 0) {
        chmod(path, 0664); // Explicitly ensure permissions are 664
        write(fd, &r, sizeof(Report));
        close(fd);

        int monitor_notified = 0;
        int pid_fd = open(".monitor_pid", O_RDONLY);
        if (pid_fd >= 0) {
            char pid_str[32] = {0};
            int bytes = read(pid_fd, pid_str, sizeof(pid_str) - 1);
            close(pid_fd);
            if (bytes > 0) {
                pid_t monitor_pid = atoi(pid_str);
                if (kill(monitor_pid, SIGUSR1) == 0) monitor_notified = 1;
            }
        }

        if (monitor_notified) log_action(district, "add (monitor notified successfully)");
        else log_action(district, "add (monitor could NOT be notified)");

    } else perror("Error opening reports.dat");
}

void cmd_list(const char *district) {
    char path[256];
    snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, R_OK);

    struct stat st; stat(path, &st);
    char perms[10]; mode_to_string(st.st_mode, perms);
    printf("File: %s | Perms: %s | Size: %ld bytes | Last Mod: %s",
           path, perms, st.st_size, ctime(&st.st_mtime));
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    Report r;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        printf("ID: %d | Inspector: %s | Cat: %s | Sev: %d | Desc: %s\n",
               r.id, r.inspector, r.category, r.severity, r.description);
    }
    close(fd);
}
void cmd_view(const char *district, int target_id) {
    char path[256];
    snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, R_OK); // Both roles can view

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Could not open reports.dat");
        return;
    }

    Report r;
    int found = 0;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        if (r.id == target_id) {
            printf("--- Report Details ---\n");
            printf("ID: %d\nInspector: %s\nGPS: %.4f, %.4f\nCategory: %s\nSeverity: %d\nTimestamp: %ld\nDescription: %s\n",
                   r.id, r.inspector, r.lat, r.lon, r.category, r.severity, r.timestamp, r.description);
            found = 1;
            break; // Stop reading once we find it
        }
    }

    if (!found) {
        printf("Report %d not found in district %s.\n", target_id, district);
    }
    close(fd);
}
void cmd_remove(const char *district, int target_id) {
    if (strcmp(current_role, "manager") != 0) {
        fprintf(stderr, "Access Denied: Only managers can remove reports.\n");
        return;
    }

    char path[256]; snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, W_OK);

    struct stat st_before;
    stat(path, &st_before);
    printf("File size before removal: %ld bytes\n", st_before.st_size);

    int fd = open(path, O_RDWR);
    if (fd < 0) return;

    Report r; off_t read_offset = 0, write_offset = 0; int found = 0;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        if (r.id == target_id) { found = 1; }
        else {
            if (found) {
                lseek(fd, write_offset, SEEK_SET);
                write(fd, &r, sizeof(Report));
                read_offset += sizeof(Report);
                lseek(fd, read_offset, SEEK_SET);
            }
            write_offset += sizeof(Report);
        }
        if (!found) read_offset += sizeof(Report);
    }

    if (found) {
        ftruncate(fd, write_offset);
        log_action(district, "remove_report");

        struct stat st_after;
        stat(path, &st_after);
        printf("Report %d removed. File size after removal: %ld bytes\n", target_id, st_after.st_size);
    } else {
        printf("Report %d not found.\n", target_id);
    }
    close(fd);
}
void cmd_update_threshold(const char *district, int new_value) {
    char path[256];
    snprintf(path, sizeof(path), "%s/district.cfg", district);

    if (strcmp(current_role, "manager") != 0) {
        fprintf(stderr, "Access Denied: Only managers can update threshold.\n");
        return;
    }

    struct stat st;
    if (stat(path, &st) == 0) {
        // Isolate the lower 9 bits to check if it exactly matches 0640
        if ((st.st_mode & 0777) != 0640) {
            fprintf(stderr, "Error: district.cfg permissions altered. Expected 640.\n");
            return;
        }
    }

    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        char buf[50];
        snprintf(buf, sizeof(buf), "threshold=%d\n", new_value);
        write(fd, buf, strlen(buf));
        close(fd);
        printf("Threshold updated successfully.\n");
        log_action(district, "update_threshold");
    } else {
        perror("Failed to open district.cfg");
    }
}
void cmd_filter(const char *district, int condition_count, char *conditions[]) {
    char path[256]; snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, R_OK);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    Report r;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        int all_match = 1;

        // Test the record against EVERY condition passed in
        for (int i = 0; i < condition_count; i++) {
            char field[50], op[5], value[50];
            if (parse_condition(conditions[i], field, op, value)) {
                if (!match_condition(&r, field, op, value)) {
                    all_match = 0;
                    break; // Fails one AND condition, stop checking others
                }
            }
        }

        if (all_match) {
            printf("Matched ID: %d | Cat: %s | Sev: %d\n", r.id, r.category, r.severity);
        }
    }
    close(fd);
}

void cmd_remove_district(const char *district) {
    if (strcmp(current_role, "manager") != 0) {
        fprintf(stderr, "Access Denied: Only managers can remove entire districts.\n");
        return;
    }
    if (strlen(district) == 0 || strchr(district, '/') != NULL || strcmp(district, ".") == 0 || strcmp(district, "..") == 0) {
        fprintf(stderr, "Error: Invalid district name.\n"); return;
    }

    char symlink_name[256];
    snprintf(symlink_name, sizeof(symlink_name), "active_reports-%s", district);
    unlink(symlink_name);

    pid_t pid = fork();
    if (pid < 0) perror("Fork failed");
    else if (pid == 0) {
        execlp("rm", "rm", "-rf", district, NULL);
        perror("Exec failed"); exit(1);
    } else {
        wait(NULL);
        printf("District '%s' and its symlink have been successfully removed.\n", district);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 6) return 1;
    char command[50] = "", district[50] = "", extra_arg[100] = "";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0) strcpy(current_role, argv[++i]);
        else if (strcmp(argv[i], "--user") == 0) strcpy(current_user, argv[++i]);
        else if (strncmp(argv[i], "--", 2) == 0) {
            strcpy(command, argv[i] + 2);
            if (i + 1 < argc) strcpy(district, argv[++i]);
            if (i + 1 < argc) strcpy(extra_arg, argv[++i]);
        }
    }

    if (strcmp(command, "remove_district") == 0) {
        cmd_remove_district(district);
        return 0;
    }

    init_district(district);

    if (strcmp(command, "add") == 0) cmd_add(district);
    else if (strcmp(command, "list") == 0) cmd_list(district);
    else if (strcmp(command, "view") == 0) cmd_view(district, atoi(extra_arg)); // NEW
    else if (strcmp(command, "remove_report") == 0) cmd_remove(district, atoi(extra_arg));
    else if (strcmp(command, "update_threshold") == 0) cmd_update_threshold(district, atoi(extra_arg)); // NEW
    else if (strcmp(command, "filter") == 0) {
        int condition_start_idx = 0;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], district) == 0) {
                condition_start_idx = i + 1;
                break;
            }
        }
        int num_conditions = argc - condition_start_idx;
        cmd_filter(district, num_conditions, &argv[condition_start_idx]);
    }
    else printf("Unknown command: %s\n", command);

    return 0;
}