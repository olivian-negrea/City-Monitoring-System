// city_manager.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define MAX_STR 50
#define MAX_DESC 255

// The fixed-size record for reports.dat
typedef struct {
    int id;
    char inspector[MAX_STR];
    float lat;
    float lon;
    char category[MAX_STR];
    int severity; // 1 = minor, 2 = moderate, 3 = critical
    time_t timestamp;
    char description[MAX_DESC];
} Report;

// Global variables to hold session state
char current_role[MAX_STR] = "";
char current_user[MAX_STR] = "";
// Converts stat st_mode to a 9-character string (e.g., "rw-rw-r--")
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

// Checks if the current role has the requested access (R_OK or W_OK)
int check_permission(const char *filepath, int requested_access) {
    struct stat file_stat;
    if (stat(filepath, &file_stat) < 0) {
        // If file doesn't exist yet, we allow creation to proceed elsewhere
        return 1;
    }

    int can_access = 0;
    if (strcmp(current_role, "manager") == 0) {
        // Manager checks Owner bits
        if (requested_access == R_OK && (file_stat.st_mode & S_IRUSR)) can_access = 1;
        if (requested_access == W_OK && (file_stat.st_mode & S_IWUSR)) can_access = 1;
    } else if (strcmp(current_role, "inspector") == 0) {
        // Inspector checks Group bits
        if (requested_access == R_OK && (file_stat.st_mode & S_IRGRP)) can_access = 1;
        if (requested_access == W_OK && (file_stat.st_mode & S_IWGRP)) can_access = 1;
    }

    if (!can_access) {
        fprintf(stderr, "Access Denied: Role '%s' does not have permission for this operation on %s.\n", current_role, filepath);
        exit(1);
    }
    return 1;
}
void log_action(const char *district, const char *action) {
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s/logged_district", district);

    // Check if we are allowed to write to the log (Only manager!)
    check_permission(log_path, W_OK);

    // Open in append mode
    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        perror("Failed to open log file");
        return;
    }

    char log_entry[512];
    time_t now = time(NULL);

    // Matches the screenshot exactly: Timestamp \t User \t Role \t Action
    snprintf(log_entry, sizeof(log_entry), "%ld\t%s\t%s\t%s\n",
             now, current_user, current_role, action);

    write(fd, log_entry, strlen(log_entry));
    close(fd);
}

void init_district(const char *district) {
    struct stat st;
    if (stat(district, &st) == -1) {
        // Create directory with 750 (rwxr-x---)
        mkdir(district, 0750);

        // Create reports.dat with 664 (rw-rw-r--)
        char file_path[256];
        snprintf(file_path, sizeof(file_path), "%s/reports.dat", district);
        int fd = open(file_path, O_CREAT | O_RDWR, 0664);
        if (fd >= 0) close(fd);

        // Create district.cfg with 640 (rw-r-----)
        snprintf(file_path, sizeof(file_path), "%s/district.cfg", district);
        fd = open(file_path, O_CREAT | O_RDWR, 0640);
        if (fd >= 0) {
            write(fd, "threshold=2\n", 12); // Default threshold
            close(fd);
        }

        // Create logged_district with 644 (rw-r--r--)
        snprintf(file_path, sizeof(file_path), "%s/logged_district", district);
        fd = open(file_path, O_CREAT | O_RDWR, 0644);
        if (fd >= 0) close(fd);
    }

    // Handle symlink creation
    char symlink_name[256];
    char target_path[256];
    snprintf(symlink_name, sizeof(symlink_name), "active_reports-%s", district);
    snprintf(target_path, sizeof(target_path), "%s/reports.dat", district);

    struct stat lst;
    if (lstat(symlink_name, &lst) == -1) {
        symlink(target_path, symlink_name);
    } else {
        // Check for dangling link
        if (stat(symlink_name, &st) == -1) {
            printf("Warning: Symlink %s is dangling (target missing).\n", symlink_name);
        }
    }
}
// AI-GENERATED FUNCTION 1: Parses field:operator:value
int parse_condition(const char *input, char *field, char *op, char *value) {
    char temp[256];
    strncpy(temp, input, sizeof(temp));

    char *token = strtok(temp, ":");
    if (!token) return 0;
    strcpy(field, token);

    token = strtok(NULL, ":");
    if (!token) return 0;
    strcpy(op, token);

    token = strtok(NULL, ":");
    if (!token) return 0;
    strcpy(value, token);

    return 1;
}

// AI-GENERATED FUNCTION 2: Matches a condition against a record
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
    }
    // (You can add inspector and timestamp logic similarly here)
    return 0;
}
void cmd_add(const char *district) {
    char path[256];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    // Check write permissions before prompting user
    check_permission(path, W_OK);

    Report r;
    // Generate an ID (using timestamp for uniqueness in this lab)
    r.id = (int)time(NULL);
    strncpy(r.inspector, current_user, MAX_STR);
    r.timestamp = time(NULL);

    // Interactive prompts matching the assignment screenshot exactly
    printf("X: ");
    if (scanf("%f", &r.lat) != 1) return;

    printf("Y: ");
    if (scanf("%f", &r.lon) != 1) return;

    printf("Category (road/lighting/flooding/other): ");
    if (scanf("%49s", r.category) != 1) return;

    printf("Severity level (1/2/3): ");
    if (scanf("%d", &r.severity) != 1) return;

    // Clear the input buffer before reading the description string
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    printf("Description:"); // Image shows no space after colon here
    if (fgets(r.description, MAX_DESC, stdin) != NULL) {
        // Strip the trailing newline character added by fgets
        r.description[strcspn(r.description, "\n")] = 0;
    }

    // Open file to append the new binary record
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0664);
    if (fd >= 0) {
        write(fd, &r, sizeof(Report));
        close(fd);
        // Log "add" exactly as shown in the screenshot
        log_action(district, "add");
    } else {
        perror("Error opening reports.dat for writing");
    }
}
void cmd_list(const char *district) {
    char path[256];
    snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, R_OK);

    struct stat st;
    stat(path, &st);
    char perms[10];
    mode_to_string(st.st_mode, perms);

    printf("File: %s | Perms: %s | Size: %ld bytes | Last Mod: %s",
           path, perms, st.st_size, ctime(&st.st_mtime));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    Report r;
    printf("--- Reports ---\n");
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        printf("ID: %d | Inspector: %s | Category: %s | Severity: %d\n",
               r.id, r.inspector, r.category, r.severity);
    }
    close(fd);
}

void cmd_remove(const char *district, int target_id) {
    char path[256];
    snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, W_OK);

    int fd = open(path, O_RDWR);
    if (fd < 0) return;

    Report r;
    off_t read_offset = 0;
    off_t write_offset = 0;
    int found = 0;

    // We read each record. If it's NOT the target, we write it back at the write_offset.
    // If it IS the target, we just skip writing it, which shifts the rest up.
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        if (r.id == target_id) {
            found = 1;
        } else {
            if (found) { // Only need to move things if we've already found and skipped the target
                lseek(fd, write_offset, SEEK_SET);
                write(fd, &r, sizeof(Report));
                read_offset += sizeof(Report);
                lseek(fd, read_offset, SEEK_SET); // Jump back to where we were reading
            }
            write_offset += sizeof(Report);
        }
        if (!found) read_offset += sizeof(Report);
    }

    if (found) {
        ftruncate(fd, write_offset); // Truncate the file to remove the leftover duplicate at the end
        printf("Report %d removed.\n", target_id);
        log_action(district, "remove_report");
    } else {
        printf("Report %d not found.\n", target_id);
    }
    close(fd);
}

void cmd_filter(const char *district, const char *condition) {
    char path[256];
    snprintf(path, sizeof(path), "%s/reports.dat", district);
    check_permission(path, R_OK);

    char field[50], op[5], value[50];
    if (!parse_condition(condition, field, op, value)) {
        printf("Invalid filter format.\n");
        return;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    Report r;
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        if (match_condition(&r, field, op, value)) {
            printf("Matched ID: %d | Cat: %s | Sev: %d\n", r.id, r.category, r.severity);
        }
    }
    close(fd);
}
int main(int argc, char *argv[]) {
    if (argc < 6) {
        printf("Usage: %s --role <role> --user <user> --<command> <district> [args]\n", argv[0]);
        return 1;
    }

    char command[50] = "";
    char district[50] = "";
    char extra_arg[100] = "";

    // Argument parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0) { strcpy(current_role, argv[++i]); }
        else if (strcmp(argv[i], "--user") == 0) { strcpy(current_user, argv[++i]); }
        else if (strncmp(argv[i], "--", 2) == 0) {
            strcpy(command, argv[i] + 2); // get command without '--'
            if (i + 1 < argc) strcpy(district, argv[++i]);
            if (i + 1 < argc) strcpy(extra_arg, argv[++i]);
        }
    }

    init_district(district);

    if (strcmp(command, "add") == 0) { cmd_add(district); }
    else if (strcmp(command, "list") == 0) { cmd_list(district); }
    else if (strcmp(command, "remove_report") == 0) { cmd_remove(district, atoi(extra_arg)); }
    else if (strcmp(command, "filter") == 0) { cmd_filter(district, extra_arg); }
    else { printf("Unknown command: %s\n", command); }

    return 0;
}
