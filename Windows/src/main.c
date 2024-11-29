#include <stdio.h>
#include <string.h>
#include <dirent.h>   // For directory traversal
#include <sys/stat.h> // For checking if the path is a file or directory
#include "../include/virus_signature.h"
#include "../include/behavioral_analysis.h"
#include "virus_signature.c"
#include "alert_box.c"
#include "../include/alert_box.h"
#include "behavioral_analysis.c"
#include "email.c"

// function to process each file
void process_file(const char *file_path, VirusSignatureDB *db)
{
    if (check_file_signature(file_path, db))
    {
        printf("Virus detected in %s!\n", file_path);

        // Extract folder path from the file path
        char folder_path[MAX_PATH_LENGTH];
        strncpy(folder_path, file_path, MAX_PATH_LENGTH);
        char *last_slash = strrchr(folder_path, '\\');
        if (last_slash)
            *last_slash = '\0'; // Trim to folder path

        // Extract the virus name from the file path
        char virus_name[MAX_PATH_LENGTH];
        strncpy(virus_name, file_path, MAX_PATH_LENGTH);
        char *last_slash_virus = strrchr(virus_name, '\\');
        if (last_slash_virus)
        {
            memmove(virus_name, last_slash_virus + 1, strlen(last_slash_virus));
        }
        printf("Virus name: %s\n", virus_name);

        // Generate alert box
        char hash[HASH_SIZE];
        compute_md5(file_path, hash);
        char alert_message[256];
        snprintf(alert_message, sizeof(alert_message), "Virus detected: %s\nFolder: %s\nHash: %s\n", virus_name, folder_path, hash);
        show_alert(alert_message);

        // Send email notification
        send_email_notification(virus_name, folder_path, hash);

        // Start behavioral analysis with the virus name
        start_behavior_analysis(folder_path, virus_name);
    }
    else
    {
        printf("No threats detected in %s.\n", file_path);
    }
}

// Helper function to scan a directory
void scan_directory(const char *folder_path, VirusSignatureDB *db)
{
    DIR *dir = opendir(folder_path);
    if (!dir)
    {
        fprintf(stderr, "Error: Unable to open directory %s\n", folder_path);
        return;
    }

    struct dirent *entry;
    char full_path[MAX_PATH_LENGTH];
    while ((entry = readdir(dir)) != NULL)
    {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", folder_path, entry->d_name);

        struct stat path_stat;
        if (stat(full_path, &path_stat) == 0)
        {
            if (S_ISDIR(path_stat.st_mode))
            {
                // Recursively scan subdirectories
                scan_directory(full_path, db);
            }
            else if (S_ISREG(path_stat.st_mode))
            {
                // Process individual files
                process_file(full_path, db);
            }
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <virus_signatures.csv> <folder_to_scan>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *csv_file = argv[1];
    const char *folder_to_scan = argv[2];

    // Load virus signatures
    VirusSignatureDB db;
    load_virus_signatures(&db, csv_file);

    // Scan the directory
    scan_directory(folder_to_scan, &db);

    return EXIT_SUCCESS;
}
