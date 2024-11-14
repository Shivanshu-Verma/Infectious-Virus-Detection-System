////////////////////////////// task1      ///////////////////////////////

// #include <dirent.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/stat.h>

// void check_processes()
// {
//     DIR *d = opendir("/proc");
//     struct dirent *dir;
//     struct stat st;

//     if (d == NULL)
//     {
//         perror("opendir");
//         return;
//     }

//     while ((dir = readdir(d)) != NULL)
//     {
//         // Construct the full path for stat
//         char path[1024];
//         snprintf(path, sizeof(path), "/proc/%s", dir->d_name);

//         // Use stat to check if it's a directory
//         if (stat(path, &st) == 0 && S_ISDIR(st.st_mode) && atoi(dir->d_name) > 0)
//         {
//             // Construct path to cmdline file
//             snprintf(path, sizeof(path), "/proc/%s/cmdline", dir->d_name);
//             FILE *cmdline = fopen(path, "r");

//             if (cmdline)
//             {
//                 char command[256];
//                 fgets(command, sizeof(command), cmdline);
//                 printf("PID: %s, Command: %s\n", dir->d_name, command); // Print raw command

//                 // Check for a specific suspicious command pattern
//                 if (strstr(command, "sleep") != NULL)
//                 {
//                     printf("Suspicious process detected: PID %s, Command: %s\n", dir->d_name, command);
//                 }
//                 fclose(cmdline);
//             }
//         }
//     }
//     closedir(d);
// }

///////////////////////////// task 2 //////////////////////////


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

void check_processes() {
    DIR *d = opendir("/proc");
    struct dirent *dir;
    struct stat st;

    if (d == NULL) {
        perror("opendir");
        return;
    }

    while ((dir = readdir(d)) != NULL) {
        char path[1024];
        snprintf(path, sizeof(path), "/proc/%s", dir->d_name);

        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode) && atoi(dir->d_name) > 0) {
            snprintf(path, sizeof(path), "/proc/%s/cmdline", dir->d_name);
            FILE *cmdline = fopen(path, "r");

            if (cmdline) {
                char command[256];
                fgets(command, sizeof(command), cmdline);
                printf("PID: %s, Command: %s\n", dir->d_name, command);
                fclose(cmdline);

                // Check for a suspicious command
                if (strstr(command, "sleep") != NULL) {
                    printf("Suspicious process detected: PID %s, Command: %s\n", dir->d_name, command);
                }
            }
        }
    }
    closedir(d);
}
