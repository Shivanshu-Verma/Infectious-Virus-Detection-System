// #include <stdio.h>
// #include "scan.h"
// #include "process.h"

// int main() {
//     printf("Starting file scan...\n");
//     scan_file("testfile.txt");  
//     printf("\nStarting process scan...\n");
//     check_processes();

//     return 0;
// }


///////////////////////////// task 2 //////////////////////////


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

// Function declarations for monitoring functions
void monitor_directory(const char *path);
void check_processes();

int main() {
    const char *path = "/home/abhishek/Desktop/OS/FolderForTask2"; 
    if (fork() == 0) {
        monitor_directory(path);
        exit(0);
    }

    while (1) {
        check_processes();
        sleep(30); // Check every 30 seconds
    }

    return 0;
}


