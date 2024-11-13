#include <stdio.h>
#include "scan.h"
#include "process.h"

int main() {
    printf("Starting file scan...\n");
    scan_file("testfile.txt");  
    printf("\nStarting process scan...\n");
    check_processes();

    return 0;
}
