#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scan.h"

// Function to compute the MD5 hash of a file
void hash_file(char *filename, unsigned char *outputBuffer) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    FILE *file = fopen(filename, "rb");
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (file == NULL) {
        printf("Cannot open file: %s\n", filename);
        return;
    }

    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, 1024, file)) != 0) {
        MD5_Update(&mdContext, data, bytes);
    }
    MD5_Final(hash, &mdContext);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&outputBuffer[i * 2], "%02x", hash[i]);
    }
    fclose(file);
}

// Function to compare a hash with known virus signatures in "signatures.txt"
int is_virus(char *hash) {
    FILE *file = fopen("signatures.txt", "r");
    char line[MD5_DIGEST_LENGTH * 2 + 1];

    if (file == NULL) {
        printf("Cannot open signatures file\n");
        return 0;
    }

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;  // Remove newline character
        if (strcmp(line, hash) == 0) {
            fclose(file);
            return 1; // Virus found
        }
    }
    fclose(file);
    return 0; // No virus found
}

// Function to scan a file and check if it matches a virus signature
void scan_file(char *filename) {
    unsigned char hash[MD5_DIGEST_LENGTH * 2 + 1];
    hash_file(filename, hash);
    printf("File: %s\nHash: %s\n", filename, hash);

    if (is_virus(hash)) {
        printf("Virus detected in file: %s\n", filename);
    } else {
        printf("File is clean: %s\n", filename);
    }
}
