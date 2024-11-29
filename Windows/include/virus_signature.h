#ifndef VIRUS_SIGNATURE_H
#define VIRUS_SIGNATURE_H

#include <stdbool.h>
#include <windows.h> // For Windows-specific functions

#define HASH_SIZE 33            // MD5 hash size in hexadecimal representation + null terminator
#define MAX_SIGNATURES 10000    // Adjust as needed based on your data
#define MAX_FILENAME_LENGTH 100 // Maximum length for file names
#define MAX_LINE_LENGTH 133     // Maximum length for a line in the CSV file
#define num_threads 4           // Number of threads for parallel search

// Structure to hold a single virus signature entry
typedef struct
{
    char reported_file[MAX_FILENAME_LENGTH];
    char hash[HASH_SIZE];
} VirusSignature;

// Structure to hold the virus signature database
typedef struct
{
    VirusSignature signatures[MAX_SIGNATURES];
    long long int count;
} VirusSignatureDB;

// Function prototypes
void load_virus_signatures(VirusSignatureDB *db, const char *csv_file);
bool check_file_signature(const char *file_path, VirusSignatureDB *db);
void compute_md5(const char *file_path, char *output_buffer);

#endif
