#include <stdio.h>
#include "virus_signature.h"
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <virus_signatures.csv> <file_to_scan>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *csv_file = argv[1];
    const char *file_to_scan = argv[2];

    VirusSignatureDB db;
    load_virus_signatures(&db, csv_file);

    if (check_file_signature(file_to_scan, &db)) {
        printf("Threat detected in %s!\n", file_to_scan);
    } else {
        printf("No threats detected in %s.\n", file_to_scan);
    }

    return EXIT_SUCCESS;
}
