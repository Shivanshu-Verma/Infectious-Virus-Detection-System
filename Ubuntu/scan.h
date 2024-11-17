#ifndef SCAN_H
#define SCAN_H

void hash_file(char *filename, unsigned char *outputBuffer);
int is_virus(char *hash);
void scan_file(char *filename);

#endif
