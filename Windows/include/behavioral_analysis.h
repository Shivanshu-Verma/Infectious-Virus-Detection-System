#ifndef BEHAVIORAL_ANALYSIS_H
#define BEHAVIORAL_ANALYSIS_H

#include <stdbool.h>
#include <windows.h>

// Constants for folder and file monitoring
#define MAX_PATH_LENGTH 260

// Function prototypes
void start_behavior_analysis(const char *folder_path);
void monitor_folder(const char *folder_path);
void monitor_registry_changes();
void monitor_system_calls();
void log_event(const char *message);

#endif
