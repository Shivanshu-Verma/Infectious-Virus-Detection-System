#ifndef ALERTS_H
#define ALERTS_H

#include <stdio.h>
#include <time.h>

// Function to log suspicious activity to a file
void log_suspicious_activity(const char *activity_type, const char *details);

// Function to display alert in the console
void display_alert(const char *activity_type, const char *details);

#endif
