#include <stdio.h>
#include "config.h"

int main() {
    printf("Configuration test:\n");
    printf("NUM_SMART_METERS = %d\n", NUM_SMART_METERS);
    printf("COMMITTEE_SIZE = %d\n", COMMITTEE_SIZE);
    printf("THRESHOLD = %d\n", THRESHOLD);
    printf("OEB Rates: Off=%.1f, Mid=%.1f, On=%.1f\n", 
           OFF_PEAK_RATE, MID_PEAK_RATE, ON_PEAK_RATE);
    return 0;
}
