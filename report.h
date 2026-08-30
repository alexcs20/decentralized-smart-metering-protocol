#ifndef REPORT_H
#define REPORT_H

#include <stdint.h>
#include <stdio.h>
#include "config.h"
#include "billing.h"

typedef struct {
    uint32_t round;
    uint32_t timestamp;
    uint64_t consumption_wh;
    double consumption_kwh;
    double cost;
    const char* time_period;
    double rate;
    uint8_t committee[COMMITTEE_SIZE];
    uint64_t cumulative_total;
    double cumulative_cost;
} RoundRecord;

typedef struct {
    uint32_t day;
    uint32_t start_round;
    uint32_t end_round;
    double off_peak_kwh;
    double mid_peak_kwh;
    double on_peak_kwh;
    double total_kwh;
    double subtotal;
    double hst;
    double total_with_hst;
    uint32_t num_rounds;
} DailyBillRecord;

void init_report_files(uint32_t simulation_id);
void save_round_data(RoundRecord *record);
void save_daily_bill(DailyBillRecord *bill);
void generate_summary_report(uint32_t total_rounds, uint32_t num_days);
void generate_csv_report(void);
void generate_professor_report(const char* student_name, const char* course);

#endif
