#include <stdio.h>

#include "hashrate_total.h"

static int check_total(const char *name, const double *rates, size_t count,
		double expected)
{
	double actual = sum_hashrate_slots(rates, count);

	if (actual != expected) {
		fprintf(stderr, "%s: expected %.0f, got %.0f\n",
			name, expected, actual);
		return 1;
	}
	return 0;
}

static int check_value(const char *name, double actual, double expected)
{
	if (actual != expected) {
		fprintf(stderr, "%s: expected %.0f, got %.0f\n",
			name, expected, actual);
		return 1;
	}
	return 0;
}

int main(void)
{
	/* Synthetic FPGA-only fixture: 16 workers, service slots 16..19,
	 * ZTEX worker rates 20..35, spare slot 36. */
	double fleet64[37] = { 0.0 };
	/* Exact mixed layout for C=2, F=2: miner_count=4, service slots 4..7,
	 * board workers 8..9, spare slot 10. */
	double mixed[11] = { 0.0 };
	double raw, smooth;
	size_t i;
	int failures = 0;

	failures += check_value("fpga-only-slot-count",
		(double)hashrate_slot_count(16, 16), 37.0);
	failures += check_value("fpga-only-device-start",
		(double)hashrate_device_start(16), 20.0);
	failures += check_value("fpga-only-monitor-index",
		(double)hashrate_monitor_index(16, 16), 36.0);
	for (i = hashrate_device_start(16); i < 36; i++)
		fleet64[i] = 64000000.0;
	failures += check_total("fpga-only-16-board-layout", fleet64,
		hashrate_slot_count(16, 16), 1024000000.0);

	failures += check_value("mixed-slot-count",
		(double)hashrate_slot_count(4, 2), 11.0);
	failures += check_value("mixed-device-start",
		(double)hashrate_device_start(4), 8.0);
	failures += check_value("mixed-monitor-index",
		(double)hashrate_monitor_index(4, 2), 10.0);
	mixed[0] = 2500000.0;
	mixed[1] = 3500000.0;
	mixed[8] = 64000000.0;
	mixed[9] = 64000000.0;
	failures += check_total("mixed-worker-layout", mixed,
		hashrate_slot_count(4, 2), 134000000.0);

	/* A stopped board worker must lose its contribution immediately. */
	clear_hashrate_slot(mixed, 11, 8);
	failures += check_total("stopped-worker", mixed, 11, 70000000.0);
	clear_hashrate_slot(mixed, 11, 99);
	failures += check_total("out-of-range-clear", mixed, 11, 70000000.0);

	/* A disabled lane must not retain either raw or smoothed rate. */
	raw = 16000000.0;
	smooth = 16000000.0;
	failures += check_value("disabled-lane-total",
		active_lane_hashrate(0, &raw, &smooth), 0.0);
	failures += check_value("disabled-lane-raw", raw, 0.0);
	failures += check_value("disabled-lane-smooth", smooth, 0.0);
	raw = 16000000.0;
	smooth = 15990000.0;
	failures += check_value("enabled-lane-total",
		active_lane_hashrate(1, &raw, &smooth), 15990000.0);
	failures += check_value("enabled-lane-raw-preserved", raw, 16000000.0);
	failures += check_value("enabled-lane-smooth-preserved", smooth, 15990000.0);

	failures += check_total("zero-slots", mixed, 0, 0.0);
	failures += check_total("null-array", NULL, 99, 0.0);

	if (failures)
		return 1;
	puts("HASHRATE_TOTAL_TEST_PASS cases=18 fleet_mhs=1024.00");
	return 0;
}
