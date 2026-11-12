/* Pure host checks for the VU9P VCCINT helpers: FTDI serial from the Vivado target serial and the
 * NextJTAG --set-voltage confirmation parser (outputs as printed by NextJTAG 2.8 on a BCU-1525). */
#define VU9P_VOLTAGE_TEST
#include <stdarg.h>
#include "platform/vu9p_voltage.c"

static int failures;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

void applog(int prio, const char *fmt, ...) { (void) prio; (void) fmt; }

static const char *ok_out =
	"[2026-11-12 14:01:27] Device 1.0: Extended Sensors: vr_ph0_vin = 12.0781, vr_ph1_vin = N/A, vr_ph0_vout = 0.8000, vr_ph1_vout = 0.7998, vr_ph0_iin = 0.0609\n"
	"[2026-11-12 14:01:30] Device 1.0: Changing voltage to 0.72V: SUCCESS\n"
	"[2026-11-12 14:01:31] Device 1.0: Extended Sensors: vr_ph0_vin = 12.0625, vr_ph1_vin = N/A, vr_ph0_vout = 0.7202, vr_ph1_vout = 0.7205, vr_ph0_iin = 0.0718\n";

int main(void)
{
	char s[48];
	double p0, p1;

	CHECK(!vu9p_vccint_ftdi_serial("214302895021A", s, sizeof(s)) && !strcmp(s, "214302895021"));
	CHECK(!vu9p_vccint_ftdi_serial("21430289403EA", s, sizeof(s)) && !strcmp(s, "21430289403E"));
	CHECK(!vu9p_vccint_ftdi_serial("21430289403E", s, sizeof(s)) && !strcmp(s, "21430289403E"));
	CHECK(vu9p_vccint_ftdi_serial("", s, sizeof(s)) == -1);

	CHECK(!vu9p_vccint_parse(ok_out, 0.720, &p0, &p1));
	CHECK(fabs(p0 - 0.7202) < 1e-6 && fabs(p1 - 0.7205) < 1e-6);
	/* readback before the change only (no line after SUCCESS) */
	CHECK(vu9p_vccint_parse("x: Extended Sensors: vr_ph0_vout = 0.8000, vr_ph1_vout = 0.8000\nx: Changing voltage to 0.72V: SUCCESS\n", 0.720, &p0, &p1));
	/* failed change */
	CHECK(vu9p_vccint_parse("x: Changing voltage to 0.72V: FAILED\nx: Extended Sensors: vr_ph0_vout = 0.7202, vr_ph1_vout = 0.7205\n", 0.720, &p0, &p1));
	/* phase out of tolerance */
	CHECK(vu9p_vccint_parse("x: Changing voltage to 0.72V: SUCCESS\nx: Extended Sensors: vr_ph0_vout = 0.7202, vr_ph1_vout = 0.7400\n", 0.720, &p0, &p1));
	/* single-phase regulator */
	CHECK(!vu9p_vccint_parse("x: Changing voltage to 0.75V: SUCCESS\nx: Extended Sensors: vr_ph0_vout = 0.7490, vr_ph1_vout = N/A\n", 0.750, &p0, &p1));
	CHECK(isnan(p1));
	CHECK(vu9p_vccint_parse("", 0.720, &p0, &p1));

	CHECK(vu9p_vccint_cable_busy("Device 1.0: Error: Init Failed (LibFTDI Open Error - 0x10)"));
	CHECK(!vu9p_vccint_cable_busy(ok_out));

	if (failures) return 1;
	puts("vu9p_voltage helpers: all checks passed");
	return 0;
}
