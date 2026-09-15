#ifndef __TUI_H__
#define __TUI_H__

#include <stdbool.h>

/* Enabled with --tui. When on, applog output is routed into the TUI log pane
 * (and, if set, an --log-file) instead of the terminal, and an ncurses
 * dashboard renders the pool header, per-FPGA device table and a live log. */
extern bool opt_tui;
extern char *opt_log_file;

struct fpga_info;   /* defined in miner.h */

/* Registry: fpga-miner registers each board's fpga_info so the render thread
 * can read per-FPGA stats. Called once per board at init. */
void tui_register_board(int board_idx, struct fpga_info *fpga);

/* Per-FPGA share attribution, called from the stratum response path. */
void tui_record_share(int board_idx, int fpga_idx, bool accepted);

/* Board serial/name for a registered board, or NULL. */
const char *tui_board_name(int board_idx);

/* Logging hook (called by applog). `msg` is the already-expanded message
 * text with no timestamp/color; prio is the LOG_* level for coloring.
 * Thread-safe; also mirrors the line to opt_log_file if configured. */
void tui_log(int prio, const char *msg);

/* Lifecycle. tui_init() sets up ncurses + opens the log file; tui_thread()
 * is the render/input loop; tui_shutdown() restores the terminal. */
void tui_init(void);
void *tui_thread(void *userdata);
void tui_shutdown(void);

#endif /* __TUI_H__ */
