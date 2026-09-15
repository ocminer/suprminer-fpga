// top_sha3.v - BC3 SHA3-256t Miner for ZTEX USB-FPGA 1.15y (XC6SLX150)
// N iterative Keccak cores, 76 cycles/nonce each
// 96 MHz via DCM_SP (fixed, no auto-freq — see feedback_dcm_clkgen)

module top (
    input             fxclk_in,
    input  [7:0]      read,
    output [7:0]      write,
    input             rd_clk,
    input             wr_clk,
    input             wr_start,
    input             select,
    input             reset,
    input             clk_reset,
    input             pll_stop,
    input             dcm_progclk,
    input             dcm_progdata,
    input             dcm_progen
);

    localparam NCORES = 4;

    // ---------------------------------------------------------------
    // Clock: 48 MHz -> 96 MHz via DCM_SP
    // ---------------------------------------------------------------
    wire fxclk, hashclk;
    IBUFG fxclk_buf (.I(fxclk_in), .O(fxclk));
    wire dcm_clkfx;
    DCM_SP #(
        .CLKIN_PERIOD(20.833),
        .CLKFX_MULTIPLY(2), .CLKFX_DIVIDE(1),  // 48*2 = 96 MHz
        .CLK_FEEDBACK("NONE"), .STARTUP_WAIT("TRUE")
    ) dcm_inst (
        .CLKIN(fxclk), .RST(1'b0), .CLKFX(dcm_clkfx), .LOCKED(),
        .CLK0(), .CLK90(), .CLK180(), .CLK270(),
        .CLK2X(), .CLK2X180(), .CLKDV(), .CLKFX180(),
        .PSDONE(), .STATUS(),
        .CLKFB(1'b0), .DSSEN(1'b0), .PSCLK(1'b0), .PSEN(1'b0), .PSINCDEC(1'b0)
    );
    BUFG hashclk_buf (.I(dcm_clkfx), .O(hashclk));

    // ---------------------------------------------------------------
    // Communication: 80 bytes (76 header + 4 target)
    // ---------------------------------------------------------------
    wire [639:0] work_data;
    wire         work_valid;
    wire         rst_comm;

    reg [31:0] golden1 = 32'd0;
    reg [31:0] golden2 = 32'd0;
    reg [31:0] nonce_cnt = 32'd0;
    reg [31:0] hash7_out = 32'd0;

    ztex_comm comm_inst (
        .clk(hashclk), .select(select), .reset_in(reset),
        .read(read), .write(write), .rd_clk(rd_clk), .wr_clk(wr_clk), .wr_start(wr_start),
        .work_header(work_data), .work_valid(work_valid), .reset_out(rst_comm),
        .golden_nonce1(golden1), .golden_nonce2(golden2),
        .cur_nonce(nonce_cnt), .cur_hash7(hash7_out)
    );

    // ---------------------------------------------------------------
    // SHA3-256t multicore scanner
    // ---------------------------------------------------------------
    wire nonce_found;
    wire [31:0] golden_nonce;
    wire [31:0] miner_hash7;
    wire [31:0] miner_last_nonce;

    sha3_multicore #(.NCORES(NCORES)) miner_inst (
        .clk(hashclk),
        .reset(work_valid),
        .block(work_data),
        .nonce_start(32'd0),
        .nonce_found(nonce_found),
        .nonce_out(golden_nonce),
        .cur_hash7(miner_hash7),
        .last_done_nonce(miner_last_nonce)
    );

    // ---------------------------------------------------------------
    // Golden nonce capture + nonce counter for hashrate
    // ---------------------------------------------------------------
    always @(posedge hashclk) begin
        nonce_cnt <= miner_last_nonce;

        if (work_valid) begin
            golden1 <= 32'd0;
            golden2 <= 32'd0;
        end else if (nonce_found) begin
            golden2 <= golden1;
            golden1 <= golden_nonce;
        end

        hash7_out <= miner_hash7;
    end

endmodule
