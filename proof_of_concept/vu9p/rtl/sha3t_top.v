// Reconstructed BS1 reference top: one core, 300 MHz, build 5a3d0001.
// Not an exact source snapshot for the separately published archival bit.
// The original simple control synchronizers and result-toggle interface are
// retained. This source has no hardware or timing qualification from simulation.
// Host protocol: STOP, CTRL=2, CTRL=0, header/target/base, ACK=1, CTRL=1.

module sha3t_top (
    input  sysclk_p,
    input  sysclk_n
);

    // ---- clocks --------------------------------------------------------
    wire sysclk_ibuf, sysclk_bufg;
    wire mmcm_fb, mmcm_core_out, mmcm_ctrl_out, mmcm_locked;
    wire core_clk, ctrl_clk;

    IBUFDS ibuf_sys (.I(sysclk_p), .IB(sysclk_n), .O(sysclk_ibuf));

    MMCME4_BASE #(
        .CLKIN1_PERIOD   (3.333),
        .CLKFBOUT_MULT_F (4.0),
        .DIVCLK_DIVIDE   (1),
        .CLKOUT0_DIVIDE_F(4.0),
        .CLKOUT1_DIVIDE  (16)
    ) mmcm_i (
        .CLKIN1   (sysclk_ibuf),
        .CLKFBIN  (mmcm_fb),
        .CLKFBOUT (mmcm_fb),
        .CLKOUT0  (mmcm_core_out),
        .CLKOUT1  (mmcm_ctrl_out),
        .LOCKED   (mmcm_locked),
        .PWRDWN   (1'b0),
        .RST      (1'b0),
        .CLKOUT0B (), .CLKOUT1B(), .CLKOUT2(), .CLKOUT2B(),
        .CLKOUT3  (), .CLKOUT3B(), .CLKOUT4(), .CLKOUT5(), .CLKOUT6(),
        .CLKFBOUTB()
    );
    BUFG bufg_core (.I(mmcm_core_out), .O(core_clk));
    BUFG bufg_ctrl (.I(mmcm_ctrl_out), .O(ctrl_clk));

    // ctrl-domain reset from MMCM lock
    reg [7:0] rstn_sr = 8'h00;
    always @(posedge ctrl_clk or negedge mmcm_locked) begin
        if (!mmcm_locked) rstn_sr <= 8'h00;
        else              rstn_sr <= {rstn_sr[6:0], 1'b1};
    end
    wire ctrl_rstn = rstn_sr[7];

    // ---- JTAG-to-AXI master (Xilinx IP, instantiated in project flow) --
    wire [31:0] m_awaddr, m_wdata, m_araddr, m_rdata;
    wire [3:0]  m_wstrb;
    wire [1:0]  m_bresp, m_rresp;
    wire m_awvalid, m_awready, m_wvalid, m_wready, m_bvalid, m_bready;
    wire m_arvalid, m_arready, m_rvalid, m_rready;
    wire [2:0] m_awprot, m_arprot;

    jtag_axi_0 jtag_axi_i (
        .aclk         (ctrl_clk),
        .aresetn      (ctrl_rstn),
        .m_axi_awaddr (m_awaddr),
        .m_axi_awprot (m_awprot),
        .m_axi_awvalid(m_awvalid),
        .m_axi_awready(m_awready),
        .m_axi_wdata  (m_wdata),
        .m_axi_wstrb  (m_wstrb),
        .m_axi_wvalid (m_wvalid),
        .m_axi_wready (m_wready),
        .m_axi_bresp  (m_bresp),
        .m_axi_bvalid (m_bvalid),
        .m_axi_bready (m_bready),
        .m_axi_araddr (m_araddr),
        .m_axi_arprot (m_arprot),
        .m_axi_arvalid(m_arvalid),
        .m_axi_arready(m_arready),
        .m_axi_rdata  (m_rdata),
        .m_axi_rresp  (m_rresp),
        .m_axi_rvalid (m_rvalid),
        .m_axi_rready (m_rready)
    );

    // ---- register file (ctrl_clk domain) -------------------------------
    wire [607:0] r_hdr;
    wire [31:0]  r_target, r_nonce_base;
    wire         r_run, r_flush, r_found_ack;
    wire         found_set_ctrl;
    wire [31:0]  c_found_nonce, c_found_hash7, c_last_hash7;
    wire [63:0]  c_hashes_done;

    axil_regfile regs_i (
        .clk(ctrl_clk), .rstn(ctrl_rstn),
        .awaddr(m_awaddr[11:0]), .awvalid(m_awvalid), .awready(m_awready),
        .wdata(m_wdata), .wstrb(m_wstrb), .wvalid(m_wvalid), .wready(m_wready),
        .bresp(m_bresp), .bvalid(m_bvalid), .bready(m_bready),
        .araddr(m_araddr[11:0]), .arvalid(m_arvalid), .arready(m_arready),
        .rdata(m_rdata), .rresp(m_rresp), .rvalid(m_rvalid), .rready(m_rready),
        .hdr(r_hdr), .target(r_target), .nonce_base(r_nonce_base),
        .run(r_run), .flush_pulse(r_flush), .found_ack(r_found_ack),
        .found_set(found_set_ctrl),
        .found_nonce(c_found_nonce), .found_hash7(c_found_hash7),
        .hashes_done(c_hashes_done), .last_hash7(c_last_hash7)
    );

    // ---- CDC ctrl -> core ----------------------------------------------
    // run: 2-FF sync. While run=0 the core ignores hdr/target/base, and the
    // host only changes them with run=0, so the wide buses need no handshake:
    // they are stable long before run's rising edge crosses.
    (* ASYNC_REG = "true" *) reg [1:0] run_sync = 2'b00;
    always @(posedge core_clk) run_sync <= {run_sync[0], r_run};
    wire core_run = run_sync[1];

    // flush pulse: toggle-and-sync
    reg flush_tgl = 1'b0;
    always @(posedge ctrl_clk) if (r_flush) flush_tgl <= ~flush_tgl;
    (* ASYNC_REG = "true" *) reg [2:0] flush_sync = 3'b000;
    always @(posedge core_clk) flush_sync <= {flush_sync[1:0], flush_tgl};
    wire core_flush = flush_sync[2] ^ flush_sync[1];

    // core-domain reset: flush OR not-yet-running
    wire core_rst = core_flush | ~core_run;

    // ---- miner ----------------------------------------------------------
    wire        m_found;
    wire [31:0] m_found_nonce, m_found_hash7, m_last_hash7;
    wire [63:0] m_hashes_done;

    sha3t_core1 miner_i (
        .clk        (core_clk),
        .rst        (core_rst),
        .hdr        (r_hdr),
        .target     (r_target),
        .nonce_base (r_nonce_base),
        .run        (core_run),
        .found      (m_found),
        .found_nonce(m_found_nonce),
        .found_hash7(m_found_hash7),
        .hashes_done(m_hashes_done),
        .last_hash7 (m_last_hash7)
    );

    // ---- CDC core -> ctrl ----------------------------------------------
    // found: latch result in core domain, toggle, sync to ctrl.
    reg        f_tgl = 1'b0;
    reg [31:0] f_nonce_q = 32'h0, f_hash7_q = 32'h0;
    always @(posedge core_clk) begin
        if (m_found) begin
            f_nonce_q <= m_found_nonce;
            f_hash7_q <= m_found_hash7;
            f_tgl     <= ~f_tgl;
        end
    end
    (* ASYNC_REG = "true" *) reg [2:0] f_sync = 3'b000;
    always @(posedge ctrl_clk) f_sync <= {f_sync[1:0], f_tgl};
    assign found_set_ctrl = f_sync[2] ^ f_sync[1];
    // Historical direct payload sampling: this is not a queued mailbox.
    // Host CPU verification remains necessary; simulation below does not
    // establish asynchronous result-transfer correctness.
    assign c_found_nonce = f_nonce_q;
    assign c_found_hash7 = f_hash7_q;

    // Historical two-register counter sampling is not an atomic snapshot.
    // The host reads high/low/high and rejects regression/overrun observations.
    (* ASYNC_REG = "true" *) reg [63:0] hd_s1 = 64'h0, hd_s2 = 64'h0;
    (* ASYNC_REG = "true" *) reg [31:0] lh_s1 = 32'h0, lh_s2 = 32'h0;
    always @(posedge ctrl_clk) begin
        hd_s1 <= m_hashes_done;  hd_s2 <= hd_s1;
        lh_s1 <= m_last_hash7;   lh_s2 <= lh_s1;
    end
    assign c_hashes_done = hd_s2;
    assign c_last_hash7  = lh_s2;

endmodule
