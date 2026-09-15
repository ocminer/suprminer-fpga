// axil_regfile.v - minimal AXI4-Lite slave exposing the miner control/status
// registers to the host through the BS1 JTAG-to-AXI interface.
//
// Register map (byte address, 32-bit words):
//   0x00..0x48  W  header words 0..18 (19 x 32b = 76 bytes), word k = hdr[32k+:32]
//   0x50        W  target (share when hash7 <= target)
//   0x54        W  nonce_base
//   0x58        W  control:  bit0 = run, bit1 = flush/reset (self-clearing pulse)
//   0x5C        R  status:   bit0 = found_sticky, bit1 = run
//   0x60        R  found_nonce
//   0x64        R  found_hash7
//   0x68        R  hashes_done[31:0]
//   0x6C        R  hashes_done[63:32]
//   0x70        R  last_hash7 (liveness / core-0 most-recent)
//   0x74        R  build id / magic (0x5A3D0001)
//   0x78        W  found_ack: write 1 -> clear found_sticky
//
// This slave accepts full-word writes; WSTRB is ignored. Header, target and
// base are held directly across clock domains while the host keeps RUN low.
// RUN/flush use synchronizers; found uses an event toggle and direct payload
// sampling, with ACK clearing only this slave's sticky flag. Binary counters
// use the historical two-register sampling path, not an atomic snapshot.
// These interfaces are reference behavior, not asynchronous-transfer signoff.

module axil_regfile (
    input             clk,
    input             rstn,

    // AXI4-Lite
    input      [11:0] awaddr,
    input             awvalid,
    output reg        awready,
    input      [31:0] wdata,
    input      [3:0]  wstrb,
    input             wvalid,
    output reg        wready,
    output reg [1:0]  bresp,
    output reg        bvalid,
    input             bready,
    input      [11:0] araddr,
    input             arvalid,
    output reg        arready,
    output reg [31:0] rdata,
    output reg [1:0]  rresp,
    output reg        rvalid,
    input             rready,

    // to/from miner (control-clock domain; synchronized in sha3t_top)
    output reg [607:0] hdr,
    output reg [31:0]  target,
    output reg [31:0]  nonce_base,
    output reg         run,
    output reg         flush_pulse,   // 1-cycle
    output reg         found_ack,     // 1-cycle

    input              found_set,     // 1-cycle from core domain (already synced)
    input      [31:0]  found_nonce,
    input      [31:0]  found_hash7,
    input      [63:0]  hashes_done,
    input      [31:0]  last_hash7
);
    localparam MAGIC = 32'h5A3D0001;

    reg found_sticky;

    // ---- write channel ----
    reg aw_seen, w_seen;
    reg [11:0] awaddr_q;
    reg [31:0] wdata_q;
    integer wi;

    always @(posedge clk) begin
        if (!rstn) begin
            awready <= 0; wready <= 0; bvalid <= 0; bresp <= 0;
            aw_seen <= 0; w_seen <= 0;
            run <= 0; flush_pulse <= 0; found_ack <= 0;
            hdr <= 608'h0; target <= 32'hFFFFFFFF; nonce_base <= 32'h0;
            found_sticky <= 0;
        end else begin
            flush_pulse <= 0;
            found_ack   <= 0;

            // latch aw/w
            if (awvalid && !aw_seen) begin awready <= 1; awaddr_q <= awaddr; aw_seen <= 1; end
            else awready <= 0;
            if (wvalid && !w_seen)  begin wready  <= 1; wdata_q  <= wdata;  w_seen  <= 1; end
            else wready <= 0;

            // commit when both present and no pending bvalid
            if (aw_seen && w_seen && !bvalid) begin
                if (awaddr_q <= 12'h048) begin
                    wi = awaddr_q[7:2];               // header word index 0..18
                    hdr[32*wi +: 32] <= wdata_q;
                end else begin
                    case (awaddr_q)
                        12'h050: target     <= wdata_q;
                        12'h054: nonce_base  <= wdata_q;
                        12'h058: begin
                            run         <= wdata_q[0];
                            flush_pulse <= wdata_q[1];
                        end
                        12'h078: if (wdata_q[0]) begin
                            found_sticky <= 1'b0;
                            found_ack    <= 1'b1;
                        end
                        default: ;
                    endcase
                end
                bvalid <= 1; bresp <= 2'b00;
                aw_seen <= 0; w_seen <= 0;
            end
            if (bvalid && bready) bvalid <= 0;

            // set found sticky from core domain
            if (found_set) found_sticky <= 1'b1;
        end
    end

    // ---- read channel ----
    always @(posedge clk) begin
        if (!rstn) begin
            arready <= 0; rvalid <= 0; rresp <= 0; rdata <= 0;
        end else begin
            if (arvalid && !rvalid) begin
                arready <= 1;
                rvalid  <= 1;
                rresp   <= 2'b00;
                case (araddr)
                    12'h05C: rdata <= {30'h0, run, found_sticky};
                    12'h060: rdata <= found_nonce;
                    12'h064: rdata <= found_hash7;
                    12'h068: rdata <= hashes_done[31:0];
                    12'h06C: rdata <= hashes_done[63:32];
                    12'h070: rdata <= last_hash7;
                    12'h074: rdata <= MAGIC;
                    default: rdata <= 32'hDEADBEEF;
                endcase
            end else begin
                arready <= 0;
                if (rvalid && rready) rvalid <= 0;
            end
        end
    end
endmodule
