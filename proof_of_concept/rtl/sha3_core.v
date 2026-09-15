// sha3_core.v - autonomous SHA3-256t (triple SHA3-256) nonce scanner
//
// Hashes the 80-byte BC3 block header (76 bytes from host + 4-byte nonce
// generated here), then re-hashes the 32-byte digest twice more.
// Each hash = one Keccak-f[1600] permutation (message always fits the
// 136-byte SHA3-256 rate block).
//
// Byte order (matches ztex_comm_80 wire order):
//   block[8k+7:8k] = message byte k, k = 0..75 (header)
//   header bytes 76..79 = BE encoding of the nonce counter value, because the
//   host convention (proven with groestl/odo) is: serialized header byte
//   stream = be32enc(work->data[k]), and host sets work->data[19] = golden
//   nonce readback value for verify + submit.
//   target uint32 (host LE) at block[639:608]
//
// hash7 = final digest bytes 28..31 as LE uint32 = lane3[63:32]
// Share when hash7 <= target.
//
// Cycles per nonce: 1 load + 3*24 rounds + 2 reinject + 1 check = 76

module sha3_core # (
    parameter NONCE_STRIDE = 32'd1
) (
    input             clk,
    input             reset,
    input  [639:0]    block,
    input  [31:0]     nonce_start,
    output            nonce_found,
    output [31:0]     nonce_out,
    output reg [31:0] cur_hash7,
    output reg [31:0] last_done_nonce
);

    // rev3: capture the work block into a per-core register over a 2-cycle
    // window after reset (work_valid). The work_header -> blk_r paths are
    // multicycle (TS_hdrcap = 2x period in the UCF), taking the 640-bit
    // cross-chip distribution out of the router's critical set. The FSM
    // waits one extra cycle (cap_wait) before using blk_r.
    reg [639:0] blk_r;
    reg         cap_wait;

    wire [31:0]  target = {blk_r[615:608], blk_r[623:616], blk_r[631:624], blk_r[639:632]};
    wire [607:0] hdr    = blk_r[607:0];

    localparam S_LOAD  = 2'd0;
    localparam S_RUN   = 2'd1;
    localparam S_REINJ = 2'd2;
    localparam S_CHECK = 2'd3;

    reg [1:0]    st_m;
    reg [1:0]    phase;      // 1..3 = which SHA3 invocation
    reg [4:0]    rnd;
    reg [31:0]   nonce;
    reg [1599:0] st;
    reg          found_r;
    reg [31:0]   found_nonce_r;

    wire [1599:0] rnd_out;
    keccak_round round_i (
        .st_in (st),
        .rnd   (rnd),
        .st_out(rnd_out)
    );

    wire [31:0] hash7_w = st[64*3+63 : 64*3+32];   // lane3[63:32]

    always @(posedge clk) begin
        if (reset) begin
            blk_r           <= block;
            cap_wait        <= 1'b1;
            st_m            <= S_LOAD;
            nonce           <= nonce_start;
            found_r         <= 1'b0;
            found_nonce_r   <= 32'h0;
            cur_hash7       <= 32'h0;
            last_done_nonce <= 32'h0;
        end else begin
            found_r <= 1'b0;
            case (st_m)

            S_LOAD: if (cap_wait) begin
                // second capture cycle: blk_r settles (multicycle path)
                blk_r    <= block;
                cap_wait <= 1'b0;
            end else begin
                // absorb 80-byte header || 0x06 || 0..0 || 0x80  (136-byte rate)
                st[64*9-1  : 0]      <= hdr[575:0];              // lanes 0..8
                // lane 9 = header bytes 72..79: bytes 76..79 = BE(nonce)
                st[64*10-1 : 64*9]   <= {nonce[7:0], nonce[15:8], nonce[23:16], nonce[31:24], hdr[607:576]};
                st[64*11-1 : 64*10]  <= 64'h0000000000000006;    // lane 10: pad 0x06
                st[64*16-1 : 64*11]  <= 320'h0;                  // lanes 11..15
                st[64*17-1 : 64*16]  <= 64'h8000000000000000;    // lane 16: pad 0x80
                st[1599    : 64*17]  <= 512'h0;                  // capacity lanes 17..24
                phase <= 2'd1;
                rnd   <= 5'd0;
                st_m  <= S_RUN;
            end

            S_RUN: begin
                st  <= rnd_out;
                rnd <= rnd + 5'd1;
                if (rnd == 5'd23)
                    st_m <= (phase == 2'd3) ? S_CHECK : S_REINJ;
            end

            S_REINJ: begin
                // absorb 32-byte digest || 0x06 || 0..0 || 0x80
                // digest = lanes 0..3 of current state (keep in place)
                st[64*5-1  : 64*4]  <= 64'h0000000000000006;     // lane 4: pad 0x06
                st[64*16-1 : 64*5]  <= 704'h0;                   // lanes 5..15
                st[64*17-1 : 64*16] <= 64'h8000000000000000;     // lane 16: pad 0x80
                st[1599    : 64*17] <= 512'h0;                   // capacity
                phase <= phase + 2'd1;
                rnd   <= 5'd0;
                st_m  <= S_RUN;
            end

            S_CHECK: begin
                last_done_nonce <= nonce;
                cur_hash7       <= hash7_w;
                if (hash7_w <= target) begin
                    found_r       <= 1'b1;
                    found_nonce_r <= nonce;
                end
                nonce <= nonce + NONCE_STRIDE;
                st_m  <= S_LOAD;
            end

            default: st_m <= S_LOAD;
            endcase
        end
    end

    assign nonce_found = found_r;
    assign nonce_out   = found_nonce_r;

endmodule
