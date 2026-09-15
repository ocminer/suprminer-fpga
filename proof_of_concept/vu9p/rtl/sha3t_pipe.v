// sha3t_pipe.v - fully-unrolled SHA3-256t (triple SHA3-256) pipeline for VU9P.
//
// One nonce enters per clock, one (nonce, hash7) result exits per clock,
// LATENCY (=72) cycles later. 3 hashes x 24 rounds, one register per round.
//
// Message/byte conventions identical to the chain-proven ZTEX sha3_core.v:
//   hdr[8k+7:8k]   = header byte k, k = 0..75
//   header bytes 76..79 = BE(nonce): byte76 = nonce[31:24] .. byte79 = nonce[7:0]
//   absorb1: hdr||BE(nonce) in lanes 0..9, 0x06 pad lane 10, 0x80 in lane 16
//   reinject: digest = lanes 0..3 kept in place, 0x06 in lane 4, 0x80 in lane 16
//   hash7 = final lane3[63:32] (digest bytes 28..31 as LE uint32)
//
// The header is expected to be quasi-static (per work item); only the nonce
// streams. Round-1 constant folding over the static lanes is left to Vivado
// (hdr arrives via a register bank held stable during a work item).

module sha3t_pipe (
    input             clk,
    input             flush,      // sync: invalidate everything in flight
                                  // (assert through a work change; results for
                                  // the old header must never surface as new)
    input  [607:0]    hdr,        // header bytes 0..75
    input  [31:0]     nonce_in,
    input             in_valid,
    output [31:0]     nonce_out,
    output [31:0]     hash7_out,
    output [255:0]    digest_out, // full final digest lanes 0..3 (debug/checkNonce)
    output            out_valid
);

    localparam integer LATENCY = 72;

    function [63:0] rc_tbl;
        input integer r;
        begin
            case (r)
                0:  rc_tbl = 64'h0000000000000001;
                1:  rc_tbl = 64'h0000000000008082;
                2:  rc_tbl = 64'h800000000000808A;
                3:  rc_tbl = 64'h8000000080008000;
                4:  rc_tbl = 64'h000000000000808B;
                5:  rc_tbl = 64'h0000000080000001;
                6:  rc_tbl = 64'h8000000080008081;
                7:  rc_tbl = 64'h8000000000008009;
                8:  rc_tbl = 64'h000000000000008A;
                9:  rc_tbl = 64'h0000000000000088;
                10: rc_tbl = 64'h0000000080008009;
                11: rc_tbl = 64'h000000008000000A;
                12: rc_tbl = 64'h000000008000808B;
                13: rc_tbl = 64'h800000000000008B;
                14: rc_tbl = 64'h8000000000008089;
                15: rc_tbl = 64'h8000000000008003;
                16: rc_tbl = 64'h8000000000008002;
                17: rc_tbl = 64'h8000000000000080;
                18: rc_tbl = 64'h000000000000800A;
                19: rc_tbl = 64'h800000008000000A;
                20: rc_tbl = 64'h8000000080008081;
                21: rc_tbl = 64'h8000000000008080;
                22: rc_tbl = 64'h0000000080000001;
                23: rc_tbl = 64'h8000000080008008;
                default: rc_tbl = 64'h0;
            endcase
        end
    endfunction

    // ---- absorb 1: 80-byte header (76 static + 4 nonce BE) -----------------
    wire [1599:0] absorb1;
    assign absorb1[64*9-1  : 0]      = hdr[575:0];                 // lanes 0..8
    assign absorb1[64*10-1 : 64*9]   = {nonce_in[7:0], nonce_in[15:8],
                                        nonce_in[23:16], nonce_in[31:24],
                                        hdr[607:576]};             // lane 9
    assign absorb1[64*11-1 : 64*10]  = 64'h0000000000000006;       // lane 10
    assign absorb1[64*16-1 : 64*11]  = 320'h0;                     // lanes 11..15
    assign absorb1[64*17-1 : 64*16]  = 64'h8000000000000000;       // lane 16
    assign absorb1[1599    : 64*17]  = 512'h0;                     // lanes 17..24

    // ---- hash 1: 24 pipelined rounds ---------------------------------------
    // stage register h1_r[r] holds the output of round r
    wire [1599:0] h1_in  [0:23];
    wire [1599:0] h1_out [0:23];
    reg  [1599:0] h1_r   [0:23];

    genvar r;
    generate
        for (r = 0; r < 24; r = r + 1) begin : g_h1
            if (r == 0) begin : g_first
                assign h1_in[r] = absorb1;
            end else begin : g_rest
                assign h1_in[r] = h1_r[r-1];
            end
            keccak_round_c #(.RC(rc_tbl(r))) rnd_i (
                .st_in (h1_in[r]),
                .st_out(h1_out[r])
            );
            always @(posedge clk) h1_r[r] <= h1_out[r];
        end
    endgenerate

    // ---- reinject 1 -> absorb 2: digest (lanes 0..3) || pad ----------------
    wire [1599:0] absorb2;
    assign absorb2[64*4-1  : 0]      = h1_r[23][64*4-1:0];         // lanes 0..3
    assign absorb2[64*5-1  : 64*4]   = 64'h0000000000000006;       // lane 4
    assign absorb2[64*16-1 : 64*5]   = 704'h0;                     // lanes 5..15
    assign absorb2[64*17-1 : 64*16]  = 64'h8000000000000000;       // lane 16
    assign absorb2[1599    : 64*17]  = 512'h0;                     // lanes 17..24

    // ---- hash 2 ------------------------------------------------------------
    wire [1599:0] h2_in  [0:23];
    wire [1599:0] h2_out [0:23];
    reg  [1599:0] h2_r   [0:23];
    generate
        for (r = 0; r < 24; r = r + 1) begin : g_h2
            if (r == 0) begin : g_first
                assign h2_in[r] = absorb2;
            end else begin : g_rest
                assign h2_in[r] = h2_r[r-1];
            end
            keccak_round_c #(.RC(rc_tbl(r))) rnd_i (
                .st_in (h2_in[r]),
                .st_out(h2_out[r])
            );
            always @(posedge clk) h2_r[r] <= h2_out[r];
        end
    endgenerate

    // ---- reinject 2 -> absorb 3 --------------------------------------------
    wire [1599:0] absorb3;
    assign absorb3[64*4-1  : 0]      = h2_r[23][64*4-1:0];
    assign absorb3[64*5-1  : 64*4]   = 64'h0000000000000006;
    assign absorb3[64*16-1 : 64*5]   = 704'h0;
    assign absorb3[64*17-1 : 64*16]  = 64'h8000000000000000;
    assign absorb3[1599    : 64*17]  = 512'h0;

    // ---- hash 3 ------------------------------------------------------------
    wire [1599:0] h3_in  [0:23];
    wire [1599:0] h3_out [0:23];
    reg  [1599:0] h3_r   [0:23];
    generate
        for (r = 0; r < 24; r = r + 1) begin : g_h3
            if (r == 0) begin : g_first
                assign h3_in[r] = absorb3;
            end else begin : g_rest
                assign h3_in[r] = h3_r[r-1];
            end
            keccak_round_c #(.RC(rc_tbl(r))) rnd_i (
                .st_in (h3_in[r]),
                .st_out(h3_out[r])
            );
            always @(posedge clk) h3_r[r] <= h3_out[r];
        end
    endgenerate

    // ---- nonce / valid delay pipes -----------------------------------------
    reg [31:0] nonce_pipe [0:LATENCY-1];
    reg [LATENCY-1:0] valid_pipe = {LATENCY{1'b0}};
    integer k;
    always @(posedge clk) begin
        nonce_pipe[0] <= nonce_in;
        for (k = 1; k < LATENCY; k = k + 1)
            nonce_pipe[k] <= nonce_pipe[k-1];
        if (flush)
            valid_pipe <= {LATENCY{1'b0}};
        else
            valid_pipe <= {valid_pipe[LATENCY-2:0], in_valid};
    end

    assign nonce_out  = nonce_pipe[LATENCY-1];
    assign digest_out = h3_r[23][255:0];
    assign hash7_out  = h3_r[23][64*3+63 : 64*3+32];
    assign out_valid  = valid_pipe[LATENCY-1];

endmodule
