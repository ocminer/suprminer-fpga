// sha3_multicore.v - N parallel sha3_core scanners with interleaved nonces
//
// Core i scans nonce_start + i, + NCORES, + 2*NCORES, ...
// The cores sweep one contiguous nonce range together, so core 0's current
// nonce is (within NCORES) the total number of hashes done by the whole
// FPGA — report it directly as last_done_nonce (host computes
// (last_nonce - start_nonce)/elapsed; NO extra multiplier needed).

module sha3_multicore # (
    parameter NCORES = 4
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

    wire        nf_w    [0:NCORES-1];
    wire [31:0] no_w    [0:NCORES-1];
    wire [31:0] hash7_w [0:NCORES-1];
    wire [31:0] last_w  [0:NCORES-1];

    genvar gi;
    generate
        for (gi = 0; gi < NCORES; gi = gi + 1) begin : core
            sha3_core #(.NONCE_STRIDE(NCORES)) inst (
                .clk(clk),
                .reset(reset),
                .block(block),
                .nonce_start(nonce_start + gi[31:0]),
                .nonce_found(nf_w[gi]),
                .nonce_out(no_w[gi]),
                .cur_hash7(hash7_w[gi]),
                .last_done_nonce(last_w[gi])
            );
        end
    endgenerate

    reg        found_reg;
    reg [31:0] found_nonce_reg;
    always @(posedge clk) begin
        if (reset) begin
            found_reg       <= 1'b0;
            found_nonce_reg <= 32'h0;
            cur_hash7       <= 32'h0;
            last_done_nonce <= 32'h0;
        end else begin
            found_reg <= 1'b0;
            begin : find_golden
                integer ci;
                for (ci = 0; ci < NCORES; ci = ci + 1) begin
                    if (nf_w[ci]) begin
                        found_reg       <= 1'b1;
                        found_nonce_reg <= no_w[ci];
                        disable find_golden;
                    end
                end
            end
            cur_hash7       <= hash7_w[0];
            last_done_nonce <= last_w[0];
        end
    end

    assign nonce_found = found_reg;
    assign nonce_out   = found_nonce_reg;

endmodule
