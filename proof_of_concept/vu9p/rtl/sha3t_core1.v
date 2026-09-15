// Fixed single-core controller for the reconstructed BS1 reference.
// One nonce per clock enters the unchanged 72-capture triple-SHA3 pipeline.
// Holding nonce_base through the initial invalid edge corrects the historical
// generic feeder's skipped-first-nonce behavior; this is not byte-identical RTL.
module sha3t_core1 (
    input clk,
    input rst,
    input [607:0] hdr,
    input [31:0] target,
    input [31:0] nonce_base,
    input run,
    output reg found,
    output reg [31:0] found_nonce,
    output reg [31:0] found_hash7,
    output reg [63:0] hashes_done,
    output reg [31:0] last_hash7
);
    reg [31:0] nonce;
    reg input_valid;
    wire [31:0] output_nonce, output_hash7;
    wire output_valid;

    always @(posedge clk) begin
        if (rst) begin
            nonce <= nonce_base;
            input_valid <= 1'b0;
        end else if (run) begin
            if (input_valid) nonce <= nonce + 32'd1;
            input_valid <= 1'b1;
        end else begin
            input_valid <= 1'b0;
        end
    end

    sha3t_pipe pipe_i (
        .clk(clk), .flush(rst), .hdr(hdr), .nonce_in(nonce),
        .in_valid(input_valid), .nonce_out(output_nonce),
        .hash7_out(output_hash7), .digest_out(), .out_valid(output_valid)
    );

    // The historical single-core leaf and final capture, without a tree.
    reg hit_q, count_q;
    reg [31:0] nonce_q, hash7_q, last_q;
    always @(posedge clk) begin
        if (rst) begin
            hit_q <= 1'b0;
            count_q <= 1'b0;
            nonce_q <= 32'h0;
            hash7_q <= 32'h0;
        end else begin
            hit_q <= output_valid && (output_hash7 <= target);
            count_q <= output_valid;
            nonce_q <= output_nonce;
            hash7_q <= output_hash7;
        end
        if (output_valid) last_q <= output_hash7;
    end

    always @(posedge clk) begin
        if (rst) begin
            found <= 1'b0;
            found_nonce <= 32'h0;
            found_hash7 <= 32'h0;
            hashes_done <= 64'h0;
            last_hash7 <= 32'h0;
        end else begin
            found <= hit_q;
            if (hit_q) begin
                found_nonce <= nonce_q;
                found_hash7 <= hash7_q;
            end
            hashes_done <= hashes_done + {63'h0, count_q};
            last_hash7 <= last_q;
        end
    end
endmodule
