// ztex_comm_80.v - ZTEX USB-FPGA 1.15y communication for 80-byte work
// Groestl: 76 bytes header + 4 bytes target = 80 bytes

module ztex_comm (
    input             clk,
    input             select,
    input             reset_in,
    input  [7:0]      read,
    output [7:0]      write,
    input             rd_clk,
    input             wr_clk,
    input             wr_start,

    output reg [639:0] work_header,  // 80 bytes = 640 bits
    output reg         work_valid,
    output reg         reset_out,

    input [31:0]      golden_nonce1,
    input [31:0]      golden_nonce2,
    input [31:0]      cur_nonce,
    input [31:0]      cur_hash7
);

    localparam INBUF_BITS = 640;  // 80 bytes
    localparam WORK_BYTES = 80;

    reg [INBUF_BITS-1:0] inbuf_tmp;
    reg [INBUF_BITS-1:0] inbuf;

    reg [6:0] byte_count = 7'd0;
    reg       work_pending = 1'b0;

    reg [127:0] outbuf;

    reg [3:0] rd_clk_b, wr_clk_b;
    reg wr_start_b1, wr_start_b2;
    reg [7:0] read_buf;
    reg [7:0] write_buf;
    reg select_buf;
    reg [4:0] wr_delay;

    reg [31:0] golden1_reg, golden2_reg;

    assign write = select ? write_buf : 8'bz;

    wire rd_clk_edge = (rd_clk_b[3] == rd_clk_b[2]) &&
                       (rd_clk_b[2] == rd_clk_b[1]) &&
                       (rd_clk_b[1] != rd_clk_b[0]) && select_buf;

    always @(posedge clk) begin
        read_buf <= read;
        rd_clk_b[0] <= rd_clk;
        rd_clk_b[3:1] <= rd_clk_b[2:0];
        wr_clk_b[0] <= wr_clk;
        wr_clk_b[3:1] <= wr_clk_b[2:0];
        wr_start_b1 <= wr_start;
        wr_start_b2 <= wr_start_b1;
        select_buf <= select;

        if (rd_clk_edge) begin
            inbuf_tmp[INBUF_BITS-1:INBUF_BITS-8] <= read_buf;
            inbuf_tmp[INBUF_BITS-9:0] <= inbuf_tmp[INBUF_BITS-1:8];
            byte_count <= byte_count + 7'd1;
            if (byte_count == WORK_BYTES - 1)
                work_pending <= 1'b1;
        end

        inbuf <= inbuf_tmp;

        if (work_pending && !reset_out) begin
            work_valid <= 1'b1;
            work_pending <= 1'b0;
            byte_count <= 7'd0;
            work_header <= inbuf_tmp;
        end else begin
            work_valid <= 1'b0;
        end

        if (wr_start_b1 && wr_start_b2) begin
            wr_delay <= 5'd0;
        end else begin
            wr_delay[0] <= 1'b1;
            wr_delay[4:1] <= wr_delay[3:0];
        end

        if (!wr_delay[4]) begin
            outbuf <= { golden2_reg, cur_hash7, cur_nonce, golden1_reg };
        end else begin
            if ((wr_clk_b[3] == wr_clk_b[2]) && (wr_clk_b[2] == wr_clk_b[1]) && (wr_clk_b[1] != wr_clk_b[0]))
                outbuf[119:0] <= outbuf[127:8];
        end

        write_buf <= outbuf[7:0];

        if (select_buf)
            reset_out <= reset_in;

        if (reset_out) begin
            golden1_reg <= 32'd0;
            golden2_reg <= 32'd0;
        end else if (golden_nonce1 != golden1_reg) begin
            golden2_reg <= golden1_reg;
            golden1_reg <= golden_nonce1;
        end
    end

endmodule
