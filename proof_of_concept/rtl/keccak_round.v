// keccak_round.v - one combinational Keccak-f[1600] round
// State: 25 lanes of 64 bits, lane index = x + 5*y, packed into 1600-bit bus
// st_in[64*i+63 : 64*i] = lane i (little-endian 64-bit lanes, FIPS-202)

module keccak_round (
    input  [1599:0] st_in,
    input  [4:0]    rnd,
    output [1599:0] st_out
);

    // Round constants
    function [63:0] rc;
        input [4:0] r;
        begin
            case (r)
                5'd0:  rc = 64'h0000000000000001;
                5'd1:  rc = 64'h0000000000008082;
                5'd2:  rc = 64'h800000000000808A;
                5'd3:  rc = 64'h8000000080008000;
                5'd4:  rc = 64'h000000000000808B;
                5'd5:  rc = 64'h0000000080000001;
                5'd6:  rc = 64'h8000000080008081;
                5'd7:  rc = 64'h8000000000008009;
                5'd8:  rc = 64'h000000000000008A;
                5'd9:  rc = 64'h0000000000000088;
                5'd10: rc = 64'h0000000080008009;
                5'd11: rc = 64'h000000008000000A;
                5'd12: rc = 64'h000000008000808B;
                5'd13: rc = 64'h800000000000008B;
                5'd14: rc = 64'h8000000000008089;
                5'd15: rc = 64'h8000000000008003;
                5'd16: rc = 64'h8000000000008002;
                5'd17: rc = 64'h8000000000000080;
                5'd18: rc = 64'h000000000000800A;
                5'd19: rc = 64'h800000008000000A;
                5'd20: rc = 64'h8000000080008081;
                5'd21: rc = 64'h8000000000008080;
                5'd22: rc = 64'h0000000080000001;
                5'd23: rc = 64'h8000000080008008;
                default: rc = 64'h0;
            endcase
        end
    endfunction

    wire [63:0] a [0:24];
    genvar i;
    generate
        for (i = 0; i < 25; i = i + 1) begin : unpack
            assign a[i] = st_in[64*i +: 64];
        end
    endgenerate

    // theta
    wire [63:0] c [0:4];
    wire [63:0] d [0:4];
    generate
        for (i = 0; i < 5; i = i + 1) begin : theta_c
            assign c[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20];
        end
        for (i = 0; i < 5; i = i + 1) begin : theta_d
            assign d[i] = c[(i+4)%5] ^ {c[(i+1)%5][62:0], c[(i+1)%5][63]};
        end
    endgenerate

    wire [63:0] t [0:24];   // after theta
    generate
        for (i = 0; i < 25; i = i + 1) begin : theta_a
            assign t[i] = a[i] ^ d[i%5];
        end
    endgenerate

    // rho + pi: source lane (x,y)=x+5y -> dest lane y + 5*((2x+3y)%5),
    // rotated left by r[x][y]. Written as explicit constant slices so XST
    // implements pure wiring (no barrel shifters).
    wire [63:0] b [0:24];
    genvar x, y;

    assign b[0]  = t[0];                          // r=0
    assign b[10] = {t[1][62:0],  t[1][63]};       // r=1
    assign b[20] = {t[2][1:0],   t[2][63:2]};     // r=62
    assign b[5]  = {t[3][35:0],  t[3][63:36]};    // r=28
    assign b[15] = {t[4][36:0],  t[4][63:37]};    // r=27
    assign b[16] = {t[5][27:0],  t[5][63:28]};    // r=36
    assign b[1]  = {t[6][19:0],  t[6][63:20]};    // r=44
    assign b[11] = {t[7][57:0],  t[7][63:58]};    // r=6
    assign b[21] = {t[8][8:0],   t[8][63:9]};     // r=55
    assign b[6]  = {t[9][43:0],  t[9][63:44]};    // r=20
    assign b[7]  = {t[10][60:0], t[10][63:61]};   // r=3
    assign b[17] = {t[11][53:0], t[11][63:54]};   // r=10
    assign b[2]  = {t[12][20:0], t[12][63:21]};   // r=43
    assign b[12] = {t[13][38:0], t[13][63:39]};   // r=25
    assign b[22] = {t[14][24:0], t[14][63:25]};   // r=39
    assign b[23] = {t[15][22:0], t[15][63:23]};   // r=41
    assign b[8]  = {t[16][18:0], t[16][63:19]};   // r=45
    assign b[18] = {t[17][48:0], t[17][63:49]};   // r=15
    assign b[3]  = {t[18][42:0], t[18][63:43]};   // r=21
    assign b[13] = {t[19][55:0], t[19][63:56]};   // r=8
    assign b[14] = {t[20][45:0], t[20][63:46]};   // r=18
    assign b[24] = {t[21][61:0], t[21][63:62]};   // r=2
    assign b[9]  = {t[22][2:0],  t[22][63:3]};    // r=61
    assign b[19] = {t[23][7:0],  t[23][63:8]};    // r=56
    assign b[4]  = {t[24][49:0], t[24][63:50]};   // r=14

    // chi + iota
    generate
        for (y = 0; y < 5; y = y + 1) begin : chi_y
            for (x = 0; x < 5; x = x + 1) begin : chi_x
                if (x == 0 && y == 0) begin : g_iota
                    assign st_out[64*(x+5*y) +: 64] =
                        (b[x+5*y] ^ (~b[((x+1)%5)+5*y] & b[((x+2)%5)+5*y])) ^ rc(rnd);
                end else begin : g_plain
                    assign st_out[64*(x+5*y) +: 64] =
                        b[x+5*y] ^ (~b[((x+1)%5)+5*y] & b[((x+2)%5)+5*y]);
                end
            end
        end
    endgenerate

endmodule
