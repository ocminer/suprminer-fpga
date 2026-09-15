#!/usr/bin/env python3
"""CPU-oracle RTL simulation; no Vivado, JTAG, network or hardware operations.

The actual round, pipeline and single-core controller are simulated by Icarus.
Python hashlib independently computes SHA3-256 three times over 76 header bytes
and a big-endian uint32 nonce. Full 256-bit digest, tags, valid/flush timing,
nonce-zero startup, wrap, comparison and counted results are checked. Clock/IP,
AXI and asynchronous top-level transfers are outside this simulation's scope.
"""
from pathlib import Path
import hashlib
import json
import random
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
RTL = HERE / 'rtl'


def digest(header, nonce):
    value = header + nonce.to_bytes(4, 'big')
    for _ in range(3):
        value = hashlib.sha3_256(value).digest()
    return int.from_bytes(value, 'little')


def vectors():
    rng = random.Random(0x425331)
    records = []
    for step in range(200):
        header = (bytes(76) if step == 0 else bytes([255])*76 if step == 1
                  else bytes(range(76)) if step == 2 else rng.randbytes(76))
        nonce = [0, 1, 0xffffffff, 0x12345678][step % 4] if step < 4 else rng.getrandbits(32)
        valid = step < 16 or step in (20, 23) or 100 <= step <= 115
        flush = step == 108
        records.append((header, nonce, valid, flush))
    # Absolute due-edge oracle, independent of RTL shift-register internals.
    pending = {}
    expected = []
    for step, (header, nonce, valid, flush) in enumerate(records):
        if flush:
            pending.clear()
        elif valid:
            pending[step + 71] = (nonce, digest(header, nonce))
        expected.append(pending.pop(step, None))
    assert sum(x is not None for x in expected) == 25
    assert not pending
    return records, expected


def pipeline_tb():
    records, expected = vectors()
    setup = []
    for i, ((header, nonce, valid, flush), result) in enumerate(zip(records, expected)):
        setup += [f"headers[{i}]=608'h{int.from_bytes(header,'little'):0152x};",
                  f"nonces[{i}]=32'h{nonce:08x}; valid_in[{i}]=1'b{int(valid)}; flush_in[{i}]=1'b{int(flush)};",
                  f"valid_expected[{i}]=1'b{int(result is not None)};"]
        if result is not None:
            setup += [f"nonce_expected[{i}]=32'h{result[0]:08x}; digest_expected[{i}]=256'h{result[1]:064x};"]
    return r'''
`timescale 1ns/1ps
module tb;
reg clk=0; always #5 clk=~clk;
reg flush=1,in_valid=0; reg [607:0] hdr=0; reg [31:0] nonce_in=0;
wire [31:0] nonce_out,hash7_out; wire [255:0] digest_out; wire out_valid;
sha3t_pipe dut(.*);
reg [607:0] headers[0:199];reg [31:0] nonces[0:199],nonce_expected[0:199];
reg valid_in[0:199],flush_in[0:199],valid_expected[0:199];
reg [255:0] digest_expected[0:199];integer i,seen=0;
initial begin
''' + '\n'.join(setup) + r'''
repeat(2) @(negedge clk);
for(i=0;i<200;i=i+1) begin
    hdr=headers[i];nonce_in=nonces[i];in_valid=valid_in[i];flush=flush_in[i];
    @(posedge clk);#1;
    if(out_valid!==valid_expected[i])$fatal(1,"pipeline valid/flush edge=%0d",i);
    if(valid_expected[i])begin
        if(nonce_out!==nonce_expected[i]||digest_out!==digest_expected[i]||hash7_out!==digest_expected[i][255:224])
            $fatal(1,"pipeline nonce/serialization/full digest edge=%0d",i);
        seen=seen+1;
    end
    @(negedge clk);
end
if(seen!=25)$fatal(1,"pipeline result count");
$display("PASS pipeline full256=25 latency=72 bubbles=1 flush=1 nonce_zero=1");$finish;
end
initial begin #3000;$fatal(1,"pipeline timeout");end
endmodule
'''


def core_tb():
    header = bytes((i*17 + 3) % 256 for i in range(76))
    bases = [0, 0xfffffffe, 0, 1]
    targets = [0xffffffff, 0xffffffff, digest(header, 0) >> 224, 0]
    setup = [f"hdr=608'h{int.from_bytes(header,'little'):0152x};"]
    for j, (base, target) in enumerate(zip(bases, targets)):
        setup += [f"bases[{j}]=32'h{base:08x};targets[{j}]=32'h{target:08x};"]
        for n in range(8):
            setup += [f"golden[{j*8+n}]=256'h{digest(header,(base+n)&0xffffffff):064x};"]
    assert any((digest(header,n)>>224)>targets[2] for n in range(6))
    return r'''
`timescale 1ns/1ps
module tb;
reg clk=0;always #5 clk=~clk;
reg rst=1,run=0;reg [607:0] hdr=0;reg [31:0] target=0,nonce_base=0;
wire found;wire [31:0] found_nonce,found_hash7,last_hash7;wire [63:0] hashes_done;
sha3t_core1 dut(.*);
reg [31:0] bases[0:3],targets[0:3];reg [255:0] golden[0:31];
reg expected_hit;reg [31:0] expected_nonce;
integer job,step,n,seen=0,hits=0,misses=0;
initial begin
'''+'\n'.join(setup)+r'''
for(job=0;job<4;job=job+1)begin
    @(negedge clk);rst=1;run=0;nonce_base=bases[job];target=targets[job];
    repeat(2)begin @(posedge clk);#1;if(found!==0||hashes_done!==0)$fatal(1,"core reset/stale result");@(negedge clk);end
    rst=0;run=1;
    for(step=0;step<80;step=step+1)begin
        @(posedge clk);#1;
        if(step>=72)begin
            n=step-72;expected_nonce=bases[job]+n;
            if(dut.output_valid!==1||dut.output_nonce!==expected_nonce||dut.pipe_i.digest_out!==golden[job*8+n])
                $fatal(1,"core pipeline full256/first nonce job=%0d step=%0d",job,step);
        end
        if(step<74)begin
            if(found!==0||hashes_done!==0)$fatal(1,"early/stale core result job=%0d step=%0d",job,step);
        end else begin
            n=step-74;expected_nonce=bases[job]+n;expected_hit=golden[job*8+n][255:224]<=targets[job];
            if(found!==expected_hit||hashes_done!==(n+1)||last_hash7!==golden[job*8+n][255:224])
                $fatal(1,"core target/count/liveness job=%0d step=%0d",job,step);
            if(expected_hit)begin
                if(found_nonce!==expected_nonce||found_hash7!==golden[job*8+n][255:224])$fatal(1,"core found tuple");
                hits=hits+1;
            end else misses=misses+1;
            seen=seen+1;
        end
        @(negedge clk);
    end
end
rst=1;run=0;repeat(3)begin @(posedge clk);#1;if(found!==0||hashes_done!==0)$fatal(1,"final flush");end
if(seen!=24||hits==0||misses==0)$fatal(1,"core coverage");
$display("PASS core full256=32 counted=24 first_nonce_zero=1 wrap=1 equal_target=1 reset_jobs=4 hits=%0d misses=%0d",hits,misses);$finish;
end
initial begin #5000;$fatal(1,"core timeout");end
endmodule
'''


def main():
    start=time.monotonic()
    source_names=['keccak_round_c.v','sha3t_pipe.v','sha3t_core1.v','axil_regfile.v','sha3t_top.v']
    pins={name:hashlib.sha256((RTL/name).read_bytes()).hexdigest() for name in source_names}
    results=[]
    with tempfile.TemporaryDirectory(prefix='bs1-reference-rtl-') as td:
        temp=Path(td)
        for name, text in [('pipeline',pipeline_tb()),('core',core_tb())]:
            bench=temp/(name+'.sv');bench.write_text(text)
            image=temp/(name+'.vvp')
            source=[RTL/'keccak_round_c.v',RTL/'sha3t_pipe.v']
            if name=='core':source += [RTL/'sha3t_core1.v']
            subprocess.run(['iverilog','-g2012','-s','tb','-o',str(image),str(bench),*[str(p) for p in source]],check=True,timeout=60)
            run=subprocess.run(['vvp',str(image)],check=True,text=True,capture_output=True,timeout=90)
            print(run.stdout,end='')
            assert 'PASS ' in run.stdout and 'FATAL' not in run.stdout
            results.append({'test':name,'output':run.stdout.strip()})
    assert pins=={name:hashlib.sha256((RTL/name).read_bytes()).hexdigest() for name in source_names}
    print(json.dumps({'schema':'BS1_REFERENCE_FUNCTIONAL_SIMULATION_REV1','rtl_sha256':pins,'results':results,
                      'elapsed_seconds':round(time.monotonic()-start,3),'hardware_qualified':False,
                      'archival_bit_reproduction_claimed':False},sort_keys=True))

if __name__=='__main__':main()
