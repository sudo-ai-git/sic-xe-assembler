#!/usr/bin/env python3
"""
Demonstrate QEC-protected memory error correction in the SIC/XE simulator.

Loads test_add.svl (z = x + y = 1 + 2 = 3), then flips a physical bit in QEC
memory AFTER loading, and verifies the simulator still produces the correct result.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from svl.lexer import tokenize
from svl.parser_rd import Parser
from svl_to_sic import SICXECodeGen, assembly_to_source
from sic_xe_assembler_sim import Assembler, Simulator, parse_source


def main():
    source_path = Path("test_add.svl")
    svl_text = source_path.read_text()

    # Parse and compile
    tokens = tokenize(svl_text)
    parser = Parser(tokens)
    ast = parser.parse()
    codegen = SICXECodeGen()
    asm_lines = codegen.compile(ast)
    asm_text = assembly_to_source(asm_lines)
    src_lines = parse_source(asm_text)
    asm = Assembler(src_lines)
    success, records = asm.assemble()
    if not success:
        print("ASSEMBLY FAILED:", asm.errors)
        return 1

    # Load into simulator with QEC memory
    sim = Simulator(memory_size=0x2000)  # 8 KiB
    sim.verify_and_load_records(records)

    # Find where the value 3 (z = x + y) is stored in memory
    target_addr = None
    for addr in range(sim.memory.size):
        if sim.memory.read_byte(addr) == 3:
            target_addr = addr
            break

    if target_addr is None:
        print("Could not find value 3 in memory before corruption")
        return 1

    print(f"Found z=3 at address {target_addr} (0x{target_addr:04x})")
    original = sim.memory.read_byte(target_addr)
    print(f"Before corruption: mem[{target_addr}] = {original:#04x} ({original})")

    # Flip one physical bit in codeword 0 of the target byte
    sim.memory._store[target_addr][0] ^= (1 << 3)
    sim.memory.invalidate(target_addr)  # force re-decode on next read

    # Read back - QEC should auto-correct
    corrected = sim.memory.read_byte(target_addr)
    print(f"After corruption + QEC correction: mem[{target_addr}] = {corrected:#04x} ({corrected})")

    if corrected != original:
        print("FAIL: QEC did not correct the error!")
        return 1

    print("PASS: QEC memory auto-corrected single physical bit error")

    # Now run the simulator - it should still produce the correct result
    trace = sim.run()

    # Check final A register (should be 3)
    a_val = sim.regs["A"]
    print(f"Final A register: {a_val:#06x} ({a_val})")

    if a_val == 3:
        print("PASS: Simulator produced correct result (3 = 1 + 2) despite memory corruption")
    else:
        print(f"FAIL: Expected A=3, got A={a_val}")
        return 1

    # Print stats
    stats = sim.memory.stats()
    print(f"QEC Memory stats: {stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
