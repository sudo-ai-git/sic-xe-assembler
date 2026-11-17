# SVL → SIC/XE Compiler

A compiler pipeline that takes **SVL** (Spike Verification Language) source code,
compiles it to **SIC/XE** assembly, assembles it into **tamper-evident H/T/E object
code** stamped with 231-gate checksums, links multiple object files, and executes
the result in a verified simulator.

SVL language: <https://github.com/sudo-ai-git/svl>

```
SVL source → lex/parse → SIC/XE assembly → 231-gate stamped object code
          → link (multi-file) → verified simulator
```

## Project structure

| File | Purpose |
|------|---------|
| `sic_xe_assembler_sim.py` | Two-pass SIC/XE assembler + simulator with 231-gate tamper-evident object code |
| `svl_to_sic.py` | SVL → SIC/XE compiler (also emits `.obj` and `.sym` files) |
| `sic_xe_linker.py` | Relocating linker for multiple object files |
| `qec_memory.py` | QEC-protected byte memory ([[5475,1,19]] annulus code) |
| `qec_error_demo.py` | Demonstrates memory error correction under corruption |
| `test_linker.py` | Linker smoke test (two objects) |
| `svl/` | Vendored SVL front end (`lexer`, `parser_rd`, `gate231`) — stdlib only |
| `examples/` | Example SVL programs |
| `tests/` | Test suite + `run_all.py` runner |
| `LICENSE` | GNU AGPL-3.0 |

The repository is **self-contained**: `svl/` is vendored, so no install of the
upstream SVL package is required.

## Pipeline

1. **Lex & parse** — SVL source is tokenized (`svl.lexer`) and parsed into an AST
   (`svl.parser_rd`).
2. **Code generation** — The AST is walked to emit SIC/XE assembly. Variables and
   strings are relocatable labels; a runtime library (`MOD`, `XOR`, `SHL`, `SHR`,
   `NOT`, temporaries) is appended to every object.
3. **Assembly** — SIC/XE assembly is assembled into H/T/E object records. Every T
   record is stamped with a 231-gate three-channel checksum (SUM/LINEAR/ROLLING mod
   231) over its raw data bytes.
4. **Linking** — `sic_xe_linker.py` relocates each object, resolves cross-object
   symbols, and re-stamps the checksums of every patched record.
5. **Verified execution** — The simulator loads the object code, verifies each T
   record's 231-gate checksum before executing any instruction, and rejects tampered
   object code with a clear error.

## Build & run

```bash
# Clone
git clone https://github.com/sudo-ai-git/sic-xe-assembler.git
cd sic-xe-assembler

# Compile and run an SVL program
python3 svl_to_sic.py examples/arithmetic.svl

# Emit assembly without executing
python3 svl_to_sic.py examples/arithmetic.svl --emit-asm

# Emit an object file (no execution) for later linking
python3 svl_to_sic.py examples/arithmetic.svl --emit-obj
```

## Example programs

### `examples/arithmetic.svl` — basic arithmetic

```svl
module m {
  func main() type void {
    let x: int = 1
    let y: int = 2
    let z: int = x + y
    return
  }
}
```

Compiles to (variables are relocatable labels):

```
main:  LDA #1      ; load 1
       STA V0      ; store x
       LDA #2      ; load 2
       STA V1      ; store y
       LDA V0      ; load x
       STA TMP0    ; save left
       LDA V1      ; load y
       STA TMP1    ; save right
       LDA TMP0    ; reload left
       ADD TMP1    ; + right
       STA V2      ; store z
       HALT        ; halt — return from main
```

### `examples/bitwise.svl` — bitwise operators

`&`, `|`, `^`, `~` (NOT is `-x - 1`; XOR is `(a|b) - (a&b)`).

### `examples/shift.svl` — shift operators

`<<` and `>>` are runtime subroutines (`SHL` doubles repeatedly, `SHR` halves
repeatedly).

### `examples/conditional.svl` — ternary `if … then … else`

### `examples/control.svl` — while loops

### `examples/functions.svl` — function calls

Arguments are passed in a fixed absolute region at `0xF000`; the callee reads them
positionally.

## Multi-file linking

Compile each source to an object file, then link:

```bash
python3 svl_to_sic.py tests/test_utils.svl --emit-obj
python3 svl_to_sic.py tests/test_main2.svl --emit-obj
python3 sic_xe_linker.py tests/test_utils.obj tests/test_main2.obj -o linked.obj
```

The linker keeps the first definition of duplicate symbols (every object carries
the same runtime library), relocates symbols by `load_addr + (rel_addr - start)`,
patches format-4 references with a 20-bit absolute address and format-3 references
with a PC-relative displacement, and re-stamps the 231-gate checksum of every
patched record. The entry point is taken from the last object (the main program).

## Tests

```bash
python3 tests/run_all.py
```

Runs 13 standalone programs (each checked against an expected register value or
printed text) plus the multi-file link test. `tests/test_utils.svl` and
`tests/test_main2.svl` are link inputs and are exercised by `test_multifile.py`.

## How it works

### Assembler (two-pass)

**Pass 1** — Scans source to build the symbol table and compute the location counter.
Forward references are resolved because all labels are registered before pass 2.

**Pass 2** — Emits object code:
- Format 3 instructions (3 bytes) for addresses ≤ 4095 (PC-relative or base-relative)
- Format 4 instructions (4 bytes) for larger addresses (20-bit absolute)
- Format 1 instructions (1 byte) for HALT (0xFF)

### Object code format (H/T/E)

```
H^NONAME^001000^00003C        — Header: name, start address, program length
T^001000^0B^4B2024...:G:143:220:92   — Text: code bytes + 231-gate checksum
E^001000                        — End: entry point
```

Every T record ends with `:G:sum:lin:rol` — the 231-gate three-channel checksum
(SUM/LINEAR/ROLLING mod 231) over the record's data bytes.

### Simulator

Loads object records via `verify_and_load_records()`, which:
1. Parses the H record for the start address
2. For each T record, recomputes the 231-gate checksum and compares against the
   embedded values — raises `ValueError` on mismatch
3. Loads verified bytes into memory
4. Parses the E record for the entry point

Execution is instruction-by-instruction with full register tracing (A, X, L, B, S,
T, F, PC, SW). Built-in routines live at 0xFF00 (`print_int`), 0xFF03 (`print`) and
0xFF06 (SVC dispatcher); execution halts on the `HALT` (0xFF) opcode.

Memory is QEC-protected (`qec_memory.py`): each byte is stored as eight
[[5475,1,19]] annulus codewords and decoded with automatic error correction.

## Tamper detection

Flip any byte in a T record's data and the simulator rejects it:

```
231-gate checksum mismatch at 001000:
  expected G:143:220:92, computed G:142:187:91 — object code may be tampered
```

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## License

GNU AGPL-3.0. See `LICENSE` for details.
