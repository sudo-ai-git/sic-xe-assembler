# SVL → SIC/XE Compiler

A compiler pipeline that takes **SVL** (Spike Verification Language) source code,
compiles it to **SIC/XE** assembly, assembles it into **tamper-evident H/T/E object
code** stamped with 231-gate checksums, and executes it in a verified simulator.

SVL language: <https://github.com/sudo-ai-git/svl>

```
SVL source → lex/parse → SIC/XE assembly → 231-gate stamped object code → verified simulator
```

## Project structure

| File | Purpose |
|------|---------|
| `sic_xe_assembler_sim.py` | Two-pass SIC/XE assembler + simulator with 231-gate tamper-evident object code |
| `svl_to_sic.py` | SVL → SIC/XE compiler |
| `LICENSE` | GNU AGPL-3.0 |
| `examples/` | Example SVL programs |

## Pipeline

1. **Lex & parse** — SVL source is tokenized (`svl.lexer`) and parsed into an AST
   (`svl.parser_rd`).
2. **Code generation** — The AST is walked to emit SIC/XE assembly (3-address code
   with variables, strings, labels, and runtime subroutines).
3. **Assembly** — SIC/XE assembly is assembled into H/T/E object records. Every T
   record is stamped with a 231-gate three-channel checksum (SUM/LINEAR/ROLLING mod
   231) over its raw data bytes.
4. **Verified execution** — The simulator loads the object code, verifies each T
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

Compiles to:
```
MAIN:  LDA #1      ; load 1
       STA 16      ; store x
       LDA #2      ; load 2
       STA 19      ; store y
       LDA 16      ; load x
       STA TMP0    ; save left
       LDA 19      ; load y
       STA TMP1    ; save right
       LDA TMP0    ; reload left
       ADD TMP1    ; + right
       STA 22      ; store z
       HALT        ; halt — return from main
```

### `examples/control.svl` — if/else and while loops

```svl
module m {
  func main() type void {
    let i: int = 0
    while i < 5 {
      let j: int = i + 1
      i = i + 1
    }
    return
  }
}
```

### `examples/functions.svl` — function calls

```svl
module m {
  func add(a: int, b: int) type int {
    let r: int = a + b
    return r
  }

  func main() type void {
    let s: int = add(3, 4)
    return
  }
}
```

### `examples/bitwise.svl` — bitwise operators

```svl
module m {
  func main() type void {
    let x: int = 1
    let y: int = 2
    let a: int = x & y
    let o: int = x | y
    let xr: int = x ^ y
    let n: int = ~x
    return
  }
}
```

### `examples/shift.svl` — shift operators

```svl
module m {
  func main() type void {
    let x: int = 1
    let y: int = 2
    let l: int = x << 1
    let r: int = y >> 1
    return
  }
}
```

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
T, F, PC, SW). The simulator includes built-in routines at 0xFF00 (`print_int`)
and 0xFF03 (`print`), and halts on the `HALT` (0xFF) opcode.

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
