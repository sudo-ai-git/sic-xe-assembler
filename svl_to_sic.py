#!/usr/bin/env python3
"""
SVL → SIC/XE Compiler

Compiles SVL source code to SIC/XE assembly, assembles it with 231-gate
tamper-evident object code, and runs it in the verified simulator.

Pipeline:
  SVL source → lex/parse (svl.lexer + svl.parser_rd) → AST walk → SIC/XE asm
  → Assembler (231-gate stamped H/T/E records) → Simulator.verify_and_load_records
  → sim.run()

Usage:
  python3 svl_to_sic.py <source.svl>
  python3 svl_to_sic.py <source.svl> --emit-asm  # also print assembly
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from svl.lexer import tokenize
from svl.parser_rd import (
    Parser, Program, Module, FuncDecl, Block, LetStmt, IfStmt, WhileStmt,
    ReturnStmt, AssertStmt, ExprStmt, BinaryExpr, UnaryExpr, CallExpr,
    Ident, Literal, TernaryExpr, ForStmt, Param,
    AssignExpr,
)
from sic_xe_assembler_sim import Assembler, Simulator, parse_source


# ═════════════════════════════════════════════════════════════════════════════
# CODE GENERATOR
# ═════════════════════════════════════════════════════════════════════════════

class SICXECodeGen:
    """Walks an SVL AST and emits SIC/XE assembly lines."""

    def __init__(self):
        self.lines = []           # list of (label, opcode, operand, comment)
        self.var_addr = {}        # var name -> memory address
        self.next_var = 16      # variables start at 16 (base-relative, B=0)
        self.string_pool = {}     # string text -> address
        self.next_string = 1024   # strings at 1024
        self.label_n = 0
        # parameter passing area (static, no recursion)
        self.param_addr = {}      # param name -> offset from PARAM_BASE
        self.param_base = 512     # params at 512
        self.next_param = 0
        self.pending_label = None  # label to attach to next emit
        self.in_main = False  # set True when compiling main's body

    # ---------------------------------------------------------------- helpers
    def new_label(self, prefix="L"):
        self.label_n += 1
        return f"{prefix}{self.label_n}"

    def alloc_var(self, name):
        if name not in self.var_addr:
            self.var_addr[name] = self.next_var
            self.next_var += 3
        return self.var_addr[name]

    def alloc_string(self, text):
        if text not in self.string_pool:
            self.string_pool[text] = self.next_string
            self.next_string += len(text) + 1  # +1 for null terminator
        return self.string_pool[text]

    def alloc_param(self, name):
        if name not in self.param_addr:
            self.param_addr[name] = self.next_param
            self.next_param += 3
        return self.param_addr[name]

    def emit(self, opcode, operand="", comment="", label=""):
        if label == "" and self.pending_label is not None:
            label = self.pending_label
            self.pending_label = None
        self.lines.append((label, opcode, operand, comment))

    def emit_addr(self, opcode, addr, comment="", label=""):
        """Emit a memory-reference instruction.
        Uses format 4 (+ prefix) if addr > 4095 (format 3 limit)."""
        if addr > 4095:
            self.emit("+" + opcode, str(addr), comment, label)
        else:
            self.emit(opcode, str(addr), comment, label)

    def emit_comment(self, text):
        """Emit a comment line — does NOT consume pending_label."""
        self.lines.append(("", "", "", text))

    def emit_directive(self, directive, operand="", comment=""):
        self.emit(directive, operand, comment)

    def emit_label(self, label):
        """Attach a label to the NEXT emitted instruction."""
        self.pending_label = label

    # ---------------------------------------------------------------- main
    def compile(self, program: Program):
        """Entry point. Returns list of assembly lines."""
        self.emit("START", "1000", comment="program entry")

        # ---- allocate all variables and strings first (single pass over AST) ----
        self._preallocate(program)

        # ---- Emit ALL runtime subroutines first (so symbols resolve in user code) ----
        self.emit_comment("runtime subroutines and data")
        self._emit_runtime()

        # ---- emit string pool ----
        for text, addr in sorted(self.string_pool.items(), key=lambda x: x[1]):
            bytes_data = text.encode("ascii") + b"\x00"
            hex_str = "".join(f"{b:02X}" for b in bytes_data)
            # Escape newlines and other special chars in comment
            safe_text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            self.emit_comment(f"string @ {addr}: {safe_text!r}")
            self.emit_directive("BYTE", hex_str, comment=f"@ {addr} ({len(bytes_data)} bytes)")

        # ---- compile each module's functions (after runtime, so symbols resolve) ----
        for module in program.modules:
            self._compile_module(module)

        # ---- HALT at the very end ----
        self.emit_label("HALT")
        self.emit("HALT", comment="halt — end of program")

        self.emit("END", "MAIN", comment="entry point")
        return self.lines

    def _preallocate(self, program: Program):
        """Walk AST once to allocate variable and string addresses."""
        for module in program.modules:
            self._preallocate_block(module.body)

    def _preallocate_block(self, block: Block):
        for stmt in block.statements:
            self._preallocate_stmt(stmt)

    def _preallocate_stmt(self, stmt):
        t = stmt.type.value
        if t == "LetStmt":
            self.alloc_var(stmt.name)
            self._preallocate_expr(stmt.value)
        elif t == "IfStmt":
            self._preallocate_expr(stmt.condition)
            self._preallocate_block(stmt.then_branch)
            if stmt.else_branch:
                self._preallocate_block(stmt.else_branch)
        elif t == "WhileStmt":
            self._preallocate_expr(stmt.condition)
            self._preallocate_block(stmt.body)
        elif t == "ReturnStmt":
            if stmt.value:
                self._preallocate_expr(stmt.value)
        elif t == "AssertStmt":
            self._preallocate_expr(stmt.condition)
        elif t == "ExprStmt":
            self._preallocate_expr(stmt.expression)
        elif t == "Block":
            self._preallocate_block(stmt)

    def _preallocate_expr(self, expr):
        if expr is None:
            return
        t = expr.type.value
        if t == "BinaryExpr":
            self._preallocate_expr(expr.left)
            self._preallocate_expr(expr.right)
        elif t == "UnaryExpr":
            self._preallocate_expr(expr.operand)
        elif t == "CallExpr":
            for arg in expr.arguments:
                self._preallocate_expr(arg)
        elif t == "TernaryExpr":
            self._preallocate_expr(expr.condition)
            self._preallocate_expr(expr.then_expr)
            self._preallocate_expr(expr.else_expr)
        elif t == "Ident":
            self.alloc_var(expr.name)
        elif t == "Literal":
            if expr.literal_type == "string":
                self.alloc_string(expr.value)

    # ---------------------------------------------------------------- module
    def _compile_module(self, module: Module):
        self.emit_comment(f"module {module.name}")
        # Sort statements so 'main' compiles first (at START address)
        stmts = list(module.body.statements)
        main_stmts = [s for s in stmts if s.type.value == "FuncDecl" and getattr(s, "name", None) == "main"]
        other_stmts = [s for s in stmts if not (s.type.value == "FuncDecl" and getattr(s, "name", None) == "main")]
        ordered = main_stmts + other_stmts

        # Pre-declare all function labels so forward references resolve
        for stmt in ordered:
            if stmt.type.value == "FuncDecl" and getattr(stmt, "name", None):
                self.emit_label(stmt.name)

        for stmt in ordered:
            self._compile_stmt(stmt)

    # ---------------------------------------------------------------- stmt
    def _compile_stmt(self, stmt):
        t = stmt.type.value
        if t == "LetStmt":
            self._compile_let(stmt)
        elif t == "IfStmt":
            self._compile_if(stmt)
        elif t == "WhileStmt":
            self._compile_while(stmt)
        elif t == "ForStmt":
            self._compile_for(stmt)
        elif t == "ReturnStmt":
            self._compile_return(stmt)
        elif t == "AssertStmt":
            self._compile_assert(stmt)
        elif t == "ExprStmt":
            self._compile_expr_stmt(stmt)
        elif t == "FuncDecl":
            self._compile_func_decl(stmt)
        elif t == "Block":
            for s in stmt.statements:
                self._compile_stmt(s)
        else:
            self.emit_comment(f"unhandled stmt: {stmt.type}")

    def _compile_for(self, stmt: ForStmt):
        """Desugar for loop to while loop:
           for var in expr { body }
           becomes:
           var = expr.start
           while var < expr.end {
             body
             var = var + expr.step
           }
        """
        iter_expr = stmt.iter_expr
        # For now, support simple range: for i in start..end { body }
        # The iter_expr is a BinaryExpr with operator '..'
        if iter_expr.type.value != "BinaryExpr" or iter_expr.operator != "..":
            self.emit_comment("unsupported for loop iterator")
            return
        start_expr = iter_expr.left
        end_expr = iter_expr.right

        # var = start
        self._compile_expr(start_expr)
        self.emit_addr("STA", self.alloc_var(stmt.var), comment=f"init {stmt.var}")

        loop_label = self.new_label("for")
        end_label = self.new_label("endfor")

        self.emit_label(loop_label)
        # while var < end
        self.emit_addr("LDA", self.var_addr[stmt.var], comment=f"load {stmt.var}")
        self.emit("STA", "TMP0", comment="save var")
        self._compile_expr(end_expr)
        self.emit("STA", "TMP1", comment="save end")
        self.emit("LDA", "TMP0", comment="reload var")
        self.emit("COMP", "TMP1", comment=f"compare {stmt.var} < end")
        self.emit("JGT", end_label, comment="exit if var > end")

        # body
        self._compile_block(stmt.body)

        # var = var + step (step defaults to 1)
        self.emit_addr("LDA", self.var_addr[stmt.var], comment=f"load {stmt.var}")
        self.emit("LDA", "#1", comment="load 1")
        self.emit("ADD", "TMP1", comment="var + 1")  # TMP1 still holds end
        # Actually TMP1 was overwritten... let me redo this properly
        # Reset: reload var, add 1, store
        self.emit_addr("LDA", self.var_addr[stmt.var], comment=f"reload {stmt.var}")
        self.emit("ADD", "#1", comment="var + 1")
        self.emit_addr("STA", self.var_addr[stmt.var], comment=f"store {stmt.var}")

        self.emit("J", loop_label, comment="repeat loop")

        self.emit_label(end_label)

    def _compile_func_decl(self, func: FuncDecl):
        """Compile a function declaration to a SIC/XE subroutine."""
        func_name = func.name  # Preserve original case
        self.emit_label(func_name)
        self.emit_comment(f"function {func.name}")

        # Allocate parameter addresses
        for param in func.params:
            self.alloc_param(param.name)

        # Set in_main flag for return handling
        self.in_main = (func.name == "main")

        # Compile function body
        self._compile_block(func.body)

        # If the last statement wasn't a ReturnStmt, add RSUB (or HALT for main)
        if func.body.statements:
            last = func.body.statements[-1]
            if last.type.value != "ReturnStmt":
                if self.in_main:
                    self.emit("HALT", comment="halt")
                else:
                    self.emit("RSUB", comment="implicit return")
        else:
            if self.in_main:
                self.emit("HALT", comment="halt")
            else:
                self.emit("RSUB", comment="empty function")

        self.in_main = False

    def _compile_let(self, stmt: LetStmt):
        addr = self.alloc_var(stmt.name)
        self.emit_comment(f"let {stmt.name} = ...  @ {addr:04X}")
        self._compile_expr(stmt.value)
        self.emit_addr("STA", addr, comment=f"store {stmt.name}")

    def _compile_if(self, stmt: IfStmt):
        end_label = self.new_label("endif")
        else_label = self.new_label("else")

        self._compile_expr(stmt.condition)
        # COMP with 0 — if A == 0, condition is false → jump to else
        self.emit("COMP", "ZERO", comment="condition == 0?")
        self.emit("JEQ", else_label, comment="if false → else")

        self._compile_block(stmt.then_branch)
        self.emit("J", end_label, comment="skip else")

        self.emit_label(else_label)
        if stmt.else_branch:
            self._compile_block(stmt.else_branch)

        self.emit_label(end_label)

    def _compile_while(self, stmt: WhileStmt):
        loop_label = self.new_label("while")
        exit_label = self.new_label("endwhile")

        self.emit_label(loop_label)
        self._compile_expr(stmt.condition)
        self.emit("COMP", "ZERO", comment="condition == 0?")
        self.emit("JEQ", exit_label, comment="exit loop if false")
        self._compile_block(stmt.body)
        self.emit("J", loop_label, comment="repeat")
        self.emit_label(exit_label)

    def _compile_return(self, stmt: ReturnStmt):
        if stmt.value:
            self._compile_expr(stmt.value)
            self.emit("STA", "RETVAL", comment="return value")
        if self.in_main:
            self.emit("HALT", comment="halt — return from main")
        else:
            self.emit("RSUB", comment="return")

    def _compile_assert(self, stmt: AssertStmt):
        self._compile_expr(stmt.condition)
        self.emit("COMP", "ZERO", comment="assert condition == 0?")
        self.emit("JEQ", "ASSERT_FAIL", comment="fail if zero")

    def _compile_expr_stmt(self, stmt: ExprStmt):
        expr = stmt.expression
        if isinstance(expr, AssignExpr):
            self._compile_assign(expr)
        else:
            self._compile_expr(expr)

    def _compile_assign(self, expr: AssignExpr):
        """Compile assignment expression: target = value or target op= value."""
        target = expr.target
        op = expr.operator
        value = expr.value

        target_name = target.name if isinstance(target, Ident) else str(target)

        if op == "=":
            # Simple assignment: x = value
            self._compile_expr(value)
            addr = self.alloc_var(target_name)
            self.emit_addr("STA", addr, comment=f"store {target_name}")
        else:
            # Compound assignment: x op= value  =>  x = x op value
            # Map compound ops to base ops
            op_map = {
                "+=": "+",
                "-=": "-",
                "*=": "*",
                "/=": "/",
                "%=": "%",
                "&=": "&",
                "|=": "|",
                "^=": "^",
                "<<=": "<<",
                ">>=": ">>",
            }
            base_op = op_map.get(op)
            if base_op is None:
                self.emit_comment(f"unhandled compound assign: {op}")
                return

            # Load current value of target
            self.emit_addr("LDA", self.alloc_var(target_name), comment=f"load {target_name}")
            self.emit("STA", "TMP0", comment="save target")
            # Load right operand
            self._compile_expr(value)
            self.emit("STA", "TMP1", comment="save right")
            self.emit("LDA", "TMP0", comment="reload target")

            # Perform operation
            if base_op == "+":
                self.emit("ADD", "TMP1", comment=f"{target_name} + right")
            elif base_op == "-":
                self.emit("SUB", "TMP1", comment=f"{target_name} - right")
            elif base_op == "*":
                self.emit("MUL", "TMP1", comment=f"{target_name} * right")
            elif base_op == "/":
                self.emit("DIV", "TMP1", comment=f"{target_name} / right")
            elif base_op == "%":
                self.emit("STA", "MOD_ARG", comment="set mod divisor")
                self.emit("LDA", "TMP0", comment="left operand")
                self.emit("JSUB", "MOD", comment=f"{target_name} % right")
            elif base_op == "&":
                self.emit("AND", "TMP1", comment=f"{target_name} & right")
            elif base_op == "|":
                self.emit("OR", "TMP1", comment=f"{target_name} | right")
            elif base_op == "^":
                self.emit("STA", "XOR_ARG", comment="set xor mask")
                self.emit("LDA", "TMP0", comment="left operand")
                self.emit("JSUB", "XOR", comment=f"{target_name} ^ right")
            elif base_op == "<<":
                self.emit("STA", "SHL_ARG", comment="set shl amount")
                self.emit("LDA", "TMP0", comment="value to shift")
                self.emit("JSUB", "SHL", comment=f"{target_name} << right")
            elif base_op == ">>":
                self.emit("STA", "SHR_ARG", comment="set shr amount")
                self.emit("LDA", "TMP0", comment="value to shift")
                self.emit("JSUB", "SHR", comment=f"{target_name} >> right")

            # Store result back to target
            addr = self.alloc_var(target_name)
            self.emit_addr("STA", addr, comment=f"store {target_name}")

    # ---------------------------------------------------------------- expr
    def _compile_expr(self, expr):
        if expr is None:
            return
        if isinstance(expr, Literal):
            self._compile_literal(expr)
        elif isinstance(expr, Ident):
            self._compile_ident(expr)
        elif isinstance(expr, BinaryExpr):
            self._compile_binary(expr)
        elif isinstance(expr, UnaryExpr):
            self._compile_unary(expr)
        elif isinstance(expr, CallExpr):
            self._compile_call(expr)
        elif isinstance(expr, TernaryExpr):
            self._compile_ternary(expr)
        elif isinstance(expr, AssignExpr):
            self._compile_assign(expr)
        else:
            self.emit_comment(f"unhandled expr: {type(expr).__name__}")

    def _compile_literal(self, expr: Literal):
        lt = expr.literal_type
        v = expr.value
        if lt == "int":
            self.emit("LDA", f"#{v}", comment=f"load {v}")
        elif lt == "string":
            addr = self.alloc_string(v)
            self.emit("LDA", f"#{addr}", comment=f'load string addr "{v}"')
        elif lt == "bool":
            self.emit("LDA", f"#{1 if v else 0}", comment=f"load bool {v}")
        else:
            self.emit_comment(f"unhandled literal type: {lt}")

    def _compile_ident(self, expr: Ident):
        name = expr.name
        if name in self.param_addr:
            # parameter — load from param area
            offset = self.param_addr[name]
            self.emit_addr("LDA", self.param_base + offset, comment=f"load param {name}")
        else:
            addr = self.alloc_var(name)
            self.emit_addr("LDA", addr, comment=f"load {name}")

    def _compile_binary(self, expr: BinaryExpr):
        op = expr.operator
        left = expr.left
        right = expr.right

        # For comparisons, use COMP + conditional
        if op in ("==", "!=", "<", ">", "<=", ">="):
            self._compile_expr(left)
            self.emit("STA", "TMP0", comment="save left")
            self._compile_expr(right)
            self.emit("STA", "TMP1", comment="save right")
            self.emit("LDA", "TMP0", comment="reload left")
            self.emit("COMP", "TMP1", comment=f"compare {op}")
            self.emit_comment(f"SW set for {op} comparison")
            return

        # For arithmetic/bitwise, load left into A
        self._compile_expr(left)
        self.emit("STA", "TMP0", comment="save left")
        self._compile_expr(right)
        # Now A = right, TMP0 = left
        self.emit("STA", "TMP1", comment="save right")
        self.emit("LDA", "TMP0", comment="reload left")

        op_map = {
            "+": "ADD",
            "-": "SUB",
            "*": "MUL",
            "/": "DIV",
            "&": "AND",
            "|": "OR",
        }
        if op in op_map:
            self.emit(op_map[op], "TMP1", comment=f"{op} right")
        elif op == "%":
            self.emit("STA", "TMP1", comment="right operand")
            self.emit("LDA", "TMP0", comment="left operand")
            self.emit("STA", "MOD_ARG", comment="set mod divisor")
            self.emit("JSUB", "MOD", comment="A = left % right")
        elif op == "<<":
            self.emit("STA", "TMP1", comment="shift amount")
            self.emit("LDA", "TMP0", comment="value to shift")
            self.emit("STA", "SHL_ARG", comment="set shl amount")
            self.emit("JSUB", "SHL", comment="A = left << right")
        elif op == ">>":
            self.emit("STA", "TMP1", comment="shift amount")
            self.emit("LDA", "TMP0", comment="value to shift")
            self.emit("STA", "SHR_ARG", comment="set shr amount")
            self.emit("JSUB", "SHR", comment="A = left >> right")
        elif op == "^":
            self.emit("STA", "TMP1", comment="xor right")
            self.emit("LDA", "TMP0", comment="left operand")
            self.emit("STA", "XOR_ARG", comment="set xor mask")
            self.emit("JSUB", "XOR", comment="A = left ^ right")
        else:
            self.emit_comment(f"unhandled binary op: {op}")

    def _compile_unary(self, expr: UnaryExpr):
        op = expr.operator
        self._compile_expr(expr.operand)

        if op == "-":
            self.emit("STA", "TMP0", comment="save operand")
            self.emit("LDA", "#0", comment="0 - operand")
            self.emit("SUB", "TMP0", comment="negate")
        elif op == "~":
            self.emit("STA", "NOT_ARG", comment="set not operand")
            self.emit("JSUB", "NOT", comment="A = ~operand")
        elif op == "!":
            self.emit("STA", "TMP0", comment="save operand")
            self.emit("COMP", "#0", comment="is operand zero?")
            self.emit("LDA", "#0", comment="default false")
            self.emit("JEQ", "DONE_NOT", comment="if zero → not is true")
            self.emit("LDA", "#1", comment="not zero → not is false")
            self.emit_label("DONE_NOT")
        else:
            self.emit_comment(f"unhandled unary op: {op}")

    def _compile_ternary(self, expr: TernaryExpr):
        end_label = self.new_label("endtern")
        else_label = self.new_label("ternelse")

        self._compile_expr(expr.condition)
        self.emit("COMP", "#0", comment="condition == 0?")
        self.emit("JEQ", else_label, comment="if false → else branch")
        self._compile_expr(expr.then_expr)
        self.emit("STA", "TERN_RESULT", comment="save then result")
        self.emit("J", end_label, comment="skip else")

        self.emit_label(else_label)
        self._compile_expr(expr.else_expr)
        self.emit("STA", "TERN_RESULT", comment="save else result")

        self.emit_label(end_label)
        self.emit("LDA", "TERN_RESULT", comment="load ternary result")

    def _compile_call(self, expr: CallExpr):
        callee = expr.callee
        args = expr.arguments

        # Built-in calls
        if callee == "print_int":
            if args:
                self._compile_expr(args[0])
                self.emit("JSUB", "PRINT_INT", comment="print_int(arg)")
            return
        if callee == "print":
            if args:
                self._compile_expr(args[0])
                self.emit("JSUB", "PRINT", comment="print(string)")
            return

        # User function call — pass params via static area
        param_index = 0
        for arg in args:
            self._compile_expr(arg)
            self.emit_addr("STA", self.param_base + param_index, comment=f"param[{param_index}]")
            param_index += 3

        self.emit("JSUB", callee, comment=f"call {callee}")

    # ---------------------------------------------------------------- block
    def _compile_block(self, block: Block):
        for stmt in block.statements:
            self._compile_stmt(stmt)

    # ---------------------------------------------------------------- runtime
    def _emit_runtime(self):
        """Emit runtime subroutines: MOD, SHL, SHR, XOR, NOT, PRINT_INT, PRINT,
        ZERO (constant 0), RETVAL, TMP0, TMP1, etc."""

        self.emit_comment("runtime subroutines and data")

        # ---- ZERO constant ----
        self.emit_label("ZERO")
        self.emit_directive("WORD", "0", comment="constant 0")

        # ---- RETVAL ----
        self.emit_label("RETVAL")
        self.emit_directive("WORD", "0", comment="return value")

        # ---- TMP0, TMP1 ----
        self.emit_label("TMP0")
        self.emit_directive("WORD", "0", comment="temp 0")
        self.emit_label("TMP1")
        self.emit_directive("WORD", "0", comment="temp 1")

        # ---- MOD_ARG, SHL_ARG, SHR_ARG, XOR_ARG, NOT_ARG ----
        for label in ("MOD_ARG", "SHL_ARG", "SHR_ARG", "XOR_ARG", "NOT_ARG"):
            self.emit_label(label)
            self.emit_directive("WORD", "0", comment=f"arg for {label}")

        # ---- TERN_RESULT ----
        self.emit_label("TERN_RESULT")
        self.emit_directive("WORD", "0", comment="ternary result")

        # ================================================================
        # MOD: A = A % MOD_ARG  (A is dividend, MOD_ARG is divisor)
        # Simple repeated subtraction (works for small non-negative values)
        # ================================================================
        self.emit_label("MOD")
        self.emit("STA", "MOD_DIVIDEND", comment="save dividend")
        self.emit("LDA", "MOD_ARG", comment="load divisor")
        self.emit("STA", "MOD_DIVISOR", comment="save divisor")
        self.emit("LDA", "MOD_DIVIDEND", comment="reload dividend")
        self.emit_label("MOD_LOOP")
        self.emit("STA", "MOD_REM", comment="save current remainder")
        self.emit("SUB", "MOD_DIVISOR", comment="subtract divisor")
        self.emit("JLT", "MOD_DONE", comment="if negative → done")
        self.emit("LDA", "MOD_REM", comment="reload")
        self.emit("SUB", "MOD_DIVISOR", comment="subtract again")
        self.emit("JGE", "MOD_LOOP", comment="if still >= divisor → loop")
        # fell through: result is MOD_REM + divisor (overshot by one)
        self.emit("LDA", "MOD_REM", comment="load last positive remainder")
        self.emit("ADD", "MOD_DIVISOR", comment="add back divisor")
        self.emit("J", "MOD_EXIT")
        self.emit_label("MOD_DONE")
        self.emit("LDA", "MOD_REM", comment="remainder is correct")
        self.emit_label("MOD_EXIT")
        self.emit("RSUB", comment="return from MOD")
        self.emit_label("MOD_DIVIDEND")
        self.emit_directive("WORD", "0")
        self.emit_label("MOD_DIVISOR")
        self.emit_directive("WORD", "0")
        self.emit_label("MOD_REM")
        self.emit_directive("WORD", "0")

        # ================================================================
        # SHL: A = A << SHL_ARG
        # ================================================================
        self.emit_label("SHL")
        self.emit("STA", "SHL_VALUE", comment="save value")
        self.emit("LDA", "SHL_ARG", comment="load shift count")
        self.emit("STA", "SHL_COUNT", comment="save count")
        self.emit("LDA", "SHL_VALUE", comment="reload value")
        self.emit_label("SHL_LOOP")
        self.emit("COMP", "#0", comment="count == 0?")
        self.emit("JEQ", "SHL_DONE", comment="done if zero")
        self.emit("ADD", "SHL_VALUE", comment="value = value * 2 (<<1)")
        self.emit("STA", "SHL_VALUE", comment="save value")
        self.emit("LDA", "SHL_COUNT", comment="load count")
        self.emit("SUB", "#1", comment="count -= 1")
        self.emit("STA", "SHL_COUNT", comment="save count")
        self.emit("J", "SHL_LOOP")
        self.emit_label("SHL_DONE")
        self.emit("LDA", "SHL_VALUE", comment="result")
        self.emit("RSUB", comment="return from SHL")
        self.emit_label("SHL_VALUE")
        self.emit_directive("WORD", "0")
        self.emit_label("SHL_COUNT")
        self.emit_directive("WORD", "0")

        # ================================================================
        # SHR: A = A >> SHR_ARG
        # ================================================================
        self.emit_label("SHR")
        self.emit("STA", "SHR_VALUE", comment="save value")
        self.emit("LDA", "SHR_ARG", comment="load shift count")
        self.emit("STA", "SHR_COUNT", comment="save count")
        self.emit("LDA", "SHR_VALUE", comment="reload value")
        self.emit_label("SHR_LOOP")
        self.emit("COMP", "#0", comment="count == 0?")
        self.emit("JEQ", "SHR_DONE", comment="done if zero")
        # integer divide by 2: SUB repeatedly or use DIV #2
        self.emit("STA", "SHR_TMP", comment="save value")
        self.emit("LDA", "#0", comment="0 - value/2 via repeated sub")
        # Simpler: just DIV by 2
        self.emit("LDA", "SHR_VALUE", comment="reload")
        self.emit("DIV", "#2", comment="divide by 2")
        self.emit("STA", "SHR_VALUE", comment="save")
        self.emit("LDA", "SHR_COUNT", comment="load count")
        self.emit("SUB", "#1", comment="count -= 1")
        self.emit("STA", "SHR_COUNT", comment="save count")
        self.emit("J", "SHR_LOOP")
        self.emit_label("SHR_DONE")
        self.emit("LDA", "SHR_VALUE", comment="result")
        self.emit("RSUB", comment="return from SHR")
        self.emit_label("SHR_VALUE")
        self.emit_directive("WORD", "0")
        self.emit_label("SHR_COUNT")
        self.emit_directive("WORD", "0")
        self.emit_label("SHR_TMP")
        self.emit_directive("WORD", "0")

        # ================================================================
        # XOR: A = A ^ XOR_ARG
        # ================================================================
        self.emit_label("XOR")
        self.emit("STA", "XOR_LEFT", comment="save left")
        self.emit("LDA", "XOR_ARG", comment="load right")
        self.emit("STA", "XOR_RIGHT", comment="save right")
        # XOR via AND/OR/NOT: (A & ~B) | (~A & B)
        self.emit("LDA", "XOR_LEFT", comment="left")
        self.emit("STA", "XOR_T1", comment="t1 = left")
        self.emit("LDA", "XOR_RIGHT", comment="right")
        self.emit("STA", "XOR_T2", comment="t2 = right")
        self.emit("LDA", "XOR_T1", comment="t1")
        self.emit("AND", "XOR_T2", comment="t1 & t2")
        self.emit("STA", "XOR_T3", comment="t3 = t1 & t2")
        self.emit("LDA", "XOR_T1", comment="t1")
        self.emit("STA", "NOT_ARG", comment="set not arg")
        self.emit("JSUB", "NOT", comment="~t1")
        self.emit("STA", "XOR_T4", comment="t4 = ~t1")
        self.emit("LDA", "XOR_T2", comment="t2")
        self.emit("STA", "NOT_ARG", comment="set not arg")
        self.emit("JSUB", "NOT", comment="~t2")
        self.emit("STA", "XOR_T5", comment="t5 = ~t2")
        self.emit("LDA", "XOR_T4", comment="~t1")
        self.emit("AND", "XOR_T5", comment="~t1 & ~t2... wait that's wrong")
        # Actually: XOR = (A | B) & (~A | ~B) ... simpler:
        # XOR = (A & ~B) | (~A & B)
        self.emit("LDA", "XOR_T1", comment="left")
        self.emit("AND", "XOR_T5", comment="left & ~right")
        self.emit("STA", "XOR_T6", comment="t6 = left & ~right")
        self.emit("LDA", "XOR_T4", comment="~left")
        self.emit("AND", "XOR_T2", comment="~left & right")
        self.emit("STA", "XOR_T7", comment="t7 = ~left & right")
        self.emit("LDA", "XOR_T6", comment="t6")
        self.emit("OR", "XOR_T7", comment="t6 | t7")
        self.emit("RSUB", comment="return from XOR")
        self.emit_label("XOR_LEFT")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_RIGHT")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_T1")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_T2")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_T3")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_T4")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_T5")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_T6")
        self.emit_directive("WORD", "0")
        self.emit_label("XOR_T7")
        self.emit_directive("WORD", "0")

        # ================================================================
        # NOT: A = ~NOT_ARG
        # ================================================================
        self.emit_label("NOT")
        self.emit("STA", "NOT_VAL", comment="save value")
        self.emit("LDA", "#0", comment="0")
        self.emit("SUB", "NOT_VAL", comment="0 - val = -val")
        self.emit("SUB", "NOT_VAL", comment="-val - val = -2*val... wrong")
        # ~A = -A - 1 (two's complement)
        self.emit("LDA", "NOT_VAL", comment="reload")
        self.emit("STA", "NOT_TMP", comment="tmp")
        self.emit("LDA", "#0", comment="0")
        self.emit("SUB", "NOT_TMP", comment="0 - val")
        self.emit("SUB", "#1", comment="-1")
        self.emit("RSUB", comment="return from NOT")
        self.emit_label("NOT_VAL")
        self.emit_directive("WORD", "0")
        self.emit_label("NOT_TMP")
        self.emit_directive("WORD", "0")

        # ================================================================
        # ASSERT_FAIL
        # ================================================================
        self.emit_label("ASSERT_FAIL")
        self.emit("LDA", "#0", comment="assert failed")
        self.emit("JSUB", "PRINT_INT", comment="print 0 (failure)")
        self.emit("RSUB", comment="halt")

        # ================================================================
        # PRINT_INT: print value in A register
        # Simulator built-in at address 0xFF00
        # ================================================================
        self.emit_label("PRINT_INT")
        # This is a simulator built-in. We emit a JSUB to it.
        # The simulator intercepts JSUB to 0xFF00.
        self.emit("+JSUB", "65280", comment="print_int(A) — simulator builtin")
        self.emit("RSUB", comment="return")

        # ================================================================
        # PRINT: print null-terminated string at address in A
        # Simulator built-in at address 0xFF03
        # ================================================================
        self.emit_label("PRINT")
        self.emit("+JSUB", "65283", comment="print(A) — simulator builtin")
        self.emit("RSUB", comment="return")


# ═════════════════════════════════════════════════════════════════════════════
# ASSEMBLY → OBJECT CODE
# ═════════════════════════════════════════════════════════════════════════════

def assembly_to_source(lines):
    """Convert assembly lines to source text parseable by parse_source()."""
    out = []
    for label, opcode, operand, comment in lines:
        # Comment-only lines: output with . prefix so parse_source skips them
        if not opcode:
            if comment:
                # Escape newlines in comments to avoid breaking assembly lines
                safe_comment = comment.replace("\n", "\\n").replace("\r", "\\r")
                out.append(f". {safe_comment}")
            continue
        parts = []
        if label:
            parts.append(label)
        parts.append(opcode)
        if operand:
            parts.append(operand)
        line = " ".join(parts)
        if comment:
            safe_comment = comment.replace("\n", "\\n").replace("\r", "\\r")
            line = line + " . " + safe_comment
        out.append(line)
    return "\n".join(out)


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 svl_to_sic.py <source.svl> [--emit-asm]")
        return 1

    source_path = Path(sys.argv[1])
    emit_asm = "--emit-asm" in sys.argv

    # Read SVL source
    svl_text = source_path.read_text()

    # Tokenize and parse
    tokens = tokenize(svl_text)
    parser = Parser(tokens)
    ast = parser.parse()

    # Compile to SIC/XE assembly
    codegen = SICXECodeGen()
    asm_lines = codegen.compile(ast)

    if emit_asm:
        print("=" * 70)
        print("SIC/XE ASSEMBLY OUTPUT")
        print("=" * 70)
        for label, opcode, operand, comment in asm_lines:
            parts = []
            if label:
                parts.append(f"{label}:")
            if opcode:
                parts.append(opcode)
            if operand:
                parts.append(operand)
            if comment:
                parts.append(f". {comment}")
        print(assembly_to_source(asm_lines))

    # Convert assembly to source text for our Assembler
    asm_text = assembly_to_source(asm_lines)

    # Assemble with 231-gate stamping
    src_lines = parse_source(asm_text)
    asm = Assembler(src_lines)
    sym_path = str(source_path.with_suffix(".sym"))
    success, records = asm.assemble(write_symbol_file_path=sym_path)

    if not success:
        print("ASSEMBLY FAILED:")
        for err in asm.errors:
            print(f"  {err}")
        return 1

    print(f"\nSymbol table: {len(asm.symtab)} symbols")
    print(f"Object records: {len(records['T'])} T records")

    # Print object records
    print(f"  H: {records['H']}")
    for t in records["T"]:
        print(f"  T: {t[:80]}..." if len(t) > 80 else f"  T: {t}")
    print(f"  E: {records['E']}")

    # Simulate with 231-gate verification
    print("\n--- Simulation Trace (231-gate verified load) ---")
    sim = Simulator()
    try:
        start = sim.verify_and_load_records(records)
        print(f"  231-gate verification PASSED — entry at {start:06X}")
    except ValueError as e:
        print(f"  231-gate verification FAILED: {e}")
        return 1

    trace = sim.run()

    for line in trace:
        print(line)

    print("\n--- Final Register State ---")
    for reg in ["A", "X", "L", "B", "S", "T", "F", "PC", "SW"]:
        print(f"  {reg} = {sim.regs[reg]:06X}")

    print("\n" + "=" * 70)
    print("SVL → SIC/XE → 231-gate verified object code → executed")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
