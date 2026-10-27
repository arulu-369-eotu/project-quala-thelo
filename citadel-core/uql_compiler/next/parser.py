"""Small explicit grammar. No eval, dynamic includes, or backend execution."""
from fractions import Fraction
import re

from .model import (MAX_SOURCE_BYTES, MAX_OPERATIONS, MAX_PHASE_INTEGER,
                    GATE_ARITY, Operation, Program, UQLError)

TOKEN = re.compile(r"\s+|//[^\n]*|->|<=|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[{}\[\];,()*/+.-]")


class Parser:
    def __init__(self, source):
        if type(source) is not str or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise UQLError("source exceeds size limit or is not text")
        self.tokens = []
        pos = 0
        for match in TOKEN.finditer(source):
            if match.start() != pos:
                raise UQLError(f"invalid character at offset {pos}")
            value = match.group()
            if not value.isspace() and not value.startswith("//"):
                self.tokens.append((value, match.start()))
            pos = match.end()
        if pos != len(source):
            raise UQLError(f"invalid character at offset {pos}")
        self.tokens.append(("<eof>", len(source)))
        self.i = 0

    def peek(self):
        return self.tokens[self.i][0]

    def take(self, expected=None):
        value, offset = self.tokens[self.i]
        if expected is not None and value != expected:
            raise UQLError(f"expected {expected!r}, got {value!r} at offset {offset}")
        if value == "<eof>":
            raise UQLError(f"unexpected end of source at offset {offset}")
        self.i += 1
        return value

    def number(self):
        value = self.take()
        if not value.isascii() or not value.isdigit() or len(value) > 13:
            raise UQLError("expected bounded unsigned integer")
        n = int(value)
        if n > MAX_PHASE_INTEGER:
            raise UQLError("integer literal exceeds limit")
        return n

    def index(self, kind):
        self.take(kind)
        self.take("[")
        n = self.number()
        self.take("]")
        return n

    def angle(self):
        sign = 1
        if self.peek() in ("+", "-"):
            sign = -1 if self.take() == "-" else 1
        if self.peek() == "pi":
            self.take()
            n = 1
        else:
            n = self.number()
            if self.peek() == "*":
                self.take()
                self.take("pi")
            elif n != 0:
                raise UQLError("angles must be rational multiples of pi")
        d = 1
        if self.peek() == "/":
            self.take()
            d = self.number()
        if d == 0:
            raise UQLError("zero phase denominator")
        return Fraction(sign * n, d)

    def program(self):
        for token in ("uql", "0", ".", "2", ";", "program"):
            self.take(token)
        name = self.take()
        self.take("{")
        self.take("qubits")
        qubits = self.number()
        self.take(";")
        self.take("bits")
        bits = self.number()
        self.take(";")
        requirements, trust, operations = [], [], []
        while self.peek() in ("require", "trust"):
            kind = self.take()
            key = self.take()
            if kind == "require":
                self.take("<=")
                requirements.append((key, self.number()))
            else:
                trust.append(key)
            self.take(";")
        while self.peek() != "}":
            gate = self.take()
            if gate not in GATE_ARITY:
                raise UQLError(f"unsupported instruction: {gate}")
            phase = None
            if gate == "rz":
                self.take("(")
                phase = self.angle()
                self.take(")")
            qs = [self.index("q")]
            if GATE_ARITY[gate] == 2:
                self.take(",")
                qs.append(self.index("q"))
            bit = None
            if gate == "measure":
                self.take("->")
                bit = self.index("c")
            self.take(";")
            operations.append(Operation(gate, tuple(qs), phase, bit))
            if len(operations) > MAX_OPERATIONS:
                raise UQLError("operation limit exceeded")
        self.take("}")
        if self.peek() != "<eof>":
            raise UQLError("trailing source text")
        return Program(name, qubits, bits, tuple(operations), tuple(requirements), tuple(trust))


def parse(source: str) -> Program:
    return Parser(source).program()
