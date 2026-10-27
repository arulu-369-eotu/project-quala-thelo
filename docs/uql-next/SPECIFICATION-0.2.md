# UQL NEXT specification 0.2

Status: implemented reference subset. Compiler `uql-next/0.2.0`; package version
`1.2.0.dev0`. Normative words MUST and MUST NOT define this subset only.

## Grammar

```ebnf
program = "uql", "0.2", ";", "program", identifier, "{",
          "qubits", integer, ";", "bits", integer, ";",
          { contract }, { operation }, "}" ;
contract = "require", resource, "<=", integer, ";"
         | "trust", capability, ";" ;
operation = single, qubit, ";"
          | double, qubit, ",", qubit, ";"
          | "rz", "(", phase, ")", qubit, ";"
          | "measure", qubit, "->", bit, ";" ;
single = "h" | "x" | "y" | "z" | "s" | "t" ;
double = "cx" | "cz" ;
qubit = "q", "[", integer, "]" ;
bit = "c", "[", integer, "]" ;
phase = [ sign ], ("pi" | integer, "*", "pi" | "0"), [ "/", integer ] ;
sign = "+" | "-" ;
```

Whitespace and `//` line comments are ignored between tokens. Identifiers use
ASCII `[A-Za-z_][A-Za-z0-9_]{0,63}`. Integers are unsigned decimal literals with
at most 13 digits and value at most 10^12. Decimal radians, Unicode identifiers,
imports, macros and dynamic evaluation are not supported. `0.2` is the grammar
token sequence `0 . 2`; inter-token whitespace is allowed.

## Static semantics

Qubit count MUST be 1..4096; bit count MUST be 1..qubit count. Indices are
zero-based. Two-qubit operands MUST differ. Every classical output bit MUST be
written exactly once, and a measured qubit MUST NOT be measured again. All
measurements MUST follow all unitary operations; at least one is required.
Unmeasured quantum wires are allowed. All qubits begin in |0>, and measurements
are in the computational basis.

`rz(a*pi/b)` uses exact rational `a/b`, reduced with positive denominator.
Reduced numerator magnitude and denominator are bounded by 10^12. Division by
zero is invalid. Exact Rz semantics are diag(exp(-i*theta/2), exp(i*theta/2)).
The compiler MUST NOT reduce rotations modulo 2*pi: that loses global phase
which can become relative phase under coherent control. This subset does not
provide coherent-control syntax.

H, X, Y, Z, S, T, CX and CZ have their standard unitary meanings. CX's first
operand is the control. Gate order is source order. State index q[0] is the
least significant bit. Result strings are c[bits-1]...c[0], and the measurement
map is part of the circuit identity.

Input is bounded to 1,000,000 UTF-8 bytes and 10,000 operations. Bounds are
rejected explicitly. Syntax accepted by OpenQASM/QIR but not this grammar MUST
NOT be silently accepted as UQL.

## AST, IR and canonical encoding

The pre-optimization AST and compiled IR share the
[JSON Schema](../../citadel-core/schemas/uql-ir-0.2.schema.json). `Program`
validation adds terminal-measurement order, index ranges relative to declarations,
unique writes, exact phase reduction and contract invariants beyond JSON Schema.

Canonical bytes are ASCII JSON with escaped strings, recursively sorted ASCII
object keys, compact separators, no floating-point values, and exactly one final
LF. Array order is retained. Integer values are plain JSON integers. Duplicate
keys and nonfinite constants are rejected. This is a UQL-specific encoding, not a
claim of general RFC 8785 compliance.

`ir_digest = SHA256("uql.ir/0.2" || NUL || canonical(IR))` includes name,
operations, registers and contracts. `circuit_digest` uses domain
`uql.circuit/0.2` over the object containing only qubits, bits and operations.
Names, comments and policies are excluded from circuit identity, while output
mapping and exact phases are retained. The normalized optimized circuit is only
one normal form under the implemented local rewrites; it is not a canonical
representation of every mathematically equivalent quantum program.

Equal circuit hashes establish identical normalized circuit data subject to
hash assumptions and this version's interpretation. They do not attest a
compiler, prove hardware behavior, or decide general equivalence. Unequal
hashes can describe equivalent computations.

## Transformation and resource contracts

The optimizer cancels adjacent identical H/X/Y/Z/CX/CZ gates, removes Rz(0),
and merges adjacent same-wire Rz rotations by exact rational addition. It does
not commute gates or perform approximate synthesis. When rational addition
would exceed representational bounds, the pair is retained. An edit receipt
records the input/output IR digests, rule/version, offset and before/after
operations. A separate rule checker replays each edit. This is local executable
validation of named identities, not a proof-assistant-verified compiler.

`require qubits|gates|depth|two_qubit_gates <= N;` is checked on compiled IR.
Gate count excludes measurements; depth includes them and assigns each
operation duration one, parallelizing disjoint wires. These are structural
counts. Physical qubits, timing and fidelity are unknown. Duplicate or unknown
requirements are errors. `trust reproducible;` is supported; `signed_compiler`,
`attested_backend` and `independent_verifier` parse as capability requests but
MUST fail compilation while those mechanisms are unavailable.

## Lowering and comparison

OpenQASM output declares `stdgates.inc`, static quantum/classical arrays and
terminal measurement assignments. QIR targets 2.0 Base Profile with opaque
pointers, static qubit/result indices, four blocks, initialization, irreversible
measurement declarations and tuple output in descending classical-bit order.
Rz rational angles become binary64 constants in QIR; exact symbolic phase is
retained in UQL-IR and OpenQASM. No device-specific QIS support is implied.

The dependency-free simulator is bounded to 10 qubits and 2,000,000
state-size-times-operation work units. The optional differential runner compares
the emitted OpenQASM through Qiskit's importer and the validated IR through Cirq
against the reference simulator. Its boundary is ideal, zero-input,
terminal-measurement output distributions, using total variation distance. The
runner records SDK versions and tolerance. All adapters are maintained in the
same UQL project; this does not establish organizational independence.

`compare` adds two numerical relations for at most four qubits:
`zero_input_distribution` observes the classical mapping; and
`premeasurement_unitary` enumerates every computational basis column, retains
global phase and excludes terminal measurement mapping. Failures return a
probability discrepancy or a matrix-entry discrepancy respectively. A matrix
discrepancy is not automatically an observable physical counterexample. The
work budget is 2,000,000 matrix-size-times-operation units. These comparisons
are tolerance-limited numerical experiments, not symbolic proofs.

## Evidence bundle and seal

Exactly 14 regular files are allowed: `program.uql`, `ast.json`,
`program.uir.json`, `program.qasm`, `program.ll`, `transforms.json`,
`resources.json`, `qbom.json`, `claims.json`, `passport.json`, `proof369.json`,
`identity.json`, `seal.jpg`, and `manifest.json`. All payloads are hashed with
byte lengths in the manifest; the manifest fingerprint is domain-separated by
`uql.bundle-manifest/0.2`. The compiler identity hashes its Python source module
map under `uql.compiler-source/0.2`. Runtime/platform provenance is outside the
deterministic compiler bundle and belongs in separate execution evidence.

The original Seal of Eotu is included byte-for-byte and named explicitly in
identity metadata and the passport. It is visual identity, not a verification
credential. Its SHA-256 is
`736562814373312a141133bf41a6fe5431bdfd78bce52743332fcae05767df19`.

The verifier restricts the filename set, rejects symbolic links/nonregular files,
checks bounded sizes and all payload hashes, then recompiles the captured source
with the declared optimization option and compares every output byte. It never
executes submitted LLVM. Limits: 8,000,000 bytes per member, 32,000,000 total.
Compilation writes to a fresh directory and refuses existing destinations.
Applications MUST NOT consume partially written output before compilation
returns. The destination directory and ancestors must be under operator control;
this is not a defense against a hostile local administrator.

Without a separately trusted manifest fingerprint, complete source+bundle
replacement can remain self-consistent. `--expect` checks a supplied pin; it
does not create publisher authentication. No signatures, witnesses, attestation,
PROOF-369 network registration or royalty execution are implemented.

`proof369.uql.local/0.1` is a draft local adapter format. The actual external
PROOF-369 protocol and Kundalini Kali implementation were not supplied; no
compatibility or certification is asserted. Unknown external states remain
UNVERIFIED or NOT_PERFORMED even when local rebuild succeeds.
