"""OpenQASM 3.0 and QIR 2.0 Base Profile lowering for the specified subset."""
import math


def phase_text(phase):
    if phase == 0:
        return "0"
    n, d = phase.numerator, phase.denominator
    text = "pi" if n == 1 else "-pi" if n == -1 else f"{n}*pi"
    return text if d == 1 else f"({text})/{d}"


def openqasm(program):
    lines = ["OPENQASM 3.0;", 'include "stdgates.inc";',
             f"qubit[{program.qubits}] q;", f"bit[{program.bits}] c;"]
    for op in program.operations:
        qs = ", ".join(f"q[{q}]" for q in op.qubits)
        if op.gate == "measure":
            lines.append(f"c[{op.bit}] = measure {qs};")
        else:
            name = f"rz({phase_text(op.phase)})" if op.gate == "rz" else op.gate
            lines.append(f"{name} {qs};")
    return "\n".join(lines) + "\n"


def _pointer(n):
    return "ptr null" if n == 0 else f"ptr inttoptr (i64 {n} to ptr)"


def qir(program):
    lines = [f"; UQL NEXT: QIR 2.0 Base Profile, program {program.name}",
             "define i64 @main() #0 {", "initialize:",
             "  call void @__quantum__rt__initialize(ptr null)", "  br label %unitary", "unitary:"]
    declarations = set()
    for op in program.operations:
        if op.gate == "measure":
            continue
        name = "cnot" if op.gate == "cx" else op.gate
        args = [_pointer(q) for q in op.qubits]
        types = ["ptr"] * len(args)
        if op.gate == "rz":
            theta = float(op.phase) * math.pi
            # Fixed-width IEEE binary64 LLVM literal, independent of decimal printing.
            import struct
            args.insert(0, "double 0x" + struct.pack(">d", theta).hex().upper())
            types.insert(0, "double")
        lines.append(f"  call void @__quantum__qis__{name}__body({', '.join(args)})")
        declarations.add(f"declare void @__quantum__qis__{name}__body({', '.join(types)})")
    lines.extend(["  br label %measurements", "measurements:"])
    for op in program.operations:
        if op.gate == "measure":
            lines.append(f"  call void @__quantum__qis__mz__body({_pointer(op.qubits[0])}, {_pointer(op.bit)})")
    lines.extend(["  br label %output", "output:",
                  f"  call void @__quantum__rt__tuple_record_output(i64 {program.bits}, ptr null)"])
    for bit in reversed(range(program.bits)):
        lines.append(f"  call void @__quantum__rt__result_record_output({_pointer(bit)}, ptr null)")
    lines.extend(["  ret i64 0", "}"])
    lines.extend(sorted(declarations))
    lines.extend([
        "declare void @__quantum__qis__mz__body(ptr, ptr writeonly) #1",
        "declare void @__quantum__rt__initialize(ptr)",
        "declare void @__quantum__rt__tuple_record_output(i64, ptr)",
        "declare void @__quantum__rt__result_record_output(ptr, ptr)",
        'attributes #0 = { "entry_point" "qir_profiles"="base_profile" "output_labeling_schema"="" '
        f'"required_num_qubits"="{program.qubits}" "required_num_results"="{program.bits}" }}',
        'attributes #1 = { "irreversible" }',
        '!llvm.module.flags = !{!0, !1, !2, !3}',
        '!0 = !{i32 1, !"qir_major_version", i32 2}',
        '!1 = !{i32 7, !"qir_minor_version", i32 0}',
        '!2 = !{i32 1, !"dynamic_qubit_management", i1 false}',
        '!3 = !{i32 1, !"dynamic_result_management", i1 false}',
    ])
    return "\n".join(lines) + "\n"
