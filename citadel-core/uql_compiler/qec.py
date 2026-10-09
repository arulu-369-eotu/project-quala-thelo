"""Rotated surface-code lattice and repeated syndrome extraction.

The layout is the standard planar rotated [[d^2, 1, d]] family for odd
distance d: d^2 data qubits and d^2-1 independent X/Z stabilizers. Boundary
checks have weight two; interior checks have weight four.

This module constructs the measurement circuit and exposes syndrome records.
It intentionally does not pretend to be a decoder or a fault-tolerance proof:
logical performance must be established against an explicit circuit-level noise
model and decoder.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import cirq

Pauli = Literal["X", "Z"]


@dataclass(frozen=True)
class Stabilizer:
    kind: Pauli
    data: tuple[tuple[int, int], ...]

    @property
    def weight(self) -> int:
        return len(self.data)


class SurfaceCode:
    """A planar rotated surface-code patch encoding one logical qubit."""

    def __init__(self, distance: int = 3):
        if distance < 3 or distance % 2 == 0:
            raise ValueError("distance must be an odd integer >= 3")
        self.distance = distance
        self.data_coords = tuple((r, c) for r in range(distance) for c in range(distance))
        self.x_checks = self._checks("X")
        self.z_checks = self._checks("Z")
        self.stabilizers = self.x_checks + self.z_checks
        if len(self.stabilizers) != distance * distance - 1:
            raise RuntimeError("invalid surface-code stabilizer count")
        self.ancilla_coords = tuple((check.kind, index) for index, check in enumerate(self.stabilizers))

    def _checks(self, kind: Pauli) -> tuple[Stabilizer, ...]:
        checks: list[Stabilizer] = []
        parity = 1 if kind == "X" else 0

        for r in range(self.distance - 1):
            for c in range(self.distance - 1):
                if (r + c) % 2 == parity:
                    checks.append(Stabilizer(
                        kind,
                        ((r, c), (r, c + 1), (r + 1, c), (r + 1, c + 1)),
                    ))

        # Alternating boundary half-plaquettes preserve X/Z commutation.
        if kind == "X":
            for c in range(0, self.distance - 1, 2):
                checks.append(Stabilizer(kind, ((0, c), (0, c + 1))))
            for c in range(1, self.distance - 1, 2):
                checks.append(Stabilizer(kind, ((self.distance - 1, c),
                                               (self.distance - 1, c + 1))))
        else:
            for r in range(1, self.distance - 1, 2):
                checks.append(Stabilizer(kind, ((r, 0), (r + 1, 0))))
            for r in range(0, self.distance - 1, 2):
                checks.append(Stabilizer(kind, ((r, self.distance - 1),
                                               (r + 1, self.distance - 1))))

        return tuple(checks)

    @property
    def num_data_qubits(self) -> int:
        return self.distance * self.distance

    @property
    def num_ancillas(self) -> int:
        return self.distance * self.distance - 1

    @property
    def parameters(self) -> tuple[int, int, int]:
        return (self.num_data_qubits, 1, self.distance)

    def logical_x(self) -> tuple[tuple[int, int], ...]:
        return tuple((r, self.distance // 2) for r in range(self.distance))

    def logical_z(self) -> tuple[tuple[int, int], ...]:
        return tuple((self.distance // 2, c) for c in range(self.distance))

    def validate(self) -> None:
        if len(self.x_checks) != len(self.z_checks):
            raise RuntimeError("X/Z stabilizer sectors must have equal rank")
        for x_check in self.x_checks:
            for z_check in self.z_checks:
                if len(set(x_check.data) & set(z_check.data)) % 2:
                    raise RuntimeError("X/Z stabilizers do not commute")
        if len(self.logical_x()) != self.distance or len(self.logical_z()) != self.distance:
            raise RuntimeError("logical operators have incorrect distance")

    def _qubits(self):
        data = {coord: cirq.GridQubit(*coord) for coord in self.data_coords}
        anc = {
            key: cirq.GridQubit(self.distance + 2 + index, 0 if key[0] == "X" else 1)
            for index, key in enumerate(self.ancilla_coords)
        }
        return data, anc

    def build_circuit(self, rounds: int = 1) -> cirq.Circuit:
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        self.validate()
        data, anc = self._qubits()
        circuit = cirq.Circuit()

        for round_index in range(rounds):
            circuit.append(cirq.reset_each(*anc.values()))
            for index, check in enumerate(self.stabilizers):
                a = anc[(check.kind, index)]
                if check.kind == "X":
                    circuit.append(cirq.H(a))
                    for coord in check.data:
                        circuit.append(cirq.CNOT(a, data[coord]))
                    circuit.append(cirq.H(a))
                else:
                    for coord in check.data:
                        circuit.append(cirq.CNOT(data[coord], a))
                circuit.append(cirq.measure(a, key=f"{check.kind}_{index}_r{round_index}"))
        return circuit

    def syndrome_keys(self, rounds: int) -> tuple[str, ...]:
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        return tuple(
            f"{check.kind}_{index}_r{round_index}"
            for round_index in range(rounds)
            for index, check in enumerate(self.stabilizers)
        )
