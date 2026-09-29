"""Rotated-style surface-code syndrome extraction in Cirq.

The implementation constructs a small planar stabilizer lattice, emits repeated
syndrome-extraction rounds, and exposes boundary logical X/Z strings. It is a
circuit construction and simulator component; it does not claim fault-tolerant
logical error rates without a calibrated noise model and decoder.
"""

from __future__ import annotations

from dataclasses import dataclass

import cirq


@dataclass(frozen=True)
class Stabilizer:
    kind: str
    data: tuple[tuple[int, int], ...]


class SurfaceCode:
    def __init__(self, distance: int = 3):
        if distance < 3 or distance % 2 == 0:
            raise ValueError("distance must be an odd integer >= 3")
        self.distance = distance
        self.data_coords = tuple(
            (r, c) for r in range(distance) for c in range(distance)
        )
        self.x_checks = self._checks("X")
        self.z_checks = self._checks("Z")
        self.ancilla_coords = tuple(
            (kind, r, c)
            for kind, checks in (("X", self.x_checks), ("Z", self.z_checks))
            for r, c in checks
        )

    def _checks(self, kind: str) -> tuple[Stabilizer, ...]:
        checks = []
        # Plaquette checks are offset by parity; boundary checks are omitted,
        # giving a planar patch with open X/Z boundaries.
        for r in range(self.distance - 1):
            for c in range(self.distance - 1):
                if (r + c) % 2 == (0 if kind == "Z" else 1):
                    cells = ((r, c), (r + 1, c), (r, c + 1), (r + 1, c + 1))
                    checks.append(Stabilizer(kind, cells))
        return tuple(checks)

    @property
    def num_data_qubits(self) -> int:
        return len(self.data_coords)

    @property
    def num_ancillas(self) -> int:
        return len(self.ancilla_coords)

    def logical_x(self) -> tuple[tuple[int, int], ...]:
        return tuple((r, self.distance // 2) for r in range(self.distance))

    def logical_z(self) -> tuple[tuple[int, int], ...]:
        return tuple((self.distance // 2, c) for c in range(self.distance))

    def build_circuit(self, rounds: int = 1) -> cirq.Circuit:
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        data = {coord: cirq.GridQubit(*coord) for coord in self.data_coords}
        anc = {
            key: cirq.GridQubit(self.distance + 2 + r, c)
            for key, r, c in self.ancilla_coords
        }
        circuit = cirq.Circuit()

        for _round in range(rounds):
            circuit.append(cirq.Moment(cirq.ResetChannel()(q) for q in anc.values()))

            for index, check in enumerate(self.x_checks):
                a = anc[("X", *check.data[0])]
                circuit.append(cirq.H(a))
                for coord in check.data:
                    circuit.append(cirq.CNOT(a, data[coord]))
                circuit.append(cirq.H(a))
                circuit.append(cirq.measure(a, key=f"X_{index}_r{_round}"))

            for index, check in enumerate(self.z_checks):
                a = anc[("Z", *check.data[0])]
                for coord in check.data:
                    circuit.append(cirq.CNOT(data[coord], a))
                circuit.append(cirq.measure(a, key=f"Z_{index}_r{_round}"))

        return circuit
