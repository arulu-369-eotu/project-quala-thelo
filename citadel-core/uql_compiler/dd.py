"""Coherence-aware dynamical-decoupling scheduling for Qiskit 2.x.

The compiler inserts timed refocusing gates into real idle windows after
scheduling. Gate durations are explicit so the resulting timing is auditable.
A backend's calibrated Target/InstructionDurations should be supplied for
hardware execution; the local profile exists for deterministic simulation and
testing.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from qiskit.circuit import QuantumCircuit
from qiskit.circuit.library import XGate
from qiskit.transpiler import InstructionDurations, PassManager
from qiskit.transpiler.passes import ALAPScheduleAnalysis, PadDynamicalDecoupling


@dataclass(frozen=True)
class CoherenceModel:
    t1_us: float
    t2_us: float

    def __post_init__(self) -> None:
        if self.t1_us <= 0 or self.t2_us <= 0:
            raise ValueError("T1 and T2 must be positive")

    @property
    def effective_coherence_us(self) -> float:
        return min(self.t1_us, self.t2_us)

    def survival_fraction(self, idle_us: float) -> float:
        if idle_us < 0:
            raise ValueError("idle_us must be non-negative")
        return math.exp(-idle_us / self.effective_coherence_us)


@dataclass(frozen=True)
class DDConfig:
    dt_ns: float = 0.222
    x_pulse_dt: int = 160
    min_idle_ratio: float = 2.0
    pulse_budget_fraction: float = 0.10

    def __post_init__(self) -> None:
        if self.dt_ns <= 0 or self.x_pulse_dt <= 0:
            raise ValueError("invalid DD timing configuration")
        if self.min_idle_ratio < 1:
            raise ValueError("min_idle_ratio must be >= 1")
        if not 0 < self.pulse_budget_fraction <= 1:
            raise ValueError("pulse_budget_fraction must be in (0, 1]")


def uhrig_spacings(pulse_count: int) -> tuple[float, ...]:
    if pulse_count < 1:
        raise ValueError("pulse_count must be >= 1")
    boundaries = [
        math.sin(math.pi * (k + 1) / (2 * pulse_count + 2)) ** 2
        for k in range(pulse_count)
    ]
    return tuple(
        [boundaries[0]]
        + [boundaries[i] - boundaries[i - 1] for i in range(1, pulse_count)]
        + [1.0 - boundaries[-1]]
    )


def build_dd_pass_manager(
    coherence: CoherenceModel,
    *,
    config: DDConfig = DDConfig(),
    pulse_count: int = 2,
    durations: InstructionDurations | None = None,
) -> PassManager:
    if pulse_count != 2:
        raise ValueError("this profile currently uses a balanced XX sequence")

    pulse_us = config.x_pulse_dt * config.dt_ns / 1000.0
    if pulse_count * pulse_us > coherence.effective_coherence_us * config.pulse_budget_fraction:
        raise ValueError("DD pulse budget exceeds configured coherence budget")

    if durations is None:
        durations = InstructionDurations(
            [
                ("h", None, 80),
                ("x", None, config.x_pulse_dt),
                ("measure", None, max(1, config.x_pulse_dt)),
                ("reset", None, max(1, config.x_pulse_dt)),
                ("cx", None, 2 * config.x_pulse_dt),
            ],
            dt=config.dt_ns * 1e-9,
        )

    return PassManager([
        ALAPScheduleAnalysis(durations),
        PadDynamicalDecoupling(
            durations,
            [XGate(), XGate()],
            spacing=list(uhrig_spacings(pulse_count)),
        ),
    ])


def apply_dynamical_decoupling(
    circuit: QuantumCircuit,
    coherence: CoherenceModel,
    *,
    config: DDConfig = DDConfig(),
    durations: InstructionDurations | None = None,
) -> QuantumCircuit:
    return build_dd_pass_manager(
        coherence, config=config, durations=durations
    ).run(circuit)
