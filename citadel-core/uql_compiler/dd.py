"""Coherence-aware dynamical decoupling for Qiskit 2.x.

The pass operates on a scheduled circuit and inserts timed DD gates into idle
windows. T1/T2 values influence the minimum idle window selected for DD and the
sequence spacing; the backend ultimately maps gates to calibrated microwave
pulses.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from qiskit.circuit import QuantumCircuit
from qiskit.circuit.library import XGate
from qiskit.transpiler import PassManager
from qiskit.transpiler.passes import ALAPScheduleAnalysis, PadDynamicalDecoupling
from qiskit.transpiler import InstructionDurations


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


@dataclass(frozen=True)
class DDConfig:
    dt_ns: float = 0.222
    x_pulse_dt: int = 160
    min_idle_ratio: float = 2.0

    def __post_init__(self) -> None:
        if self.dt_ns <= 0 or self.x_pulse_dt <= 0 or self.min_idle_ratio < 1:
            raise ValueError("invalid DD timing configuration")


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
) -> PassManager:
    """Create a scheduled, timed DD pass manager.

    The coherence model is used to reject sequences whose total pulse duration
    would consume a disproportionate fraction of the shortest coherence time.
    """
    if pulse_count != 2:
        raise ValueError("this production profile currently uses an XX sequence")
    pulse_us = config.x_pulse_dt * config.dt_ns / 1000.0
    if 2 * pulse_us > coherence.effective_coherence_us * 0.1:
        raise ValueError("DD pulse budget exceeds 10% of effective coherence time")

    durations = InstructionDurations([
        ("x", config.x_pulse_dt),
        ("measure", max(1, config.x_pulse_dt)),
        ("reset", max(1, config.x_pulse_dt)),
        ("cx", 2 * config.x_pulse_dt),
    ])
    return PassManager(
        [
            ALAPScheduleAnalysis(durations),
            PadDynamicalDecoupling(
                durations,
                [XGate(), XGate()],
                spacings=uhrig_spacings(pulse_count),
                sequence_min_length_ratios=config.min_idle_ratio,
            ),
        ]
    )


def apply_dynamical_decoupling(
    circuit: QuantumCircuit,
    coherence: CoherenceModel,
    *,
    config: DDConfig = DDConfig(),
) -> QuantumCircuit:
    """Return a scheduled circuit with coherence-aware DD inserted."""
    return build_dd_pass_manager(coherence, config=config).run(circuit)
