"""Declarative architecture layer.

Declarations describe what the compiler intends to provide. They do not claim
that an implementation is verified until the concrete mechanism modules pass
their tests and runtime capability checks.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ArchitectureDeclaration:
    name: str
    version: str
    mechanisms: tuple[str, ...]
    security_properties: tuple[str, ...]


@dataclass(frozen=True)
class CompilerManifest:
    architecture: ArchitectureDeclaration
    verified_mechanisms: tuple[str, ...] = field(default_factory=tuple)

    def is_verified(self, mechanism: str) -> bool:
        return mechanism in self.verified_mechanisms


DEFAULT_ARCHITECTURE = ArchitectureDeclaration(
    name="UQL Omniversal Compiler",
    version="1.0.0",
    mechanisms=(
        "X25519",
        "ML-KEM-1024",
        "HKDF-SHA-512",
        "OS-backed secret-memory locking",
        "surface-code syndrome extraction",
        "coherence-aware dynamical decoupling",
    ),
    security_properties=(
        "hybrid classical/post-quantum key establishment",
        "explicit memory-lock capability reporting",
        "repeated stabilizer syndrome extraction",
        "hardware-aware idle-time pulse scheduling",
    ),
)
