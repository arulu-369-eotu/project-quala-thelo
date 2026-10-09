"""Declarative architecture layer.

Declarations describe intent. A mechanism is considered verified only after
its concrete implementation and tests establish the declared behavior.
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
    version="1.2.0",
    mechanisms=(
        "native OpenSSL X25519",
        "native OpenSSL ML-KEM-1024",
        "native OpenSSL HKDF-SHA-512",
        "dedicated anonymous mlock/MADV_DONTDUMP working pages",
        "surface-code syndrome extraction",
        "coherence-aware dynamical decoupling",
    ),
    security_properties=(
        "hybrid classical/post-quantum key establishment",
        "pointer-only native secret handles",
        "fail-closed kernel memory lockdown",
        "repeated stabilizer syndrome extraction",
        "hardware-aware idle-time pulse scheduling",
    ),
)
