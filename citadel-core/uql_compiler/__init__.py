"""UQL Omniversal Compiler: verified cryptographic and quantum mechanisms."""

from .architecture import ArchitectureDeclaration, CompilerManifest
from .crypto import HybridCiphertext, HybridKeyExchange, HybridRecipient
from .memory import LockedBuffer, MemoryLockStatus
from .qec import SurfaceCode
from .dd import CoherenceModel, DDConfig, build_dd_pass_manager

__all__ = [
    "ArchitectureDeclaration",
    "CompilerManifest",
    "HybridCiphertext",
    "HybridKeyExchange",
    "HybridRecipient",
    "LockedBuffer",
    "MemoryLockStatus",
    "SurfaceCode",
    "CoherenceModel",
    "DDConfig",
    "build_dd_pass_manager",
]
