"""UQL mechanisms. Optional SDKs and native crypto load only when requested."""
from importlib import import_module

_EXPORTS = {
    "ArchitectureDeclaration": "architecture", "CompilerManifest": "architecture",
    "HybridCiphertext": "crypto", "HybridKeyExchange": "crypto",
    "HybridRecipient": "crypto", "NativeKeyPair": "native_crypto",
    "NativeSecret": "native_crypto", "LockedBuffer": "memory",
    "MemoryLockStatus": "memory", "SurfaceCode": "qec",
    "CoherenceModel": "dd", "DDConfig": "dd", "build_dd_pass_manager": "dd",
}


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    value = getattr(import_module(f".{_EXPORTS[name]}", __name__), name)
    globals()[name] = value
    return value

__all__ = [
    "ArchitectureDeclaration","CompilerManifest","HybridCiphertext",
    "HybridKeyExchange","HybridRecipient","NativeKeyPair","NativeSecret",
    "LockedBuffer","MemoryLockStatus","SurfaceCode","CoherenceModel",
    "DDConfig","build_dd_pass_manager",
]

