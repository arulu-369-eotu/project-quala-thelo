"""UQL modules load on demand; research imports do not initialize crypto."""
from importlib import import_module

_EXPORTS = {
    'architecture': ('ArchitectureDeclaration', 'CompilerManifest'),
    'crypto': ('HybridCiphertext', 'HybridKeyExchange', 'HybridRecipient'),
    'native_crypto': ('NativeKeyPair', 'NativeSecret'),
    'memory': ('LockedBuffer', 'MemoryLockStatus'),
    'qec': ('SurfaceCode',),
    'dd': ('CoherenceModel', 'DDConfig', 'build_dd_pass_manager'),
}
_MODULES = {name: module for module, names in _EXPORTS.items() for name in names}
__all__ = list(_MODULES)


def __getattr__(name):
    if name not in _MODULES:
        raise AttributeError(name)
    value = getattr(import_module(f'.{_MODULES[name]}', __name__), name)
    globals()[name] = value
    return value
