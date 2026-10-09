# UQL research and native cryptographic core, v1.2

OpenSSL 3.5+ provides X25519, ML-KEM-1024 and HKDF-SHA512. The custom hybrid v2
combiner derives 64 bytes from the two 32-byte shared secrets, using a versioned,
length-framed SHA-512 commitment to recipient public keys, ciphertext and at most
4,096 bytes of application context. HKDF info is constant size below 1,024 bytes.
The old v1 path exceeded that limit for every valid key bundle; it is not retained.

Application-owned X25519, ML-KEM and HKDF working buffers and the returned secret
use dedicated anonymous Linux pages. They require mlock and MADV_DONTDUMP, are
excluded from fork children with MADV_DONTFORK, cleansed on successful and failed
operations, and unmapped at close.
Owned native handles reject copying, serialization, closed use and inherited
post-fork operations. OpenSSL provider-managed private keys and internal working
allocations are outside this memory-lock guarantee. This is not an HSM, a hardware
enclave, resistance to root compromise, a FIPS validation, or an independent
security proof. Pointer access is for trusted native callers; Python cannot
prevent a caller from reading an exposed address with ctypes.

The custom combiner needs independent review. No peer-authentication or key
confirmation protocol is provided. In particular, corrupted ML-KEM ciphertext
may produce a different secret through implicit rejection; callers must use
an authenticated protocol and key confirmation before using an established key.

Surface-code circuits implement commuting boundary checks and corrected logical
operators. Tests check rank, logical commutation, small pure error distance and
stable/error-sensitive repeated syndromes in a noiseless Clifford simulator.
A decoder, circuit-level noise model and fault-tolerance proof are absent.

Dynamical decoupling uses Qiskit 2.5's supported spacing argument and padding hook,
retains a configured idle/pulse ratio, rejects non-finite inputs, and preserves
ideal circuit action in tests. Hardware calibration and timing alignment remain
integration responsibilities. The local defaults are a simulation profile.

See the root README for the hash-locked Python 3.12 test commands. Quantum imports
load lazily and do not initialize native crypto. Native crypto itself explicitly
rejects OpenSSL below 3.5; UQL_OPENSSL_LIBRARY may point to an operator-controlled
absolute library path. The Linux lockdown path has no weaker fallback.
