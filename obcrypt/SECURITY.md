# Security model — `obcrypt`

This document describes what guarantees `obcrypt` provides, what it
doesn't, and the reasoning behind the algorithm choices.

## What obcrypt provides

`obcrypt` is a **symmetric encryption primitive** library. It takes
a 64-byte master key and plaintext bytes; it produces ciphertext bytes
(framed with a scheme marker). It does not handle key exchange, key
derivation, key rotation, or transport.

| Property | a-tier (`aasv`, `aags`, `apsv`, `apgs`) | u-tier (`upbc`) |
|---|---|---|
| Confidentiality | yes | yes |
| Authenticity (integrity) | yes (AEAD tag) | **no** |
| Tampering detection | yes (returns `DecryptionFailed`) | no — produces garbled plaintext |
| Wrong-key detection | yes (returns `DecryptionFailed`) | no — produces garbled plaintext |
| Determinism | varies by scheme (see [README](README.md)) | probabilistic only |
| Nonce-misuse resistance | strong (SIV/GCM-SIV) | n/a (CBC has IV not nonce) |

If you need authenticity, **use an a-tier scheme**. The u-tier `upbc`
exists for cases where an outer mechanism (signed transport, a MAC
over the ciphertext, etc.) supplies authenticity.

## What obcrypt does not provide

- **No key derivation.** Bring your own 64 bytes of high-entropy key
  material. `obcrypt` does not stretch passwords, run KDFs, or expand
  short keys — wrap a KDF (Argon2, scrypt, HKDF, etc.) above this
  layer if your input isn't already random.
- **No asymmetric primitives.** `obcrypt` is symmetric only.
- **No key rotation.** No epoch tags, no version negotiation between
  parties. If you rotate keys, do it above this layer (e.g. by
  prepending an explicit key id to the payload before encrypting, or
  by storing key id alongside ciphertext).
- **No transport.** `obcrypt` produces a `Vec<u8>` payload; it's up
  to the caller to send / store it.
- **No protection against side channels** beyond what the underlying
  primitive crates provide. `aes`, `aes-siv`, `aes-gcm-siv`, and
  `cbc` are all from the [RustCrypto](https://github.com/RustCrypto)
  organization and aim for constant-time implementations where
  applicable; `obcrypt` adds no further hardening at its layer.
- **No constant-time `Eq` for ciphertext or plaintext.** Compare
  ciphertext / plaintext with `subtle` or another constant-time
  comparator if equality observation is part of your threat model.
- **No protection against the deterministic-equality leak** for `aasv`
  / `aags`. That leak is the point of those schemes — see scheme
  selection guidance in the [README](README.md#schemes).

## Algorithm choices and justification

| Scheme | Algorithm | Crate | Standard |
|---|---|---|---|
| `aasv` | AES-256-SIV | [`aes-siv`](https://docs.rs/aes-siv/) | [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297) |
| `apsv` | AES-256-SIV (probabilistic) | [`aes-siv`](https://docs.rs/aes-siv/) | [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297) |
| `aags` | AES-256-GCM-SIV | [`aes-gcm-siv`](https://docs.rs/aes-gcm-siv/) | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452) |
| `apgs` | AES-256-GCM-SIV (probabilistic) | [`aes-gcm-siv`](https://docs.rs/aes-gcm-siv/) | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452) |
| `upbc` | AES-256-CBC + custom 0x01 padding | [`aes`](https://docs.rs/aes/) + [`cbc`](https://docs.rs/cbc/) | [NIST SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final) |

All AES variants use 256-bit keys (extracted from the 64-byte master
key — see the [Key docs](src/key.rs) for which scheme uses which slice).

**Why SIV?** SIV-mode AEADs (both AES-SIV and AES-GCM-SIV) are
*nonce-misuse resistant*: under accidental nonce reuse, the worst-case
property degradation is the deterministic-equality leak (i.e. you get
`aasv`-like behavior), not catastrophic key recovery as in plain
AES-GCM. This makes SIV a safer default for a general-purpose
encryption layer where the caller might not be careful about RNG
quality.

**Why both SIV and GCM-SIV?** AES-SIV uses the full 64-byte key (256
bits each for two AES-CMAC and one AES-CTR sub-key) and is the
gold-standard nonce-misuse-resistant AEAD. AES-GCM-SIV uses a 32-byte
key and is typically faster on CPUs with AES-NI hardware
acceleration. Offering both lets the caller trade footprint against
peak throughput.

**Why CBC for `upbc`?** CBC is the simplest, most universally
available block-cipher mode. It exists in `obcrypt` for cases where
an outer mechanism handles authentication (signed transport,
authenticated wrappers) and confidentiality is the only need. CBC
is **not** authenticated; do not use `upbc` for unprotected payloads.

## Key handling

- The [`Key`](src/key.rs) type wraps `[u8; 64]` with `Zeroize` /
  `ZeroizeOnDrop` from the [`zeroize`](https://docs.rs/zeroize/)
  crate. Bytes are zeroed when the value is dropped.
- `Key::Debug` redacts the contents — safe to log accidentally.
- The canonical text encoding for a key is **hex** (128 lowercase
  characters), via `Key::from_hex` / `Key::to_hex`. obcrypt
  intentionally does not support other key encodings — in
  cryptography, clarity outweighs compactness, and the size saving
  of base64 over hex isn't large enough to justify the visual
  noise.

## Threat model

`obcrypt` aims to defend against:

- **Passive eavesdroppers** observing ciphertext. Both a-tier and
  u-tier schemes provide IND-CPA confidentiality.
- **Active tamperers** modifying ciphertext (a-tier only). The AEAD
  tag check rejects any modification.
- **Wrong-key recovery attempts** (a-tier only). The AEAD tag check
  rejects decryption with the wrong key with overwhelming probability.

`obcrypt` does **not** aim to defend against:

- Compromised key material. Once an attacker has the 64-byte master
  key, all confidentiality and (for a-tier) authenticity is lost.
- Side-channel attacks beyond what the upstream primitive crates
  mitigate. If your threat model includes timing, power, or EM
  side-channel attacks, validate the upstream crates' guarantees and
  consider a hardened build environment.
- Quantum adversaries. `obcrypt` uses classical symmetric primitives;
  a sufficiently powerful quantum adversary running Grover's algorithm
  reduces the effective key strength to ~128 bits per AES-256 sub-key
  (still well outside currently-feasible cryptanalysis but worth
  noting if your threat model spans decades).

## Reporting vulnerabilities

If you find a security issue in `obcrypt`, please email the maintainer
at **dev@deyanovich.org** with the subject line beginning
`[obcrypt security]`. Include reproduction details, affected versions,
and (if possible) a proposed fix or mitigation.

For non-security bugs, file an issue on the
[GitLab repository](https://gitlab.com/oboron/obcrypt-rs/-/issues).

Coordinated disclosure: I'll acknowledge receipt within 7 days and
work with you on a disclosure timeline appropriate to the severity.
