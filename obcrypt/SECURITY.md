# Security model — `obcrypt`

This document describes what guarantees `obcrypt` provides, what it
doesn't, and the reasoning behind the algorithm choices.

## What obcrypt provides

`obcrypt` is a **symmetric authenticated-encryption primitive**
library. It takes a 64-byte master key and plaintext bytes; it
produces scheme-output bytes (the AEAD output directly, with no scheme
marker). It does not handle key exchange, key rotation, or transport.

All four core schemes — `dsiv`, `psiv`, `dgcmsiv`, `pgcmsiv` — are
authenticated:

| Property | All four schemes |
|---|---|
| Confidentiality | yes |
| Authenticity (integrity) | yes (AEAD tag) |
| Tampering detection | yes (returns `DecryptionFailed`) |
| Wrong-key detection | yes (returns `DecryptionFailed`) |
| Wrong-scheme detection | yes (returns `DecryptionFailed`) |
| Determinism | `dsiv` / `dgcmsiv` deterministic; `psiv` / `pgcmsiv` probabilistic |
| Nonce-misuse resistance | strong (SIV / GCM-SIV) |

Because the output carries no scheme marker, the scheme is part of the
caller's context: decrypting under the wrong scheme fails the
authentication check, exactly like a wrong key.

## What obcrypt does not provide

- **No key derivation from low-entropy input.** Bring your own 64
  bytes of high-entropy key material. `obcrypt` does not stretch
  passwords or expand short keys — wrap a password KDF (Argon2,
  scrypt, …) above this layer if your input isn't already random. (It
  *does* derive a GCM-SIV AES key from the master internally; see
  Key handling below.)
- **No asymmetric primitives.** `obcrypt` is symmetric only.
- **No key rotation.** No epoch tags, no version negotiation between
  parties. If you rotate keys, do it above this layer (e.g. by
  prepending an explicit key id to the payload before encrypting, or
  by storing key id alongside the output).
- **No transport.** `obcrypt` produces a `Vec<u8>`; it's up to the
  caller to send / store it.
- **No protection against side channels** beyond what the underlying
  primitive crates provide. `aes-siv`, `aes-gcm-siv`, and `hkdf` are
  all from the [RustCrypto](https://github.com/RustCrypto)
  organization and aim for constant-time implementations where
  applicable; `obcrypt` adds no further hardening at its layer.
- **No constant-time `Eq` for ciphertext or plaintext.** Compare
  output / plaintext with `subtle` or another constant-time
  comparator if equality observation is part of your threat model.
- **No protection against the deterministic-equality leak** for
  `dsiv` / `dgcmsiv`. That leak is the point of those schemes — see
  scheme selection guidance in the [README](README.md#schemes).

## Algorithm choices and justification

| Scheme | Algorithm | Crate | Standard |
|---|---|---|---|
| `dsiv` | AES-256-SIV (deterministic) | [`aes-siv`](https://docs.rs/aes-siv/) | [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297) |
| `psiv` | AES-256-SIV (probabilistic) | [`aes-siv`](https://docs.rs/aes-siv/) | [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297) |
| `dgcmsiv` | AES-256-GCM-SIV (deterministic) | [`aes-gcm-siv`](https://docs.rs/aes-gcm-siv/) | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452) |
| `pgcmsiv` | AES-256-GCM-SIV (probabilistic) | [`aes-gcm-siv`](https://docs.rs/aes-gcm-siv/) | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452) |

**Why SIV?** SIV-mode AEADs (both AES-SIV and AES-GCM-SIV) are
*nonce-misuse resistant*: under accidental nonce reuse, the worst-case
property degradation is the deterministic-equality leak (i.e. you get
`dsiv`-like behavior), not catastrophic key recovery as in plain
AES-GCM. This makes SIV a safer default for a general-purpose
encryption layer where the caller might not be careful about RNG
quality.

**Why both SIV and GCM-SIV?** AES-SIV is the gold-standard
nonce-misuse-resistant AEAD and uses the full 64-byte master directly
(256 bits each for two AES-CMAC and one AES-CTR sub-key). AES-GCM-SIV
is typically faster on CPUs with AES-NI and has a smaller per-message
footprint. In practice SIV wins on short inputs while GCM-SIV scales
better and pulls ahead on medium-to-large inputs (crossover around 256
bytes). Offering both lets the caller trade footprint and size-scaling
against the cleanest security story.

## Key handling

A single 64-byte master key serves every scheme; the per-scheme key
material is derived deterministically:

- `dsiv` / `psiv` use the full 64-byte master directly as the AES-SIV
  key.
- `dgcmsiv` / `pgcmsiv` derive a 32-byte AES-256-GCM-SIV key with
  `HKDF-Expand` (HMAC-SHA-256, info `gcmsiv`). The HKDF-Extract step is
  skipped because the master is already a uniform pseudorandom key. The
  two GCM-SIV schemes share this one derived key — safe because
  AES-GCM-SIV is nonce-misuse-resistant (`dgcmsiv` uses a constant zero
  nonce, `pgcmsiv` a per-message random nonce), exactly as `dsiv` and
  `psiv` share the master. The HKDF step keeps this GCM-SIV key
  distinct from the SIV family's direct use of the master.

Other key-handling notes:

- The [`Key`](src/key.rs) type wraps `[u8; 64]` with `Zeroize` /
  `ZeroizeOnDrop` from the [`zeroize`](https://docs.rs/zeroize/)
  crate. Bytes are zeroed when the value is dropped, and the derived
  GCM-SIV sub-keys are held in `Zeroizing` buffers.
- `Key::Debug` redacts the contents — safe to log accidentally.
- The canonical text encoding for a key is **hex** (128 lowercase
  characters), via `Key::from_hex` / `Key::to_hex`. obcrypt
  intentionally does not support other key encodings — in
  cryptography, clarity outweighs compactness, and the size saving
  of base64 over hex isn't large enough to justify the visual
  noise.

## Threat model

`obcrypt` aims to defend against:

- **Passive eavesdroppers** observing the output. All four schemes
  provide IND-CPA confidentiality.
- **Active tamperers** modifying the output. The AEAD tag check
  rejects any modification.
- **Wrong-key and wrong-scheme decryption attempts.** The AEAD tag
  check rejects decryption with the wrong key or wrong scheme with
  overwhelming probability.

`obcrypt` does **not** aim to defend against:

- Compromised key material. Once an attacker has the 64-byte master
  key, all confidentiality and authenticity is lost.
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
