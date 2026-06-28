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

> The wrong-scheme guarantee covers *honest* mislabeling — decrypting
> the same output bytes under a different `Scheme` fails. It is not a
> cryptographic binding of the scheme label: `dgcmsiv` and `pgcmsiv`
> share one derived key and nonce space, so an adversary who crafts
> bytes (e.g. prepends a zero nonce) can re-frame a `dgcmsiv` output as
> a `pgcmsiv` one — without the key. Such relabeling preserves the
> plaintext and forges no new content (no key or plaintext recovery),
> but if your application treats "deterministic vs probabilistic" as a
> trust boundary, bind the scheme yourself in your own framing.

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
(per RFC 5297 the 512-bit key splits into two 256-bit sub-keys: the
S2V/AES-CMAC authentication key and the AES-CTR encryption key).
AES-GCM-SIV
is typically faster on CPUs with AES-NI and has a smaller per-message
footprint. In practice SIV wins on short inputs while GCM-SIV scales
better and pulls ahead on medium-to-large inputs (crossover around 256
bytes). Offering both lets the caller trade footprint and size-scaling
against the cleanest security story.

## Usage limits

The deterministic GCM-SIV scheme (`dgcmsiv`) encrypts under a fixed
all-zero nonce, making it deterministic. This is sound only because
AES-GCM-SIV is nonce-misuse-resistant (RFC 8452): nonce reuse does not
cause the catastrophic two-time-pad failure of plain AES-GCM, and the
only confidentiality loss is the deterministic-equality leak `dgcmsiv`
already exposes by design. The binding limit is therefore on **data
volume**, not nonce reuse: security degrades only as the total data
encrypted under one key approaches the AES-GCM-SIV birthday bound —
far out of practical reach for the short-string workloads obcrypt
targets. Because the library is stateless and tracks no cumulative
usage, honoring that bound is a deployment responsibility: callers
encrypting at high volume under one key should rotate the master key
well before it. `dgcmsiv` and `pgcmsiv` share one derived key (see
[Key handling](#key-handling) below), so their volumes draw on the
same budget. The SIV schemes (`dsiv`, `psiv`) carry comparable
AES-SIV data-volume bounds. The fixed-nonce construction must not be
transplanted onto plain AES-GCM, where nonce reuse is catastrophic.

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

## Audit status

`obcrypt` has **not** been independently security-audited. It is a thin
wrapper over the RustCrypto `aes-siv`, `aes-gcm-siv`, `hkdf`, and
`sha2` crates; the cryptographic constructions follow RFC 5297,
RFC 8452, and RFC 5869, and the wire format is pinned by the oboron
protocol's cross-implementation test vectors. Evaluate accordingly for
high-assurance use.

## Reporting vulnerabilities

If you find a security issue in `obcrypt`, please email the maintainer
at **dev@deyanovich.org** with the subject line beginning
`[obcrypt security]`. Include reproduction details, affected versions,
and (if possible) a proposed fix or mitigation.

For non-security bugs, file an issue on the
[GitLab repository](https://gitlab.com/oboron/obcrypt-rs/-/issues).

Coordinated disclosure: I'll acknowledge receipt within 7 days and
work with you on a disclosure timeline appropriate to the severity.
