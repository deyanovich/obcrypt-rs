# obcrypt-py

Python bindings for [`obcrypt`](../obcrypt) — the bytes-in /
bytes-out cryptographic core of the
[oboron](https://oboron.org/) protocol.

**Status: scaffold.** Only the package skeleton is in place; the
binding surface (PyO3 classes, methods, exception types) is being
built incrementally.

## Build (development)

```bash
pip install maturin
cd obcrypt-py
maturin develop --release
```

## License

MIT — see [LICENSE](LICENSE).
