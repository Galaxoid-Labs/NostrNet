# API Reference

Auto-generated from XML doc comments on every public type and member
across the NostrNet packages. Every public API is documented — the
build fails (CS1591) if a doc comment is missing.

Pick a package from the left-hand TOC to drill into its namespaces and
types.

## Conventions

- **Try-prefixed methods** (`TryParse`, `TryDecrypt`) return `bool` and
  use `out` parameters. Use them when parsing untrusted input.
- **Span-based crypto** zeroes its working memory on dispose via
  `CryptographicOperations.ZeroMemory`.
- **AOT-compatible** — every public API can be reached from a
  trimmed, AOT-compiled application. JSON is serialised via
  `System.Text.Json` source generators or hand-written readers/writers,
  never reflection.
- **No DI / no `Microsoft.Extensions.Logging`** — the library exposes
  types directly without any framework dependencies.

## See also

- [Source on GitHub](https://github.com/Galaxoid-Labs/NostrNet) — pinned
  to the commit each documentation build was generated from.
- [Per-package READMEs](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src)
  — quickstart snippets and protocol-specific guidance live next to
  each package's source.
