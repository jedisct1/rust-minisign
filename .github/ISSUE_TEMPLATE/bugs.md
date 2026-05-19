---
name: "Bug Report"
about: Report a bug you've encountered
title: ''
labels: ''
assignees: ''

---

Thanks for taking the time to report a bug! Before filing, please note:

**Need help or have a question?** The issue tracker is for confirmed, reproducible bugs in the `minisign` crate only. For questions about how to use the API, integration help, or general questions, please check the [API documentation on docs.rs](https://docs.rs/minisign) first.

If you're looking for the command-line tool, this is the wrong repository — please file the issue against [rsign2](https://github.com/jedisct1/rsign2) instead. If you only need to verify signatures, the relevant crate is [minisign-verify](https://github.com/jedisct1/rust-minisign-verify).

---

### Before submitting

Please make sure:

- You've read the [API documentation](https://docs.rs/minisign) and this is not answered there already
- You're using the **latest version** of the `minisign` crate from [crates.io](https://crates.io/crates/minisign)
- You can reliably reproduce the issue with a minimal example

---

## Environment

Please include:

- `minisign` crate version
- `rustc --version` output
- Operating system and architecture

## What's happening?

<!-- Describe the unexpected behavior. Include error messages, panics, or wrong outputs verbatim. -->

## Minimal reproducer

<!-- A short, self-contained Rust snippet that triggers the bug. Smaller is better. -->

```rust
```

## Expected behavior

## Additional context

<!-- Anything else that might help: signatures or keys involved (if non-sensitive), interoperability concerns with the C minisign implementation, etc. -->
