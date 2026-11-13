# Contributing to zcash-hw-wallet-sdk

This crate builds the data a hardware device signs. Follow the
[librustzcash style guides](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides)
for code, commits and pull requests; the points below are specific to this
repository.

## Before you open a pull request

```bash
cargo test                      # unit tests

# Integration tests run the whole PCZT pipeline against a virtual device
# built from the same C library the hardware runs:
cmake -S integration-tests/virtual-device -B /tmp/vd \
      -DLIBZCASH_SOURCE_DIR=$PWD/libzcash-ironwood-c && cmake --build /tmp/vd -j
/tmp/vd/virtual-device --port 9999 &
VIRTUAL_DEVICE_ADDR=127.0.0.1:9999 cargo test --test integration --features tcp -- --test-threads=1
```

## Rules

- **No panics on input.** Data from a PCZT, from the device or from a server
  is untrusted: no `unwrap`, `expect` or unchecked indexing on it. Return a
  typed error.
- **The host is not a trust anchor.** Do not add a host-supplied hint that the
  device is expected to believe (for example "this output is change"). Checks
  that protect funds belong on the device, in `libzcash-ironwood-c`.
- **Tests exercise the real code path.** A test must call the function it is
  named after, not a copy of its logic. Behaviour changes come with a test
  that fails without them.
- **Wire protocol.** `src/protocol/hwp.rs` mirrors `include/hwp.h` in the C
  library. Change both together, after agreeing the change in an issue.
- **Dependencies.** Zcash crates come from crates.io releases, with no patch
  table. A dependency bump is its own commit.
- **Documentation** (`README.md`, `docs/`) is updated in the same pull request
  as the behaviour it describes.

## Commits

One logical change per commit; subject says what, body says why and how it
was verified. Rebase on `main`.
