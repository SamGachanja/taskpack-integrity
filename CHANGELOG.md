# Changelog

## 0.2.0

- Reject rename collisions before repair and refuse accidental output overwrites.
- Require an output path for scripted repairs and protect source paths.
- Verify every entry against expected contents, paths, and permission bits, including files under renamed directories.
- Preserve empty directories in deterministic archives.
- Validate ZIP paths and entry types; enforce extraction size, entry-count, and compression-ratio limits.
- Reject symlinks and special files instead of following or silently flattening them.
- Publish archives atomically, leaving existing output intact on write or validation failure.
- Add JSON reports and optional required post-repair consistency checks.
- Add adversarial archive and injected-failure tests.

## 0.1.0

- Initial public release with scan, plan, apply, check, synthetic examples, and Linux/macOS CI.
