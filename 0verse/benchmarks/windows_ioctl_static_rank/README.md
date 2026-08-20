# Windows IOCTL static-rank contract benchmark

The synthetic contract fixture is generated in a temporary directory by
`tests/test_windows_ioctl_rank.py`. It contains a non-PE placeholder driver,
receipt-owned SSA export, one exact buffered IOCTL, one constant-offset length
field, and no executable bytes or device path.

```bash
pytest -q tests/test_windows_ioctl_rank.py
```

The positive fixture ranks one unguarded `SystemBuffer`-to-copy hypothesis. The
patched control supplies all three required guards and is suppressed. Tampered,
unresolved, duplicated, or cross-bound evidence is rejected. This is a
deterministic contract regression only, not a capability or bounty measure.
