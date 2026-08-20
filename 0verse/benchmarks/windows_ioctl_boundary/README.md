# Windows IOCTL boundary contract fixture

This synthetic JSON fixture exercises strict manifest binding and deterministic
bounded mutation planning. It contains no executable, payload bytes, device path,
or real vulnerability. The result explicitly sets `capability_measure=false` and
records zero IOCTL attempts.

```bash
0verse windows-ioctl-plan benchmarks/windows_ioctl_boundary/campaign.json
```
