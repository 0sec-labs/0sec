# 0verse public export manifest

- Source: 0sec-labs/0verse @ 5962861154234e6a2b007c56a9b79c352d8d51c6
- Exported: 2026-08-20T07:15:35Z
- Files: 674
- Allowlist sha256: c0c06b4a9222ef8a3c2df882ebd6cab554fd02552c4d608c36d13520eb81891a

## Excluded (representative, see ADR-094)

- campaigns/ — raw research campaign evidence
- ms0-vmswitch/ — third-party Microsoft binaries, redistribution rights not established
- benchmarks/{binarygym,windows_candidates,windows_negative,windows_oracle,kernel_candidates,kernel_negative,kernelctf,firmware_candidates} — private research lanes, raw logs, or unverified dataset licensing
- bounty/campaign/visor/kernelCTF operations docs
- scripts/{browser,ci,cve_kb,hyperv,linux,windows} — internal lab operations
- docker-compose.yml and internal-runner workflows
- examples/{pwnkit_cloud_lane.py,windows_scope_canary.json} — internal cloud-lane references
- 6 test files whose subjects are excluded (listed in the export PR)

## Scan receipt

Patterns scanned clean: private keys (test-fixture keys allowlisted),
lab topology (hosts/IPs), private repository references, bounty operations,
internal service endpoints.
