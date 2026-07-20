# LPE-Toolkit Binaries

Pre-compiled Linux Local Privilege Escalation exploit binaries (xpl2026).

## Usage

```bash
# Download all binaries
git clone https://github.com/coupdegrace223/LPE-Toolkit.git
cd LPE-Toolkit
chmod +x xpl2026

# Run auto-detection
./xpl2026

# Or run individual exploit
./dirtypipe-static
```

## Exploit List (23 CVEs: 2021-2026)

| Exploit | CVE | Kernel |
|---------|-----|--------|
| CopyFail | CVE-2026-31431 | 5.x - 7.x |
| DirtyFrag | CVE-2026-43284 | 5.x - 7.x |
| Fragnesia | CVE-2026-46300 | 5.x - 7.x |
| DirtyDecrypt | CVE-2026-31635 | 5.x - 7.x |
| PinTheft | N/A | 5.x - 7.x |
| CIFSwitch | CVE-2026-46243 | 5.x - 7.x |
| PACKET_EDIT_MEME | CVE-2026-46331 | 5.18 - 7.1 |
| pidfd-race | CVE-2026-46333 | 5.x - 7.x |
| Bad Epoll | CVE-2026-46242 | lts-6.12.67 |
| DirtyClone | CVE-2026-43503 | 7.1-rc1 - 7.1-rc4 |
| FUSE OOB | CVE-2026-31694 | 6.15+ |
| Pack2TheRoot | CVE-2026-41651 | All |
| DirtyPipe | CVE-2022-0847 | 5.8 - 5.16.11 |
| PwnKit | CVE-2021-4034 | All |
| OverlayFS | CVE-2021-3493 | 3.x - 5.11 |
| OvFS+FUSE | CVE-2023-0386 | 5.11+ |
| Polkit D-Bus | CVE-2021-3560 | All |
| Docker Socket | N/A | Container |
| netfilter OOB | CVE-2021-22555 | 2.6.19 - 5.12 |
| nft UAF2 | CVE-2022-2586 | 5.x - 5.18 |
| nft UAF | CVE-2024-1086 | 5.x - 6.x |
| IPv6 Frag Escape | N/A | 6.12.x |

**Disclaimer:** For authorized penetration testing and security research only.
