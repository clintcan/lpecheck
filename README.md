# lpe-check

Detect and apply temporary mitigations for two recent Linux kernel local-privilege-escalation vulnerabilities:

- **Copy Fail** — `CVE-2026-31431`, disclosed 29 April 2026
- **Dirty Frag** — disclosed 7–8 May 2026, no CVE assigned at time of writing

Both are deterministic logic bugs that let an unprivileged local user gain root on most major Linux distributions running unpatched kernels. Public proof-of-concept exploits exist for both.

> **This script is not a substitute for patching.** The real fix is your distribution's patched kernel package plus a reboot. The script applies temporary module-blacklist mitigations to reduce exposure during the window between disclosure and a vendor kernel update being installed.

## What the script does

1. **Detects** whether your kernel is exposed by checking the status of four kernel modules: `algif_aead` (Copy Fail), `esp4`, `esp6`, and `rxrpc` (Dirty Frag).
2. **Checks active use** of IPsec (`ip xfrm state`) and AFS/`rxrpc` so it can warn you *before* applying mitigations that would tear down a running service.
3. **Applies mitigations** with explicit per-vulnerability confirmation, writing tagged files to `/etc/modprobe.d/` and best-effort unloading the affected modules.
4. **Rolls back** safely — only files this script created (identified by a header tag) can be removed via `--rollback`. Hand-written admin configs at the same paths are left untouched.

## Requirements

- Linux with bash 4 or newer
- sysfs mounted at `/sys` (universal on every modern Linux)
- kmod userspace (`modinfo`, `lsmod`, `rmmod`) — present on every mainstream distro
- Root privileges only for applying or rolling back mitigations; detection runs unprivileged

## Tested compatibility

| Distribution family | Status |
|---|---|
| Ubuntu 20.04+, Debian 11+, derivatives | Supported |
| RHEL / CentOS Stream / AlmaLinux / Rocky 8+ | Supported |
| Fedora (current) | Supported |
| openSUSE Leap 15+ / Tumbleweed / SLES 15+ | Supported |
| Arch Linux, derivatives | Supported |
| Alpine Linux | Likely works; bash must be installed (`apk add bash`) |
| NixOS | Detection works; mitigation writes won't take effect — use `boot.blacklistedKernelModules` in `configuration.nix` instead |
| Containers (Docker / Podman / LXC) | Run on the **host**, not inside the container; modprobe.d inside a container does not affect the host kernel |

## Usage

```bash
chmod +x lpe-check.sh

# Detection only — read-only, no changes, no root required.
# Exits 0 if not exposed, 1 if exposed, non-zero on error.
./lpe-check.sh --check

# Interactive: detect, then prompt before applying each mitigation.
sudo ./lpe-check.sh

# Remove mitigations previously applied by this script.
sudo ./lpe-check.sh --rollback

# Help.
./lpe-check.sh --help
```

### Example: exposed system

```
$ sudo ./lpe-check.sh

=== System information ===
[*] Kernel:       Linux 6.8.0-50-generic x86_64
[*] Distribution: Ubuntu 24.04.1 LTS

=== Module status ===
    algif_aead VULNERABLE (loaded)
    esp4       VULNERABLE (not loaded but loadable)
    esp6       VULNERABLE (not loaded but loadable)
    rxrpc      VULNERABLE (loaded)

=== Active-use checks ===
[+] IPsec does not appear to be in use.
[+] rxrpc/AFS does not appear to be in use.

=== Exposure summary ===
  Copy Fail  (CVE-2026-31431): exposed
  Dirty Frag                 : exposed
```

## What the mitigations do

### Copy Fail mitigation

Writes `/etc/modprobe.d/disable-copyfail.conf` containing `install algif_aead /bin/false`, preventing the `algif_aead` module from loading. Then attempts to unload it now.

**Impact**: blocks the AEAD interface of the kernel's userspace crypto API (`AF_ALG`). It does **not** affect:

- LUKS / dm-crypt (full-disk encryption)
- kTLS (kernel TLS)
- IPsec / XFRM
- OpenSSL, GnuTLS, NSS, libsodium
- SSH, HTTPS

Only software that explicitly opens an `AF_ALG` AEAD socket is affected — typically a few `kcapi-*` utilities. On a typical desktop, server, or container host, no impact.

### Dirty Frag mitigation

Writes `/etc/modprobe.d/disable-dirtyfrag.conf` blocking `esp4`, `esp6`, and `rxrpc`. Then attempts to unload them now.

**Impact**:

- `esp4` / `esp6`: **breaks IPsec VPNs** (strongSwan, Libreswan, IKEv2/IPsec). Does **not** affect WireGuard, OpenVPN, or Tailscale.
- `rxrpc`: **breaks AFS** (Andrew File System). Almost no one uses AFS outside specific universities and research institutions; on Ubuntu the module is loaded by default but typically idle.

The script detects active IPsec/AFS use and warns before applying. If you're on a router, VPN gateway, or anything that terminates IPsec tunnels, decline the Dirty Frag prompt and prioritize installing the patched kernel instead.

## Rollback

Once your distribution has shipped a patched kernel and you've rebooted into it, remove the temporary blacklists:

```bash
sudo ./lpe-check.sh --rollback
```

The script only deletes files whose first line carries its `# Managed-by: lpe-check.sh vX.Y` header. If you (or another tool) have hand-written a `disable-copyfail.conf` or `disable-dirtyfrag.conf` at the same paths, the script will refuse to remove them and tell you so.

You can also remove the files manually:

```bash
sudo rm /etc/modprobe.d/disable-copyfail.conf
sudo rm /etc/modprobe.d/disable-dirtyfrag.conf
```

## Verifying patch status

After installing a patched kernel and rebooting, you can confirm with:

```bash
uname -r                                  # check the running kernel
./lpe-check.sh --check; echo $?           # 0 = not exposed
```

Check your distribution's security tracker for the patched version that applies to you:

- Ubuntu: <https://ubuntu.com/security/CVE-2026-31431>
- Debian: <https://security-tracker.debian.org/tracker/CVE-2026-31431>
- Red Hat: <https://access.redhat.com/security/cve/CVE-2026-31431>
- SUSE: <https://www.suse.com/security/cve/CVE-2026-31431.html>

## What this script does NOT do

- It does **not** patch the kernel. Only your distribution can ship the real fix.
- It does **not** detect successful exploitation. It measures exposure surface only. If you suspect a host has been exploited, treat it as compromised and use proper IR tooling.
- It does **not** modify any `/etc/modprobe.d/` file it did not create.
- It does **not** load any module. After rollback, modules will become loadable again on next boot, or immediately when something requests them — load them yourself with `modprobe <name>` if you want them active right away.
- It does **not** protect against built-in (compiled-in-kernel) versions of the affected modules. Modprobe configuration only governs loadable modules. If your kernel was built with `=y` rather than `=m` for any of the affected modules, the script will detect that case, warn you loudly, and tell you that only a kernel patch will help. This is uncommon on mainstream distro kernels but does happen on custom or hardened kernel builds.

## Security considerations

If you're distributing this script across many hosts, **do not** pipe it from `curl`/`wget` directly into `bash`:

- The interactive prompts can't function when stdin is the network pipe.
- `curl … | sudo bash` is a remote-code-execution vector — exactly the wrong threat model for a security mitigation tool.

Instead, download the file, verify it (read it, check a hash you trust), then execute it locally. For fleet deployment, ship it as a managed file via Ansible/Salt/Puppet/etc.

## References

**Copy Fail (CVE-2026-31431)**
- Theori writeup: <https://xint.io/blog/copy-fail-linux-distributions>
- Ubuntu advisory: <https://ubuntu.com/security/CVE-2026-31431>
- CERT-EU advisory: <https://cert.europa.eu/publications/security-advisories/2026-005/>

**Dirty Frag**
- Discoverer's repo (Hyunwoo Kim / @v4bel): <https://github.com/V4bel/dirtyfrag>
- oss-security disclosure thread: <https://www.openwall.com/lists/oss-security/2026/05/07/8>
- AlmaLinux advisory: <https://almalinux.org/blog/2026-05-07-dirty-frag/>

## License

Use freely. Modify freely. No warranty — review the script before running it on systems you care about, especially production.
