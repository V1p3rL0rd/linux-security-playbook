# Linux Security Configuration & Hardening

**English** | [Русский](README.ru.md)

Enterprise-grade automated baseline security hardening for Linux servers (**Ubuntu 20.04 / 22.04 / 24.04 LTS** and **RHEL / AlmaLinux / Rocky Linux 9+**).

Available both as **standalone idempotent Bash scripts** and as an **Ansible role / playbook**.

---

## Hardening Measures

- **Idempotent & Safe Execution**: Scripts and Ansible tasks can be run repeatedly without duplicating settings or breaking active services. Existing system files changed in place (`sshd_config`, `login.defs`, `pwquality.conf`, `dnf/automatic.conf`) are backed up automatically (Ansible `backup: true`).
- **Firewall Hardening**:
  - Dynamically respects configured SSH ports to avoid lockouts.
  - Ubuntu: Configures UFW (`default deny incoming`, `default allow outgoing`, permits SSH).
  - RHEL/AlmaLinux: Configures Firewalld (permanent rules for SSH).
- **Service Masking**: Stops, disables, and masks insecure services (`avahi-daemon`, `cups`, `cups-browsed`, `telnet`, `rsh`, `talk`).
- **Fail2ban SSH Protection**: Deploys Fail2ban with `backend = systemd`, configured for SSH with **5 retry attempts** and a **30-minute ban time**.
- **Automated Security Updates**: Configures `unattended-upgrades` (Ubuntu) or `dnf-automatic` (RHEL) strictly for security errata without interactive prompts.
- **Mandatory Access Control (MAC)**:
  - Ubuntu: Enforces and validates AppArmor status.
  - RHEL/AlmaLinux: Safe transition of SELinux to `Enforcing`. If SELinux is disabled, the role switches it to `permissive` and schedules `/.autorelabel`; after a reboot (manual, or automatic with `security_selinux_allow_reboot: true`) a second run sets `enforcing`.
- **Kernel Hardening (`/etc/sysctl.d/99-security.conf`)**:
  - Reverse path filtering (anti-spoofing), strict by default; set `security_rp_filter: 2` on multi-homed, VPN or Kubernetes hosts.
  - Disables ICMP redirect acceptance and source routing.
  - SYN flood cookies enabled.
  - ASLR (`randomize_va_space = 2`), restricts `dmesg`, kernel pointers (`kptr_restrict`), and protects symlinks/hardlinks.
- **SSH Daemon Hardening (`/etc/ssh/sshd_config.d/00-hardening.conf`)**:
  - Named `00-` so it is read before vendor/cloud-init drop-ins (`50-cloud-init.conf`, `50-redhat.conf`): sshd uses the first value it reads.
  - Keeps password authentication enabled (`PasswordAuthentication yes`) while protecting it via PAM and Fail2ban.
  - Prohibits empty passwords (`PermitEmptyPasswords no`).
  - Disables remote root password login (`prohibit-password`), requiring standard users to log in.
  - Limits authentication attempts to 5 (`MaxAuthTries 5`) to align with Fail2ban.
  - Disables X11/agent forwarding and sets client idle timeouts.
  - Tests syntax with `sshd -t` before reloading.
  - Ubuntu 22.10+ uses `ssh.socket` activation: if you change `security_ssh_port`, run `systemctl daemon-reload && systemctl restart ssh.socket` (or reboot) for the new port to take effect.
- **PAM Module & Password Policies**:
  - Installs and enables the PAM password quality module (`pam_pwquality` via `pam-auth-update` on Ubuntu, `authselect` on RHEL).
  - Enforces minimum password length of **12 characters** and character complexity classes in `/etc/security/pwquality.conf`.
  - Sets password expiration to **180 days** (`PASS_MAX_DAYS 180`, `PASS_WARN_AGE 14`) in `/etc/login.defs`.
  - **Safe account filtering**: Applies 180-day password expiration only to human users (`UID >= UID_MIN`, login shell) **with a usable password**. Locked/key-only accounts (e.g. `ubuntu`, `ec2-user`) are skipped to avoid SSH lockout; extra exclusions via `security_password_expiry_exclude_users`.
- **Auditing & Threat Detection**:
  - Deploys baseline `auditd` rules to monitor identity files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) and system time/locale.
  - Executes non-interactive security audit via **Lynis** (`lynis audit system --quick --cronjob`).

---

## Usage

### Option 1: Using Ansible (Recommended for Infrastructure)

1. Edit `inventory.example.ini` (or create your own inventory):
```ini
[servers]
server1.example.com ansible_host=192.168.1.50 ansible_user=ubuntu
```

2. Install required collections (`community.general`, `ansible.posix`):
```bash
ansible-galaxy collection install -r requirements.yml
```

3. Dry run, then apply:
```bash
ansible-playbook -i inventory.example.ini playbook.yml --check --diff
ansible-playbook -i inventory.example.ini playbook.yml
```

You can customize variables in `roles/security_hardening/defaults/main.yml` (e.g. `security_ssh_port`, `security_password_authentication`, `security_password_max_days`, `security_rp_filter`, `security_upgrade_all_packages`, `security_selinux_allow_reboot`).

---

### Option 2: Using Standalone Bash Scripts

#### On Ubuntu / Debian:
```bash
sudo ./ubuntu_security.sh
```

#### On RHEL / AlmaLinux / Rocky Linux:
```bash
sudo ./rhel_security.sh
```

---

## Verification & Logs

All execution artifacts and reports are preserved for inspection:
- **Lynis Audit Report**: `/var/log/lynis.log` and `/var/log/lynis-report.dat` (Bash scripts additionally write `/var/log/lynis-audit.log`)
- **Audit Rules Status**: `auditctl -l`
- **Fail2ban Status**: `fail2ban-client status sshd`
- **Firewall Status**: `ufw status verbose` or `firewall-cmd --list-all`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
