#!/usr/bin/env bash
# ==============================================================================
# Linux Security Configuration Script for Ubuntu / Debian
# Target OS: Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Logging & Helper Functions
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Root privilege check
if [[ "${EUID}" -ne 0 ]]; then
    log_error "This script must be run as root (or with sudo). Aborting."
    exit 1
fi

backup_file() {
    local target="$1"
    if [[ -f "${target}" ]]; then
        local timestamp
        timestamp="$(date +%Y%m%d_%H%M%S)"
        cp -p "${target}" "${target}.bak_${timestamp}"
        log_info "Backup created: ${target}.bak_${timestamp}"
    fi
}

export DEBIAN_FRONTEND=noninteractive

echo "======================================================"
echo " Starting System Security Hardening for Ubuntu"
echo "======================================================"

# ------------------------------------------------------------------------------
# 1. System Updates
# ------------------------------------------------------------------------------
log_info "Updating package lists and upgrading existing packages..."
apt-get update -y
apt-get upgrade -y
log_success "System packages updated."

# ------------------------------------------------------------------------------
# 2. Firewall Configuration (UFW)
# ------------------------------------------------------------------------------
log_info "Configuring UFW (Uncomplicated Firewall)..."
apt-get install -y ufw

# Detect configured SSH port (default to 22 if not detected)
SSH_PORT=$(ss -tlnp 2>/dev/null | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F: '{print $NF}' | head -n1 || echo "")
if [[ -z "${SSH_PORT}" ]]; then
    SSH_PORT=$(awk '/^Port / {print $2}' /etc/ssh/sshd_config 2>/dev/null || echo 22)
fi
SSH_PORT="${SSH_PORT:-22}"

ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment "SSH port"

# Enable UFW non-interactively
ufw --force enable
log_success "UFW configured: default deny incoming, allowed outgoing, SSH port ${SSH_PORT}/tcp allowed."

# ------------------------------------------------------------------------------
# 3. Disable and Mask Unnecessary / Legacy Services
# ------------------------------------------------------------------------------
log_info "Disabling and masking unnecessary services..."
SERVICES_TO_DISABLE=(
    "avahi-daemon.service"
    "avahi-daemon.socket"
    "cups.service"
    "cups.socket"
    "cups-browsed.service"
    "telnet.socket"
    "rsh.socket"
    "rexec.socket"
    "talk.socket"
)

for srv in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${srv}"; then
        systemctl stop "${srv}" 2>/dev/null || true
        systemctl disable "${srv}" 2>/dev/null || true
        systemctl mask "${srv}" 2>/dev/null || true
        log_info "Service masked: ${srv}"
    fi
done
log_success "Unnecessary services disabled and masked."

# ------------------------------------------------------------------------------
# 4. Fail2ban Installation & Configuration (5 attempts, 30 min ban)
# ------------------------------------------------------------------------------
log_info "Installing and configuring Fail2ban (5 retries, 30-minute ban)..."
apt-get install -y fail2ban

backup_file "/etc/fail2ban/jail.local"
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 30m
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
maxretry = 5
bantime  = 30m
findtime = 10m
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log_success "Fail2ban configured for SSH (5 attempts, 30 min ban) and started."

# ------------------------------------------------------------------------------
# 5. Automatic Security Updates
# ------------------------------------------------------------------------------
log_info "Configuring unattended-upgrades..."
apt-get install -y unattended-upgrades update-notifier-common

backup_file "/etc/apt/apt.conf.d/20auto-upgrades"
cat << 'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable --now unattended-upgrades
log_success "Unattended security upgrades enabled."

# ------------------------------------------------------------------------------
# 6. AppArmor Setup
# ------------------------------------------------------------------------------
log_info "Checking AppArmor status..."
apt-get install -y apparmor apparmor-utils apparmor-profiles

if ! aa-status --enabled 2>/dev/null; then
    systemctl enable --now apparmor
    log_success "AppArmor service enabled and started."
else
    log_success "AppArmor is already active and running."
fi

# ------------------------------------------------------------------------------
# 7. Logging & Auditing (auditd + rsyslog)
# ------------------------------------------------------------------------------
log_info "Configuring auditd and rsyslog..."
apt-get install -y rsyslog auditd

systemctl enable --now rsyslog
systemctl enable --now auditd

# Baseline audit rules
cat << 'EOF' > /etc/audit/rules.d/99-security.rules
## Monitor changes to user/group databases
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Monitor changes to sudoers configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

## Monitor system calls for date and time modification
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change

## Monitor network environment configuration
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
EOF

augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
log_success "Auditd rules applied and rsyslog enabled."

# ------------------------------------------------------------------------------
# 8. Kernel Hardening (sysctl)
# ------------------------------------------------------------------------------
log_info "Applying kernel hardening parameters (sysctl)..."
backup_file "/etc/sysctl.d/99-security.conf"
cat << 'EOF' > /etc/sysctl.d/99-security.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP Redirect Acceptance & Sending
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable Source Packet Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# TCP SYN Flood Protection
net.ipv4.tcp_syncookies = 1

# Ignore ICMP Broadcast Echoes
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Memory Protection & Kernel Hardening
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF

sysctl --system > /dev/null 2>&1 || true
log_success "Kernel parameters hardened via /etc/sysctl.d/99-security.conf."

# ------------------------------------------------------------------------------
# 9. SSH Hardening
# ------------------------------------------------------------------------------
log_info "Hardening SSH configuration..."
mkdir -p /etc/ssh/sshd_config.d
backup_file "/etc/ssh/sshd_config.d/99-hardening.conf"
cat << 'EOF' > /etc/ssh/sshd_config.d/99-hardening.conf
# Secure authentication defaults (password authentication allowed but protected)
PermitRootLogin prohibit-password
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 5
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
EOF

# Ensure the main config includes sshd_config.d/*.conf
if ! grep -q "^Include /etc/ssh/sshd_config.d/\*\.conf" /etc/ssh/sshd_config 2>/dev/null; then
    sed -i '1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|' /etc/ssh/sshd_config
fi

# Verify sshd configuration syntax before restarting service
if sshd -t 2>/dev/null; then
    systemctl reload ssh || systemctl restart ssh || systemctl reload sshd || systemctl restart sshd
    log_success "SSH configuration verified and reloaded."
else
    log_warn "sshd -t reported an error with new configuration. Reverting..."
    rm -f /etc/ssh/sshd_config.d/99-hardening.conf
fi

# ------------------------------------------------------------------------------
# 10. PAM Module Installation & Password Policy (minlen=12, 180-day rotation)
# ------------------------------------------------------------------------------
log_info "Installing and configuring PAM password quality module (libpam-pwquality)..."
apt-get install -y libpam-pwquality

# Ensure pwquality PAM profile is activated non-interactively
pam-auth-update --enable pwquality 2>/dev/null || true

backup_file "/etc/security/pwquality.conf"
cat << 'EOF' > /etc/security/pwquality.conf
# Enforce minimum password length of 12 characters
minlen = 12
# Require character complexity
minclass = 3
maxrepeat = 3
difok = 3
gecoscheck = 1
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF

backup_file "/etc/login.defs"
# Require password change every 180 days with a 14-day warning
sed -i 's/^\(PASS_MAX_DAYS\s*\).*/\1180/' /etc/login.defs || true
sed -i 's/^\(PASS_MIN_DAYS\s*\).*/\11/' /etc/login.defs || true
sed -i 's/^\(PASS_WARN_AGE\s*\).*/\114/' /etc/login.defs || true
sed -i 's/^\(UMASK\s*\).*/\1027/' /etc/login.defs || true

# Apply 180-day password expiration ONLY to human non-system accounts
log_info "Applying 180-day password expiration to non-system user accounts..."
UID_MIN=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs 2>/dev/null || echo 1000)
awk -F: -v min="${UID_MIN}" '$3 >= min && $1 != "nobody" && $7 !~ /(nologin|false)/ {print $1}' /etc/passwd | while read -r user; do
    chage --maxdays 180 --mindays 1 --warndays 14 "${user}" 2>/dev/null || true
    log_info "Applied 180-day password expiration policy to user: ${user}"
done
log_success "PAM module configured (minlen=12) with 180-day password rotation."

# ------------------------------------------------------------------------------
# 11. Rootkit & Security Auditing (chkrootkit & Lynis)
# ------------------------------------------------------------------------------
log_info "Installing rootkit detection and auditing tools..."
apt-get install -y chkrootkit lynis

log_info "Running chkrootkit initial scan (logging to /var/log/chkrootkit.log)..."
chkrootkit > /var/log/chkrootkit.log 2>&1 || true
log_success "chkrootkit scan finished. Log: /var/log/chkrootkit.log"

log_info "Running Lynis automated audit (this may take 1-2 minutes)..."
lynis audit system --quick --cronjob > /var/log/lynis-audit.log 2>&1 || true
log_success "Lynis audit complete. Report saved to /var/log/lynis-audit.log"

echo "======================================================"
echo " Ubuntu security hardening completed successfully!"
echo " Review logs:"
echo " - Lynis report: /var/log/lynis-audit.log"
echo " - chkrootkit:   /var/log/chkrootkit.log"
echo "======================================================"
