#!/usr/bin/env bash
# ==============================================================================
# Linux Security Configuration Script for RHEL / AlmaLinux / Rocky Linux
# Target OS: RHEL 9+ / AlmaLinux 9+ / Rocky Linux 9+
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

echo "======================================================"
echo " Starting System Security Hardening for RHEL / Clones"
echo "======================================================"

# ------------------------------------------------------------------------------
# 1. System Updates & EPEL Repository
# ------------------------------------------------------------------------------
log_info "Installing EPEL repository..."
dnf install -y epel-release || dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm || true

log_info "Updating system packages..."
dnf upgrade -y
log_success "System packages updated."

# ------------------------------------------------------------------------------
# 2. Firewall Configuration (Firewalld)
# ------------------------------------------------------------------------------
log_info "Configuring Firewalld..."
dnf install -y firewalld
systemctl enable --now firewalld

# Detect configured SSH port (default to 22 if not detected)
SSH_PORT=$(ss -tlnp 2>/dev/null | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F: '{print $NF}' | head -n1 || echo "")
if [[ -z "${SSH_PORT}" ]]; then
    SSH_PORT=$(awk '/^Port / {print $2}' /etc/ssh/sshd_config 2>/dev/null || echo 22)
fi
SSH_PORT="${SSH_PORT:-22}"

if [[ "${SSH_PORT}" -eq 22 ]]; then
    firewall-cmd --permanent --add-service=ssh > /dev/null 2>&1 || true
else
    firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" > /dev/null 2>&1 || true
fi

firewall-cmd --reload > /dev/null 2>&1 || true
log_success "Firewalld active and configured for SSH on port ${SSH_PORT}."

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
dnf install -y fail2ban fail2ban-systemd

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
# 5. Automatic Security Updates (dnf-automatic)
# ------------------------------------------------------------------------------
log_info "Configuring dnf-automatic for security updates..."
dnf install -y dnf-automatic

backup_file "/etc/dnf/automatic.conf"
sed -i 's/^upgrade_type\s*=.*/upgrade_type = security/' /etc/dnf/automatic.conf || true
sed -i 's/^apply_updates\s*=.*/apply_updates = yes/' /etc/dnf/automatic.conf || true

systemctl enable --now dnf-automatic.timer
log_success "dnf-automatic security updates enabled."

# ------------------------------------------------------------------------------
# 6. SELinux Hardening & Safety Check
# ------------------------------------------------------------------------------
log_info "Checking SELinux status..."
CURRENT_SELINUX="$(getenforce 2>/dev/null || echo "Unknown")"

backup_file "/etc/selinux/config"
if [[ "${CURRENT_SELINUX}" == "Permissive" ]]; then
    setenforce 1
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    log_success "SELinux switched to Enforcing mode."
elif [[ "${CURRENT_SELINUX}" == "Disabled" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    touch /.autorelabel
    log_warn "SELinux was DISABLED. It has been set to enforcing in config and /.autorelabel created."
    log_warn "A system reboot is required to complete file relabeling safely."
else
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    log_success "SELinux is already in Enforcing mode."
fi

# ------------------------------------------------------------------------------
# 7. Logging & Auditing (auditd + rsyslog)
# ------------------------------------------------------------------------------
log_info "Configuring auditd and rsyslog..."
dnf install -y rsyslog audit

systemctl enable --now rsyslog
systemctl enable --now auditd || service auditd start || true

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
EOF

augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
log_success "Auditd rules loaded and rsyslog enabled."

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
    systemctl reload sshd || systemctl restart sshd
    log_success "SSH configuration verified and reloaded."
else
    log_warn "sshd -t reported an error with new configuration. Reverting..."
    rm -f /etc/ssh/sshd_config.d/99-hardening.conf
fi

# ------------------------------------------------------------------------------
# 10. PAM Module Installation & Password Policy (minlen=12, 180-day rotation)
# ------------------------------------------------------------------------------
log_info "Installing and configuring PAM password quality module (libpwquality)..."
dnf install -y libpwquality

# Ensure authselect enables pwquality in PAM configuration
if command -v authselect &> /dev/null; then
    authselect enable-feature with-pwquality 2>/dev/null || true
    authselect apply-changes 2>/dev/null || true
fi

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
# 11. Rootkit & Security Auditing (chkrootkit / rkhunter & Lynis)
# ------------------------------------------------------------------------------
log_info "Installing security auditing tools (Lynis)..."
dnf install -y lynis

# Attempt to install rootkit scanner if available in EPEL
if dnf install -y chkrootkit 2>/dev/null; then
    log_info "Running chkrootkit initial scan..."
    chkrootkit > /var/log/chkrootkit.log 2>&1 || true
elif dnf install -y rkhunter 2>/dev/null; then
    log_info "Running rkhunter initial propupd..."
    rkhunter --propupd > /dev/null 2>&1 || true
fi

log_info "Running Lynis automated audit (this may take 1-2 minutes)..."
lynis audit system --quick --cronjob > /var/log/lynis-audit.log 2>&1 || true
log_success "Lynis audit complete. Report saved to /var/log/lynis-audit.log"

echo "======================================================"
echo " RHEL/AlmaLinux security hardening completed!"
echo " Review logs:"
echo " - Lynis report: /var/log/lynis-audit.log"
echo "======================================================"
