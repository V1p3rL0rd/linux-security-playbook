# Настройка безопасности и харденинг Linux

[English](README.md) | **Русский**

Автоматизированный базовый харденинг серверов Linux (**Ubuntu 20.04 / 22.04 / 24.04 LTS** и **RHEL / AlmaLinux / Rocky Linux 9+**) для промышленной эксплуатации.

Доступен в двух вариантах: **самостоятельные идемпотентные Bash-скрипты** и **роль / плейбук Ansible**.

---

## Меры харденинга

- **Идемпотентность и безопасный запуск**: скрипты и задачи Ansible можно запускать повторно — настройки не дублируются, работающие службы не ломаются. Системные файлы, которые правятся на месте (`sshd_config`, `login.defs`, `pwquality.conf`, `dnf/automatic.conf`), автоматически сохраняются в резервную копию (Ansible `backup: true`).
- **Межсетевой экран**:
  - Учитывает настроенный порт SSH, чтобы не потерять доступ к серверу.
  - Ubuntu: настраивает UFW (`default deny incoming`, `default allow outgoing`, разрешает SSH).
  - RHEL/AlmaLinux: настраивает Firewalld (постоянные правила для SSH).
- **Маскирование служб**: останавливает, отключает и маскирует небезопасные службы (`avahi-daemon`, `cups`, `cups-browsed`, `telnet`, `rsh`, `talk`).
- **Защита SSH с Fail2ban**: устанавливает Fail2ban с `backend = systemd`, для SSH — **5 попыток** и **бан на 30 минут**.
- **Автоматические обновления безопасности**: настраивает `unattended-upgrades` (Ubuntu) или `dnf-automatic` (RHEL) только для исправлений безопасности, без интерактивных запросов.
- **Мандатный контроль доступа (MAC)**:
  - Ubuntu: включает и проверяет AppArmor.
  - RHEL/AlmaLinux: безопасно переводит SELinux в `Enforcing`. Если SELinux отключён, роль переводит его в `permissive` и создаёт `/.autorelabel`; после перезагрузки (вручную или автоматически при `security_selinux_allow_reboot: true`) повторный запуск включает `enforcing`.
- **Харденинг ядра (`/etc/sysctl.d/99-security.conf`)**:
  - Фильтрация по обратному пути (защита от спуфинга), по умолчанию строгая; на хостах с несколькими интерфейсами, VPN или Kubernetes задайте `security_rp_filter: 2`.
  - Отключает приём ICMP redirect и маршрутизацию от источника (source routing).
  - Включает SYN cookies против SYN flood.
  - ASLR (`randomize_va_space = 2`), ограничение `dmesg` и указателей ядра (`kptr_restrict`), защита символических и жёстких ссылок.
- **Харденинг SSH (`/etc/ssh/sshd_config.d/00-hardening.conf`)**:
  - Префикс `00-`, чтобы файл читался раньше файлов вендора и cloud-init (`50-cloud-init.conf`, `50-redhat.conf`): sshd использует первое прочитанное значение.
  - Оставляет вход по паролю (`PasswordAuthentication yes`), защищая его через PAM и Fail2ban.
  - Запрещает пустые пароли (`PermitEmptyPasswords no`).
  - Запрещает вход root по паролю (`prohibit-password`) — входить нужно обычным пользователем.
  - Ограничивает число попыток аутентификации до 5 (`MaxAuthTries 5`) в соответствии с Fail2ban.
  - Отключает проброс X11 и агента, задаёт тайм-аут неактивного клиента.
  - Проверяет синтаксис через `sshd -t` перед перезагрузкой службы.
  - Ubuntu 22.10+ использует активацию через `ssh.socket`: если вы меняете `security_ssh_port`, выполните `systemctl daemon-reload && systemctl restart ssh.socket` (или перезагрузите сервер), чтобы применить новый порт.
- **PAM и парольная политика**:
  - Устанавливает и включает модуль проверки качества паролей (`pam_pwquality` через `pam-auth-update` в Ubuntu, `authselect` в RHEL).
  - Требует пароль длиной не менее **12 символов** и разные классы символов в `/etc/security/pwquality.conf`.
  - Задаёт срок действия пароля **180 дней** (`PASS_MAX_DAYS 180`, `PASS_WARN_AGE 14`) в `/etc/login.defs`.
  - **Безопасный отбор учётных записей**: срок действия 180 дней применяется только к пользователям-людям (`UID >= UID_MIN`, есть оболочка входа) **с рабочим паролем**. Заблокированные учётные записи и записи только с ключами (например, `ubuntu`, `ec2-user`) пропускаются, чтобы не потерять доступ по SSH; дополнительные исключения задаются в `security_password_expiry_exclude_users`.
- **Аудит и обнаружение угроз**:
  - Устанавливает базовые правила `auditd` для контроля файлов учётных записей (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`), системного времени и локали.
  - Запускает неинтерактивный аудит безопасности **Lynis** (`lynis audit system --quick --cronjob`).

---

## Использование

### Вариант 1: Ansible (рекомендуется для инфраструктуры)

1. Отредактируйте `inventory.example.ini` (или создайте свой inventory):
```ini
[servers]
server1.example.com ansible_host=192.168.1.50 ansible_user=ubuntu
```

2. Установите нужные коллекции (`community.general`, `ansible.posix`):
```bash
ansible-galaxy collection install -r requirements.yml
```

3. Пробный запуск, затем применение:
```bash
ansible-playbook -i inventory.example.ini playbook.yml --check --diff
ansible-playbook -i inventory.example.ini playbook.yml
```

Переменные настраиваются в `roles/security_hardening/defaults/main.yml` (например, `security_ssh_port`, `security_password_authentication`, `security_password_max_days`, `security_rp_filter`, `security_upgrade_all_packages`, `security_selinux_allow_reboot`).

---

### Вариант 2: самостоятельные Bash-скрипты

#### Ubuntu / Debian:
```bash
sudo ./ubuntu_security.sh
```

#### RHEL / AlmaLinux / Rocky Linux:
```bash
sudo ./rhel_security.sh
```

---

## Проверка и журналы

Все результаты и отчёты сохраняются для проверки:
- **Отчёт Lynis**: `/var/log/lynis.log` и `/var/log/lynis-report.dat` (Bash-скрипты дополнительно пишут `/var/log/lynis-audit.log`)
- **Правила аудита**: `auditctl -l`
- **Состояние Fail2ban**: `fail2ban-client status sshd`
- **Состояние межсетевого экрана**: `ufw status verbose` или `firewall-cmd --list-all`

## Лицензия

Проект распространяется по лицензии MIT — подробности в файле [LICENSE](LICENSE).
