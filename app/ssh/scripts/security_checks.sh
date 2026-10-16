# debcontrol security checks, run by `sh -s` on a managed machine next to
# Lynis (see app/ssh/security_checks.py). Read-only: nothing on the machine
# is changed, nothing is downloaded or uploaded. The checks follow
# vps-audit (https://github.com/nuver-labs/vps-audit, MIT license, (c) 2024
# Israel Abebe Kokiso), adapted to run without root where possible; a
# check that needs root and doesn't have it reports "skip". vps-audit's
# disk, memory and CPU checks are left out (debcontrol's monitoring
# covers them), and so is its public-IP lookup (no outbound requests).
#
# Output: one line per check,
#   DEBCONTROL_CHECK|<id>|<pass|warn|fail|info|skip>|<value>
# POSIX sh only: /bin/sh is dash on Debian.

ROOT=0
[ "$(id -u)" = 0 ] && ROOT=1

dc_check() {
    printf 'DEBCONTROL_CHECK|%s|%s|%s\n' "$1" "$2" \
        "$(printf '%s' "$3" | tr '|\n\t' '/  ' | cut -c1-400)"
}

dc_has() { command -v "$1" >/dev/null 2>&1; }

dc_active() { dc_has systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

# --- Restart pending ---------------------------------------------------
if [ -f /var/run/reboot-required ]; then
    dc_check reboot_required warn "$(sort -u /var/run/reboot-required.pkgs 2>/dev/null | head -8 | tr '\n' ' ')"
else
    dc_check reboot_required pass ""
fi

# --- SSH daemon --------------------------------------------------------
# sshd's own view (`sshd -T`, root only) or else the config files, read the
# way sshd reads them: Include expanded in place, the first value wins,
# nothing after the first Match block.
SSHD_T=
if [ $ROOT = 1 ]; then
    for s in sshd /usr/sbin/sshd; do
        SSHD_T=$("$s" -T 2>/dev/null) && [ -n "$SSHD_T" ] && break
    done
fi

dc_sshconf() {
    sed -e 's/^[[:space:]]*//' /etc/ssh/sshd_config 2>/dev/null | while IFS= read -r l; do
        case "$l" in
            [Ii]nclude[[:space:]]*)
                for p in ${l#*[[:space:]]}; do
                    case "$p" in /*) ;; *) p="/etc/ssh/$p" ;; esac
                    for g in $p; do
                        [ -r "$g" ] && sed -e 's/^[[:space:]]*//' "$g"
                    done
                done
                ;;
            *) printf '%s\n' "$l" ;;
        esac
    done
}

dc_sshopt() {
    if [ -n "$SSHD_T" ]; then
        printf '%s\n' "$SSHD_T" | awk -v k="$1" 'tolower($1) == k { print tolower($2); exit }'
    else
        dc_sshconf | awk -v k="$1" '
            tolower($1) == "match" { exit }
            { sub(/=/, " ") }
            tolower($1) == k { print tolower($2); exit }'
    fi
}

if [ -n "$SSHD_T" ] || [ -r /etc/ssh/sshd_config ]; then
    v=$(dc_sshopt permitrootlogin)
    [ -n "$v" ] || v=prohibit-password
    case "$v" in
        no) dc_check ssh_root_login pass "$v" ;;
        yes) dc_check ssh_root_login fail "$v" ;;
        *) dc_check ssh_root_login warn "$v" ;;
    esac

    v=$(dc_sshopt passwordauthentication)
    [ -n "$v" ] || v=yes
    if [ "$v" = no ]; then dc_check ssh_password_auth pass "$v"; else dc_check ssh_password_auth fail "$v"; fi

    SSH_PORT=$(dc_sshopt port)
    [ -n "$SSH_PORT" ] || SSH_PORT=22
    dc_check ssh_port info "$SSH_PORT"
elif [ -e /etc/ssh/sshd_config ]; then
    dc_check ssh_root_login skip "unreadable"
    dc_check ssh_password_auth skip "unreadable"
    dc_check ssh_port skip "unreadable"
fi

# --- Firewall ----------------------------------------------------------
# Rules in an input hook that drop something, not merely a firewall tool
# being installed (iptables-nft leaves an empty INPUT chain behind).
FW=
if dc_has ufw; then
    if [ $ROOT = 1 ]; then
        ufw status 2>/dev/null | grep -q '^Status: active' && FW=ufw
    elif grep -qi '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null && dc_active ufw; then
        FW=ufw
    fi
fi
[ -z "$FW" ] && dc_active firewalld && FW=firewalld
if [ -z "$FW" ] && [ $ROOT = 1 ]; then
    if dc_has pve-firewall && pve-firewall status 2>/dev/null | grep -q 'enabled/running'; then
        FW=pve-firewall
    elif dc_has nft; then
        nft list ruleset 2>/dev/null | awk '
            /^[[:space:]]*chain .*\{/ { inchain = 1; hook = 0; rules = 0; drop = 0; next }
            inchain && /hook input/ { hook = 1; if (/policy drop/) drop = 1; next }
            inchain && /^[[:space:]]*\}/ { if (hook && (rules || drop)) found = 1; inchain = 0; next }
            inchain && NF { rules++ }
            END { exit !found }' && FW=nftables
    elif dc_has iptables; then
        iptables -S INPUT 2>/dev/null | grep -qv '^-P INPUT ACCEPT' && FW=iptables
    fi
fi
if [ -n "$FW" ]; then
    dc_check firewall pass "$FW"
elif [ $ROOT = 1 ]; then
    dc_check firewall fail ""
else
    dc_check firewall skip "root"
fi

# --- Automatic security updates ----------------------------------------
if dc_has dpkg-query; then
    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'ok installed'; then
        if apt-config dump 2>/dev/null | grep -q '^APT::Periodic::Unattended-Upgrade "1"'; then
            dc_check auto_updates pass "unattended-upgrades"
        else
            dc_check auto_updates warn "disabled"
        fi
    else
        dc_check auto_updates warn "missing"
    fi
fi

# --- Intrusion prevention (fail2ban, CrowdSec) -------------------------
IPS=
for s in fail2ban crowdsec; do
    dc_active "$s" && IPS="$IPS $s"
done
if [ -z "$IPS" ] && dc_has docker; then
    IPS=$(docker ps --format '{{.Image}}' 2>/dev/null | grep -Eo 'fail2ban|crowdsec' | sort -u | tr '\n' ' ')
fi
IPS=$(printf '%s' "$IPS" | sed -e 's/^ *//' -e 's/ *$//')
if [ -n "$IPS" ]; then
    dc_check intrusion_prevention pass "$IPS"
elif dc_has fail2ban-client || dc_has cscli; then
    dc_check intrusion_prevention warn "stopped"
else
    dc_check intrusion_prevention fail ""
fi

# --- fail2ban's SSH jail covers the port sshd listens on ---------------
# A jail on port 22 while sshd listens elsewhere bans nothing at all.
dc_jail_opt() {
    r=
    for f in /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local; do
        [ -r "$f" ] || continue
        v=$(awk -v sect="$1" -v opt="$2" '
            /^[[:space:]]*\[/ { s = $0; gsub(/[][[:space:]]/, "", s); in_sect = (s == sect); next }
            in_sect {
                l = $0; sub(/^[[:space:]]*/, "", l)
                if (index(l, opt) == 1) {
                    rest = substr(l, length(opt) + 1); sub(/^[[:space:]]*/, "", rest)
                    if (substr(rest, 1, 1) == "=") { sub(/^=[[:space:]]*/, "", rest); sub(/[[:space:]]+$/, "", rest); val = rest }
                }
            }
            END { if (val != "") print val }' "$f")
        [ -n "$v" ] && r=$v
    done
    printf '%s' "$r"
}

dc_port_num() {
    case "$1" in
        *[!0-9]*) getent services "$1" 2>/dev/null | awk '{ split($2, a, "/"); print a[1]; exit }' ;;
        *) printf '%s' "$1" ;;
    esac
}

dc_ports_cover() {
    old_ifs=$IFS
    IFS=,
    for tok in $1; do
        IFS=$old_ifs
        tok=$(printf '%s' "$tok" | tr -d '[:space:]')
        case "$tok" in
            "") ;;
            *:*)
                a=$(dc_port_num "${tok%%:*}")
                b=$(dc_port_num "${tok##*:}")
                if [ -n "$a" ] && [ -n "$b" ] && [ "$2" -ge "$a" ] 2>/dev/null && [ "$2" -le "$b" ] 2>/dev/null; then
                    return 0
                fi
                ;;
            *) [ "$(dc_port_num "$tok")" = "$2" ] && return 0 ;;
        esac
        IFS=,
    done
    IFS=$old_ifs
    return 1
}

if dc_has fail2ban-client && [ -d /etc/fail2ban ]; then
    if [ ! -r /etc/fail2ban/jail.conf ]; then
        dc_check fail2ban_ssh_port skip "unreadable"
    else
        en=$(dc_jail_opt sshd enabled)
        port=$(dc_jail_opt sshd port)
        ban=$(dc_jail_opt sshd banaction)
        [ -n "$ban" ] || ban=$(dc_jail_opt DEFAULT banaction)
        [ -n "$port" ] || port=ssh
        p=${SSH_PORT:-22}
        if [ "$en" != true ]; then
            dc_check fail2ban_ssh_port warn "disabled"
        elif printf '%s' "$ban" | grep -q allports; then
            dc_check fail2ban_ssh_port pass "$ban"
        elif dc_ports_cover "$port" "$p"; then
            dc_check fail2ban_ssh_port pass "$port"
        else
            dc_check fail2ban_ssh_port fail "jail: $port, sshd: $p"
        fi
    fi
fi

# --- Failed SSH logins, last 24 hours ----------------------------------
# journalctl shows a user only their own messages unless they are root or
# in one of these groups, without saying so: count only when it can see
# everything.
CAN_JOURNAL=0
if [ $ROOT = 1 ]; then
    CAN_JOURNAL=1
else
    for g in $(id -nG 2>/dev/null); do
        case "$g" in adm | systemd-journal | wheel) CAN_JOURNAL=1 ;; esac
    done
fi
if dc_has journalctl && [ $CAN_JOURNAL = 1 ]; then
    n=$(journalctl -q --no-pager --since "24 hours ago" SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null | grep -c 'Failed password')
    src=journal
elif [ -r /var/log/auth.log ]; then
    n=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null)
    src=auth.log
else
    n=
fi
if [ -z "$n" ]; then
    dc_check failed_logins skip "unreadable"
elif [ "$n" -ge 50 ]; then
    dc_check failed_logins fail "$n ($src)"
elif [ "$n" -ge 10 ]; then
    dc_check failed_logins warn "$n ($src)"
else
    dc_check failed_logins pass "$n ($src)"
fi

# --- Pending updates (from the package lists already on the machine) ---
if dc_has apt-get; then
    sim=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep '^Inst ')
    all=$(printf '%s' "$sim" | grep -c '^Inst ')
    sec=$(printf '%s' "$sim" | grep -c -- '-security')
    if [ "$sec" -gt 0 ]; then
        dc_check pending_updates fail "$all/$sec"
    elif [ "$all" -gt 0 ]; then
        dc_check pending_updates warn "$all/0"
    else
        dc_check pending_updates pass "0/0"
    fi
fi

# --- Running services --------------------------------------------------
if dc_has systemctl; then
    dc_check running_services info "$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | wc -l | tr -d ' ')"
fi

# --- Ports listening on other than loopback ----------------------------
if dc_has ss; then
    ports=$(ss -tulnH 2>/dev/null | awk '
        { addr = $5; proto = ($1 == "tcp" ? "tcp" : "udp") }
        addr ~ /^127\./ || addr ~ /^\[::1\]/ || addr ~ /^::1:/ || addr ~ /%lo:/ { next }
        { n = split(addr, a, ":"); print a[n] "/" proto }' | sort -u | sort -t/ -k1,1n | tr '\n' ' ' | sed 's/ $//')
    count=$(printf '%s' "$ports" | wc -w | tr -d ' ')
    if [ "$count" -ge 20 ]; then
        dc_check listening_ports fail "$ports"
    elif [ "$count" -ge 10 ]; then
        dc_check listening_ports warn "$ports"
    else
        dc_check listening_ports pass "$ports"
    fi
fi

# --- sudo writes its own log file --------------------------------------
if [ $ROOT = 1 ]; then
    if grep -Eqs '^[[:space:]]*Defaults.*(logfile|log_output)' /etc/sudoers /etc/sudoers.d/*; then
        dc_check sudo_logging pass ""
    else
        dc_check sudo_logging warn ""
    fi
else
    dc_check sudo_logging skip "root"
fi

# --- Password quality (pam_pwquality) ----------------------------------
ml=$(cat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null \
    | sed -n 's/^[[:space:]]*minlen[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' | tail -1)
if [ -z "$ml" ]; then
    dc_check password_policy warn ""
elif [ "$ml" -ge 12 ]; then
    dc_check password_policy pass "$ml"
else
    dc_check password_policy warn "$ml"
fi

# --- SUID programs outside the usual places ----------------------------
# The root file system only (-xdev: no data disks or network mounts), and
# not container image layers.
TO=
dc_has timeout && TO="timeout 300"
suid=$($TO find / -xdev \( -path /proc -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers -o -path /snap \) -prune -o -type f -perm -4000 -print 2>/dev/null \
    | grep -Ev '^(/usr/bin/|/bin/|/sbin/|/usr/sbin/|/usr/lib|/usr/libexec)' \
    | grep -Ev '(ping|sudo|mount|umount|su|passwd|chsh|newgrp|gpasswd|chfn)$')
if [ -z "$suid" ]; then
    dc_check suid_files pass ""
else
    dc_check suid_files warn "$(printf '%s\n' "$suid" | head -10 | tr '\n' ' ')"
fi
