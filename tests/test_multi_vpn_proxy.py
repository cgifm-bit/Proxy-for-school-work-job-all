"""Unit tests for the Bash script added by PR #1.

Manual invocation on Linux (Python 3.9+, Bash 4+, GNU grep), from the repo root:
    python3 -B -m unittest discover -s tests -p 'test_multi_vpn_proxy.py' -v

Only function definitions and, for dispatch tests, the final case statement are
loaded. The privileged startup preamble is deliberately excluded. Each example
runs in a fresh Bash process with synthetic files and mocked host/network tools.
No VPN software, root access, network access, or Python packages are required.
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "VPN For project" / "More"
SERVERS = (
    ("usa", "us-free-67"),
    ("netherlands", "nl-free-244"),
    ("switzerland", "ch-free-9"),
    ("mexico", "mx-free-8"),
    ("japan", "jp-free-3"),
    ("canada", "ca-free-14"),
    ("us2", "us-free-24"),
    ("us3", "us-free-26"),
    ("us4", "us-free-85"),
    ("mx2", "mx-free-2"),
    ("us5", "us-free-1"),
    ("nl2", "nl-free-209"),
)

# Only these harmless utilities can resolve to external programs. Every command
# that changes host state, installs software, or contacts a network is a mock.
MOCKS = r'''
record() {
    { printf '%s' "$1"; shift; printf '\t%s' "$@"; printf '\n'; } >> "$CALLS"
}
sudo() {
    record sudo "$@"
    case "$1" in
        mkdir|cp|chmod|sed|tee|rm|ip|pkill|useradd|userdel) "$@" ;;
        apt-get|dnf|pacman|zypper|apk|make) return 0 ;;
        *) echo "Unexpected sudo command: $*" >&2; return 97 ;;
    esac
}
mkdir() {
    record mkdir "$@"
    local arg
    for arg in "$@"; do
        case "$arg" in -*) ;; "$TEST_ROOT"|"$TEST_ROOT"/*) ;;
            *) return 97 ;; esac
    done
    command mkdir "$@"
}
cp() {
    record cp "$@"
    local destination="${!#}"
    case "$destination" in
        "$TEST_ROOT"/*|"$TEMP_OVPN_PATH") command cp "$@" ;;
        /tmp/*) return 0 ;; # Credential copies are observed, never written globally.
        *) return 97 ;;
    esac
}
rm() {
    record rm "$@"
    local arg
    for arg in "$@"; do
        case "$arg" in -*) ;; "$TEST_ROOT"/*|"$TEMP_OVPN_PATH")
            command rm -rf -- "$arg" ;;
            *) : ;; # Ignore hardcoded host paths such as /tmp/credentials*.txt.
        esac
    done
}
tee() {
    case "${!#}" in "$TEST_ROOT"/*) command tee "$@" ;;
        *) record tee "$@"; command cat >/dev/null ;; esac
}
id() { record id "$@"; [[ " ${EXISTING_USERS:-} " == *" $1 "* ]]; }
useradd() { record useradd "$@"; return "${USERADD_EXIT:-0}"; }
userdel() { record userdel "$@"; }
pkill() { record pkill "$@"; return 1; }
kill() {
    record kill "$@"
    if [ "${1:-}" = -0 ]; then
        if [ "${KILL_STUCK:-0}" = 1 ]; then return 0; fi
        if [ "${KILL_CHECKS_LEFT:-0}" -gt 0 ]; then
            KILL_CHECKS_LEFT=$((KILL_CHECKS_LEFT - 1)); return 0
        fi
        return 1
    fi
}
sleep() { record sleep "$@"; }
ip() {
    record ip "$@"
    case "$*" in
        'rule del '*)
            if [ "${DELETE_RULES_LEFT:-0}" -gt 0 ]; then
                DELETE_RULES_LEFT=$((DELETE_RULES_LEFT - 1)); return 0
            fi
            return 1 ;;
        'addr show '*) return "${INTERFACE_EXIT:-0}" ;;
        '-4 addr show '*) printf '%s\n' "${IP_ADDRESS:-}" ;;
        'route show dev '*) printf '%s\n' "${IP_ROUTE:-}" ;;
        'rule add uidrange '*) return "${UID_RULE_EXIT:-0}" ;;
        'route add '*) return "${ROUTE_ADD_EXIT:-0}" ;;
    esac
}
iptables() { record iptables "$@"; return "${IPTABLES_EXIT:-0}"; }
netstat() { record netstat "$@"; printf '%s\n' "${LISTENERS:-}"; }
ps() { record ps "$@"; return "${PS_EXIT:-0}"; }
timeout() {
    record timeout "$@"
    case "${2:-}" in
        ping) return "${PING_EXIT:-0}" ;;
        curl)
            if [[ " $* " == *' --socks5 '* ]]; then
                printf '%s' "${PROXY_IP:-}"; return "${PROXY_CURL_EXIT:-0}"
            fi
            printf '%s' "${DIRECT_IP:-}"; return "${DIRECT_CURL_EXIT:-0}" ;;
        *) return 97 ;;
    esac
}
curl() { record curl "$@"; return 1; }
microsocks() { record microsocks "$@"; }
mktemp() { command mkdir -p "$TEST_ROOT/build"; printf '%s\n' "$TEST_ROOT/build"; }
su() { record su "$@"; }
openvpn() {
    record openvpn "$@"
    OPENVPN_ATTEMPTS=$((${OPENVPN_ATTEMPTS:-0} + 1))
    local previous='' arg
    for arg in "$@"; do
        case "$previous" in
            --config) command cat "$arg" >> "$TEST_ROOT/launched-configs" ;;
            --writepid) printf '424242\n' > "$arg" ;;
        esac
        previous="$arg"
    done
}
'''


class MultiVpnProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SCRIPT.read_text(encoding="utf-8")
        # Fail clearly if the source structure changes rather than running its
        # privileged preamble or silently testing an empty extraction.
        start = source.index("\nlog_info()") + 1
        marker = '\ncase "${1:-help}" in\n'
        if source.count(marker) != 1:
            raise AssertionError("Expected exactly one top-level CLI dispatcher")
        end = source.index(marker)
        cls.functions = source[start:end]
        cls.dispatch = source[end:]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vpn_name = self.root.name
        self.temp_ovpn = Path("/tmp") / (self.vpn_name + ".ovpn")
        self.addCleanup(lambda: self.temp_ovpn.unlink(missing_ok=True))
        for name in ("vpn", "logs", "run", "input"):
            (self.root / name).mkdir()
        self.calls = self.root / "calls"
        self.calls.touch()

    def fixture(self, name, text=""):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def bash(self, scenario, expected=0, args=(), dispatch=False):
        initialization = r'''
set -euo pipefail
PROJECT_DIR="$TEST_ROOT"
VPN_DIR="$TEST_ROOT/vpn"
LOG_DIR="$TEST_ROOT/logs"
RUN_DIR="$TEST_ROOT/run"
OVPN_DIR="$TEST_ROOT/input"
CONFIG_FILE="$VPN_DIR/vpn-config.conf"
GREEN='' RED='' YELLOW='' BLUE='' CYAN='' NC=''
'''
        # A minimal environment prevents inherited BASH_ENV, exported functions,
        # VPN credentials, or application configuration from affecting examples.
        env = {
            "PATH": os.defpath,
            "LC_ALL": "C.UTF-8",
            "TEST_ROOT": str(self.root),
            "CALLS": str(self.calls),
            "VPN_NAME": self.vpn_name,
            "TEMP_OVPN_PATH": str(self.temp_ovpn),
        }
        program = initialization + self.functions + MOCKS + "\n" + scenario
        if dispatch:
            program += self.dispatch
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", program, "multi-vpn-proxy", *args],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            timeout=4,
        )
        if expected is None:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def events(self, command=None):
        events = [tuple(line.split("\t")) for line in self.calls.read_text().splitlines()]
        return [event for event in events if command is None or event[0] == command]

    def configure_server(self, primary=True, backup=False):
        self.fixture("vpn/credentials.txt", "synthetic-user\nsynthetic-password\n")
        if primary:
            self.fixture("vpn/primary.ovpn", "client\ndev old-tunnel\nauth-user-pass\n")
        if backup:
            self.fixture("vpn/backup.ovpn", "client\ndev old-tunnel\nauth-user-pass\n")

    def setup_proxy(self, preparation="", backup="", expected=0):
        # Gateway and routing have their own unit tests; isolate orchestration.
        return self.bash(
            r'''
get_vpn_gateway() { record gateway "$@"; printf '10.8.0.1\n'; }
configure_routing_v3() { record routing "$@"; }
LISTENERS='tcp 0 0 127.0.0.1:1080 0.0.0.0:* LISTEN'
'''
            + preparation
            + '\nsetup_vpn_proxy "$VPN_NAME" primary.ovpn '
            + shlex.quote(backup)
            + ' 1080 100 tun0 || exit $?\nwait\n',
            expected=expected,
        )

    def test_discovery_reports_missing_directory(self):
        result = self.bash('VPN_DIR="$TEST_ROOT/missing"; discover_vpn_servers', expected=1)
        self.assertIn("no existe", result.stdout)
        self.assertEqual(self.events(), [])

    def test_discovery_ignores_unknown_files(self):
        self.fixture("vpn/unrecognized.ovpn")
        result = self.bash('discover_vpn_servers; printf "count=%s" "${#VPN_ORDER[@]}"')
        self.assertEqual(result.stdout, "count=0")

    def test_discovery_assigns_all_servers_unique_ports_tables_and_interfaces(self):
        for _, stem in reversed(SERVERS):
            self.fixture("vpn/" + stem + ".protonvpn.udp.ovpn")
        result = self.bash(
            'discover_vpn_servers; for name in "${VPN_ORDER[@]}"; do '
            'printf "%s=%s\\n" "$name" "${VPN_SERVERS[$name]}"; done'
        )
        expected = [
            f"{name}={1080 + i}:{100 + i}:tun{i}:{stem}.protonvpn.udp.ovpn::"
            for i, (name, stem) in enumerate(SERVERS)
        ]
        self.assertEqual(result.stdout.splitlines(), expected)

    def test_discovery_preserves_slot_when_only_last_server_exists(self):
        self.fixture("vpn/nl-free-209.protonvpn.udp.ovpn")
        result = self.bash(
            'discover_vpn_servers; printf "%s=%s" "${VPN_ORDER[0]}" "${VPN_SERVERS[nl2]}"'
        )
        self.assertEqual(result.stdout, "nl2=1091:111:tun11:nl-free-209.protonvpn.udp.ovpn::")

    def test_credentials_reject_missing_input_directory(self):
        result = self.bash('OVPN_DIR="$TEST_ROOT/missing"; integrate_credentials', expected=1)
        self.assertIn("No existe", result.stdout)
        self.assertEqual(self.events("cp"), [])

    def test_credentials_reject_missing_configs_or_credentials(self):
        for filename in ("credentials.txt", "only.ovpn"):
            with self.subTest(only_file=filename):
                path = self.fixture("input/" + filename, "fixture\n")
                # With pipefail, an unmatched ls glob can reject input before
                # the explicit count check. Require rejection without coupling
                # the test to either ls's or the function's error code.
                self.bash("integrate_credentials", expected=None)
                self.assertEqual(self.events("cp"), [])
                path.unlink()

    def test_credentials_assign_pairs_replace_auth_and_restrict_permissions(self):
        for name in ("credentials.txt", "credentials-2.txt", "credentials-3.txt", "credentials-4.txt"):
            self.fixture("input/" + name, "user\npassword\n")
        for i in range(8):
            self.fixture(f"input/{i:02}.ovpn", "client\nauth-user-pass stale\nauth-user-pass other\n")
        self.bash("integrate_credentials; integrate_credentials")
        for i in range(8):
            with self.subTest(config=i):
                suffix = "" if i < 2 else f"-{i // 2 + 1}"
                expected_auth = f"auth-user-pass {self.root}/vpn/credentials{suffix}.txt"
                content = (self.root / f"vpn/{i:02}.ovpn").read_text().splitlines()
                self.assertEqual(content, ["client", expected_auth])
        for credential in (self.root / "vpn").glob("credentials*.txt"):
            self.assertEqual(credential.stat().st_mode & 0o777, 0o600)

    def test_credentials_fall_back_when_numbered_file_is_missing(self):
        self.fixture("input/credentials.txt", "user\npassword\n")
        for i in range(4):
            self.fixture(f"input/{i}.ovpn", "client\n")
        self.bash("integrate_credentials")
        for i in range(4):
            self.assertEqual(
                (self.root / f"vpn/{i}.ovpn").read_text(),
                f"client\nauth-user-pass {self.root}/vpn/credentials.txt\n",
            )

    def test_create_users_assigns_reserved_uids_and_skips_existing_accounts(self):
        self.bash('EXISTING_USERS="vpnuser100 vpnuser111"; create_users')
        self.assertEqual(
            self.events("useradd"),
            [("useradd", "-r", "-s", "/bin/false", "-u", str(3000 + i), f"vpnuser{i}")
             for i in range(101, 111)],
        )

    def test_create_users_continues_after_useradd_failure(self):
        self.bash("USERADD_EXIT=1; create_users")
        self.assertEqual(len(self.events("useradd")), 12)

    def test_detect_distro_selects_first_available_package_manager(self):
        for available, expected in (("apt-get dnf", "apt"), ("dnf", "dnf"), ("pacman", "pacman"), ("zypper", "zypper"), ("apk", "apk")):
            with self.subTest(available=available):
                result = self.bash(
                    "AVAILABLE=" + shlex.quote(available) + r'''
command() {
    if [ "${1:-}" = -v ]; then
        [[ " $AVAILABLE " == *" $2 "* ]]
    else
        builtin command "$@"
    fi
}
detect_distro
printf '%s' "$PKG_MANAGER"
'''
                )
                self.assertEqual(result.stdout, expected)

    def test_detect_distro_rejects_unsupported_package_managers(self):
        result = self.bash("command() { return 1; }; detect_distro", expected=1)
        self.assertIn("Gestor de paquetes no soportado", result.stdout)

    def test_setup_directories_registers_each_routing_table_only_once(self):
        self.fixture("rt_tables", "255 local\n100 usa\n")
        self.bash(r'''
# Redirect only the hardcoded routing-table file; retain real grep/tee behavior.
mkdir() { record mkdir "$@"; }
grep() {
    local args=() arg
    for arg in "$@"; do
        if [ "$arg" = /etc/iproute2/rt_tables ]; then
            args+=("$TEST_ROOT/rt_tables")
        else args+=("$arg"); fi
    done
    command grep "${args[@]}"
}
tee() { command tee -a "$TEST_ROOT/rt_tables"; }
setup_directories
setup_directories
''')
        self.assertEqual(
            (self.root / "rt_tables").read_text().splitlines(),
            ["255 local"] + [f"{100 + i} {name}" for i, (name, _) in enumerate(SERVERS)],
        )

    def test_cleanup_system_removes_managed_files_users_and_routes(self):
        self.fixture("vpn/old.ovpn", "stale\n")
        self.fixture("logs/old.log", "stale\n")
        self.fixture("run/openvpn-old.pid", "424242\n")
        self.fixture("run/microsocks-old.pid", "434343\n")
        unrelated = self.fixture("run/unrelated.pid", "444444\n")
        self.bash("cleanup_system")
        self.assertEqual(list((self.root / "vpn").iterdir()), [])
        self.assertEqual(list((self.root / "logs").iterdir()), [])
        self.assertEqual(list((self.root / "run").iterdir()), [unrelated])
        self.assertEqual(self.events("userdel"), [("userdel", f"vpnuser{i}") for i in range(100, 112)])
        for i in range(100, 112):
            with self.subTest(table=i):
                self.assertIn(("ip", "route", "flush", "table", str(i)), self.events("ip"))
                self.assertIn(("ip", "rule", "del", "uidrange", f"{3000 + i}-{3000 + i}"), self.events("ip"))

    def test_dependency_install_selects_platform_packages(self):
        packages = {
            "apt": [("apt-get", "update"), ("apt-get", "install", "-y", "openvpn", "curl", "iproute2", "iptables", "net-tools")],
            "dnf": [("dnf", "install", "-y", "openvpn", "curl", "iproute", "iptables", "net-tools")],
            "pacman": [("pacman", "-S", "--noconfirm", "openvpn", "curl", "iproute2", "iptables")],
            "zypper": [("zypper", "install", "-y", "openvpn", "curl", "iproute2", "iptables")],
            "apk": [("apk", "add", "openvpn", "curl", "iproute2", "iptables")],
        }
        for manager, expected in packages.items():
            with self.subTest(manager=manager):
                self.calls.write_text("")
                self.bash(f"PKG_MANAGER={manager}; install_dependencies")
                self.assertEqual(self.events("sudo"), [("sudo", *args) for args in expected])
                self.assertEqual(self.events("curl"), [])

    def test_build_dependencies_include_unzip_on_every_platform_regression(self):
        for manager in ("apt", "dnf", "pacman", "zypper", "apk"):
            with self.subTest(manager=manager):
                self.calls.write_text("")
                result = self.bash(
                    f"PKG_MANAGER={manager}; unset -f microsocks; install_dependencies", expected=1
                )
                self.assertIn("unzip", self.events("sudo")[-1])
                self.assertEqual(len(self.events("curl")), 1)
                self.assertIn("No se pudo descargar microsocks", result.stdout)

    def test_dependency_build_installs_microsocks_and_removes_build_directory(self):
        self.bash(r'''
PKG_MANAGER=dnf
unset -f microsocks
command mkdir -p "$TEST_ROOT/build/microsocks-fixture"
curl() { record curl "$@"; }
unzip() { record unzip "$@"; }
make() { record make "$@"; }
install_dependencies
printf '%s' "$PWD"
''')
        self.assertEqual(self.events("unzip"), [("unzip", "-q", "microsocks.zip")])
        self.assertIn(("sudo", "make", "install"), self.events("sudo"))
        self.assertEqual(len(self.events("make")), 1)
        self.assertFalse((self.root / "build").exists())

    def test_dependency_build_stops_before_make_if_archive_is_invalid(self):
        result = self.bash(r'''
PKG_MANAGER=apk
unset -f microsocks
curl() { record curl "$@"; }
unzip() { record unzip "$@"; return 1; }
make() { record make "$@"; }
install_dependencies
''', expected=1)
        self.assertIn("No se pudo descomprimir microsocks", result.stdout)
        self.assertEqual(self.events("make"), [])

    def test_gateway_uses_latest_log_gateway_without_waiting(self):
        self.fixture("logs/usa-openvpn.log", "route_gateway 10.1.0.1\nroute_gateway 10.2.0.1\n")
        result = self.bash("get_vpn_gateway tun0 usa")
        self.assertEqual(result.stdout, "10.2.0.1\n")
        self.assertEqual(self.events("sleep"), [])
        self.assertEqual(self.events("ip"), [])

    def test_gateway_falls_back_to_route_then_interface_then_remote(self):
        cases = (
            ("IP_ROUTE='default via 10.3.0.1 dev tun0'", "", "10.3.0.1"),
            ("IP_ADDRESS='inet 10.4.7.23/24 scope global tun0'", "", "10.4.7.1"),
            ("", "UDPv4 link remote: [AF_INET]198.51.100.7:1194\n", "198.51.100.7"),
        )
        for preparation, log, expected in cases:
            with self.subTest(expected=expected):
                self.calls.write_text("")
                self.fixture("logs/usa-openvpn.log", log)
                # Production uses this function in a conditional assignment;
                # preserve that context for pipelines that find no log match.
                result = self.bash(preparation + "\nget_vpn_gateway tun0 usa || exit $?\n")
                self.assertEqual(result.stdout, expected + "\n")
                self.assertEqual(len(self.events("sleep")), 30)

    def test_gateway_reports_exhausted_sources_on_stderr(self):
        result = self.bash("get_vpn_gateway tun9 missing || exit $?", expected=1)
        self.assertEqual(result.stdout, "")
        self.assertIn("No se pudo detectar gateway VPN para tun9", result.stderr)
        self.assertEqual(len(self.events("sleep")), 30)

    def test_connectivity_requires_interface_before_ping(self):
        self.bash("INTERFACE_EXIT=1; test_vpn_connectivity tun0", expected=1)
        self.assertEqual(self.events("timeout"), [])

    def test_connectivity_uses_requested_timeout_and_propagates_ping_failure(self):
        for timeout, status in ((None, 0), (10, 0), (2, 124)):
            with self.subTest(timeout=timeout, ping_status=status):
                self.calls.write_text("")
                argument = "" if timeout is None else f" {timeout}"
                self.bash(
                    f"PING_EXIT={status}; test_vpn_connectivity tun7{argument}",
                    expected=0 if status == 0 else 1,
                )
                self.assertEqual(
                    self.events("timeout"),
                    [("timeout", str(timeout or 5), "ping", "-I", "tun7", "-c", "2", "8.8.8.8")],
                )

    def test_save_active_config_uppercases_name_and_appends(self):
        self.bash('save_active_config usa first.ovpn; save_active_config nl2 "backup file.ovpn"')
        self.assertEqual(
            (self.root / "vpn/vpn-config.conf").read_text(),
            'ACTIVE_USA="first.ovpn"\nACTIVE_NL2="backup file.ovpn"\n',
        )

    def test_routing_binds_uid_and_fwmark_to_correct_table_and_priorities(self):
        self.bash(
            "IP_ADDRESS='inet 10.8.0.2/24 scope global tun11'; DELETE_RULES_LEFT=2; "
            "configure_routing_v3 nl2 tun11 111 3111 10.8.0.1"
        )
        calls = self.events("ip")
        self.assertIn(("ip", "route", "add", "10.8.0.2/24", "dev", "tun11", "scope", "link", "table", "111"), calls)
        self.assertIn(("ip", "route", "add", "default", "via", "10.8.0.1", "dev", "tun11", "table", "111"), calls)
        self.assertIn(("ip", "rule", "add", "uidrange", "3111-3111", "table", "111", "priority", "10111"), calls)
        self.assertIn(("ip", "rule", "add", "fwmark", "111", "table", "111", "priority", "11111"), calls)
        self.assertEqual(len([call for call in calls if call[1:4] == ("rule", "del", "fwmark")]), 3)
        self.assertEqual(
            self.events("iptables"),
            [("iptables", "-t", "mangle", action, "OUTPUT", "-m", "owner", "--uid-owner", "3111", "-j", "MARK", "--set-mark", "111")
             for action in ("-D", "-A")],
        )

    def test_routing_tolerates_existing_routes(self):
        self.bash("ROUTE_ADD_EXIT=2; configure_routing_v3 usa tun0 100 3100 10.8.0.1")
        self.assertEqual(len(self.events("iptables")), 2)

    def test_routing_stops_if_required_uid_rule_cannot_be_created(self):
        self.bash("UID_RULE_EXIT=2; configure_routing_v3 usa tun0 100 3100 10.8.0.1", expected=2)
        self.assertEqual(self.events("iptables"), [])

    def test_setup_primary_config_launches_daemon_routes_and_loopback_proxy(self):
        self.configure_server()
        self.setup_proxy()
        config = (self.root / "launched-configs").read_text().splitlines()
        self.assertNotIn("dev old-tunnel", config)
        self.assertIn("dev tun0", config)
        self.assertIn("route-nopull", config)
        self.assertIn('pull-filter ignore "dhcp-option DNS"', config)
        self.assertEqual(len(self.events("openvpn")), 1)
        launch = self.events("openvpn")[0]
        self.assertIn("--daemon", launch)
        self.assertIn(str(self.root / f"run/openvpn-{self.vpn_name}.pid"), launch)
        self.assertEqual(self.events("routing"), [("routing", self.vpn_name, "tun0", "100", "3100", "10.8.0.1")])
        self.assertEqual(self.events("su"), [("su", "-s", "/bin/bash", "vpnuser100", "-c", "microsocks -i 127.0.0.1 -p 1080")])
        self.assertIn('="primary.ovpn"', (self.root / "vpn/vpn-config.conf").read_text())
        self.assertTrue((self.root / f"run/microsocks-{self.vpn_name}.pid").read_text().strip().isdigit())
        self.assertFalse(self.temp_ovpn.exists())
        self.assertIn("dev old-tunnel", (self.root / "vpn/primary.ovpn").read_text())

    def test_setup_uses_backup_when_primary_file_is_missing(self):
        self.configure_server(primary=False, backup=True)
        self.setup_proxy(backup="backup.ovpn")
        self.assertIn('="backup.ovpn"', (self.root / "vpn/vpn-config.conf").read_text())
        self.assertEqual(len(self.events("openvpn")), 1)

    def test_setup_missing_both_configs_does_not_launch_any_process(self):
        self.setup_proxy(backup="missing.ovpn", expected=1)
        self.assertEqual(self.events("openvpn"), [])
        self.assertEqual(self.events("su"), [])
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())

    def test_setup_uses_backup_after_connectivity_failure(self):
        self.configure_server(backup=True)
        self.setup_proxy(
            preparation='test_vpn_connectivity() { [ "$OPENVPN_ATTEMPTS" -eq 2 ]; }',
            backup="backup.ovpn",
        )
        self.assertEqual(len(self.events("openvpn")), 2)
        self.assertIn(("kill", "424242"), self.events("kill"))
        self.assertIn('="backup.ovpn"', (self.root / "vpn/vpn-config.conf").read_text())

    def test_setup_stops_after_two_failed_connectivity_attempts(self):
        self.configure_server(backup=True)
        self.setup_proxy("PING_EXIT=1", backup="backup.ovpn", expected=1)
        self.assertEqual(len(self.events("openvpn")), 2)
        self.assertEqual(len(self.events("kill")), 2)
        self.assertEqual(self.events("routing"), [])
        self.assertEqual(self.events("su"), [])
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())
        self.assertFalse((self.root / f"run/openvpn-{self.vpn_name}.pid").exists())
        self.assertFalse(self.temp_ovpn.exists())

    def test_setup_rejects_tunnel_that_never_appears(self):
        self.configure_server()
        self.setup_proxy("INTERFACE_EXIT=1", expected=1)
        self.assertEqual(len(self.events("sleep")), 30)
        self.assertEqual(self.events("routing"), [])
        self.assertEqual(self.events("su"), [])
        self.assertFalse(self.temp_ovpn.exists())

    def test_setup_does_not_launch_proxy_without_gateway(self):
        self.configure_server()
        self.setup_proxy('get_vpn_gateway() { return 1; }', expected=1)
        self.assertEqual(self.events("routing"), [])
        self.assertEqual(self.events("su"), [])

    def test_setup_rejects_unopened_proxy_port_after_bounded_wait(self):
        self.configure_server()
        self.setup_proxy("LISTENERS=''", expected=1)
        self.assertEqual(len(self.events("netstat")), 30)
        self.assertEqual(len(self.events("sleep")), 30)

    @unittest.expectedFailure
    def test_setup_honors_standard_auth_user_pass_path(self):
        # Known source defect: awk reads field 3, whereas standard OpenVPN
        # auth-user-pass has its credentials path in field 2. Keep this as an
        # executable regression without changing production code in a tests task.
        self.configure_server()
        custom = self.fixture("vpn/custom.txt", "custom-user\ncustom-password\n")
        self.fixture("vpn/primary.ovpn", f"client\nauth-user-pass {custom}\n")
        self.setup_proxy()
        self.assertIn(("cp", str(custom), "/tmp/custom.txt"), self.events("cp"))

    def test_cleanup_removes_state_even_when_processes_are_already_gone(self):
        self.fixture(f"run/openvpn-{self.vpn_name}.pid", "424242\n")
        self.fixture(f"run/microsocks-{self.vpn_name}.pid", "434343\n")
        unrelated = self.fixture("run/unrelated.pid", "444444\n")
        self.bash('cleanup_vpn "$VPN_NAME" 100 1080; cleanup_vpn "$VPN_NAME" 100 1080')
        self.assertEqual(list((self.root / "run").iterdir()), [unrelated])
        self.assertIn(("kill", "-9", "434343"), self.events("kill"))
        self.assertNotIn(("kill", "-TERM", "424242"), self.events("kill"))
        self.assertIn(("pkill", "-9", "-U", "3100"), self.events("pkill"))
        self.assertIn(("ip", "route", "flush", "table", "100"), self.events("ip"))

    def test_cleanup_prefers_graceful_termination(self):
        self.fixture(f"run/openvpn-{self.vpn_name}.pid", "424242\n")
        self.bash('KILL_CHECKS_LEFT=1; cleanup_vpn "$VPN_NAME" 100 1080')
        self.assertIn(("kill", "-TERM", "424242"), self.events("kill"))
        self.assertNotIn(("kill", "-KILL", "424242"), self.events("kill"))

    def test_cleanup_escalates_after_ten_checks_for_stuck_process(self):
        self.fixture(f"run/openvpn-{self.vpn_name}.pid", "424242\n")
        self.bash('KILL_STUCK=1; cleanup_vpn "$VPN_NAME" 100 1080')
        self.assertEqual(len(self.events("sleep")), 10)
        self.assertIn(("kill", "-KILL", "424242"), self.events("kill"))
        self.assertFalse((self.root / f"run/openvpn-{self.vpn_name}.pid").exists())

    def test_start_continues_after_one_server_fails_and_clears_stale_state(self):
        for _, stem in SERVERS[:2]:
            self.fixture("vpn/" + stem + ".protonvpn.udp.ovpn")
        self.fixture("vpn/vpn-config.conf", "stale\n")
        self.fixture("run/openvpn-old.pid", "424242\n")
        result = self.bash(r'''
setup_vpn_proxy() { record setup "$@"; [ "$1" != usa ]; }
show_status() { record status shown; }
start_system
''')
        self.assertEqual([call[1] for call in self.events("setup")], ["usa", "netherlands"])
        self.assertEqual(self.events("setup")[1][2:], ("nl-free-244.protonvpn.udp.ovpn", "", "1081", "101", "tun1"))
        self.assertIn("No se pudo iniciar usa", result.stdout)
        self.assertEqual(self.events("status"), [("status", "shown")])
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())
        self.assertFalse((self.root / "run/openvpn-old.pid").exists())

    def test_stop_dispatches_cleanup_for_discovered_servers(self):
        self.fixture("vpn/us-free-67.protonvpn.udp.ovpn")
        self.fixture("vpn/nl-free-209.protonvpn.udp.ovpn")
        self.fixture("vpn/vpn-config.conf", "stale\n")
        self.bash('cleanup_vpn() { record cleanup "$@"; }; stop_system')
        self.assertEqual(self.events("cleanup"), [("cleanup", "usa", "100", "1080"), ("cleanup", "nl2", "111", "1091")])
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())

    def test_status_reports_running_tunnel_proxy_and_public_addresses(self):
        self.fixture("vpn/us-free-67.protonvpn.udp.ovpn")
        self.fixture("run/openvpn-usa.pid", "424242\n")
        result = self.bash(r'''
IP_ADDRESS='inet 10.8.0.2/24 scope global tun0'
LISTENERS='tcp 0 0 127.0.0.1:1080 0.0.0.0:* LISTEN'
PROXY_IP=198.51.100.8 DIRECT_IP=203.0.113.9
discover_vpn_servers
show_status
''')
        for text in ("usa running", "Interface: tun0 (10.8.0.2)", "Proxy: 127.0.0.1:1080", "Public IP: 198.51.100.8", "Direct IP: 203.0.113.9"):
            self.assertIn(text, result.stdout)

    def test_status_ignores_stale_pid_and_handles_failed_direct_ip_lookup(self):
        self.fixture("vpn/us-free-67.protonvpn.udp.ovpn")
        self.fixture("run/openvpn-usa.pid", "424242\n")
        result = self.bash("PS_EXIT=1; DIRECT_CURL_EXIT=124; discover_vpn_servers; show_status")
        self.assertNotIn("usa running", result.stdout)
        self.assertIn("Direct IP: unknown", result.stdout)
        self.assertEqual(self.events("timeout"), [("timeout", "5", "curl", "-s", "https://ifconfig.me")])

    def test_proxy_connection_report_handles_success_and_timeout(self):
        self.fixture("vpn/us-free-67.protonvpn.udp.ovpn")
        for preparation, indicator in (("PROXY_IP=198.51.100.3", "✓ 198.51.100.3"), ("PROXY_CURL_EXIT=124", "✗")):
            with self.subTest(preparation=preparation):
                result = self.bash(preparation + "; test_system")
                self.assertIn("Probando usa (1080)", result.stdout)
                self.assertIn(indicator, result.stdout)
        self.assertEqual(self.events("timeout")[-1], ("timeout", "15", "curl", "--socks5", "127.0.0.1:1080", "-s", "https://ifconfig.me"))

    def test_cli_help_aliases_and_default_are_non_destructive(self):
        for args in ((), ("help",), ("--help",), ("-h",), ("",)):
            with self.subTest(args=args):
                result = self.bash("", args=args, dispatch=True)
                self.assertIn("VPN Multi-Proxy Script", result.stdout)
                for command in ("install", "full", "start", "stop", "restart", "status", "test", "help"):
                    self.assertIn("multi-vpn-proxy " + command, result.stdout)
                self.assertEqual(self.events(), [])

    def test_cli_unknown_command_returns_failure_and_help(self):
        result = self.bash("", args=("not-a-command",), dispatch=True, expected=1)
        self.assertIn("Comando desconocido: not-a-command", result.stdout)
        self.assertIn("VPN Multi-Proxy Script", result.stdout)
        self.assertEqual(self.events(), [])

    def test_cli_dispatches_commands_and_restart_in_order(self):
        hooks = r'''
for hook in detect_distro cleanup_system install_dependencies setup_directories integrate_credentials create_users start_system stop_system discover_vpn_servers show_status test_system; do
    eval "$hook() { record action $hook; }"
done
'''
        actions = {
            "install": ["detect_distro", "install_dependencies", "setup_directories", "integrate_credentials", "create_users"],
            "full": ["detect_distro", "cleanup_system", "install_dependencies", "setup_directories", "integrate_credentials", "create_users"],
            "start": ["start_system"],
            "stop": ["stop_system"],
            "restart": ["stop_system", "start_system"],
            "status": ["discover_vpn_servers", "show_status"],
            "test": ["test_system"],
        }
        for command, expected in actions.items():
            with self.subTest(command=command):
                self.calls.write_text("")
                self.bash(hooks, args=(command,), dispatch=True)
                self.assertEqual(self.events("action"), [("action", action) for action in expected])
                if command == "restart":
                    self.assertEqual(self.events(), [("action", "stop_system"), ("sleep", "3"), ("action", "start_system")])


if __name__ == "__main__":
    unittest.main()
