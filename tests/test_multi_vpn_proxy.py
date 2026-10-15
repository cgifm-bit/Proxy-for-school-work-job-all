"""Unit tests for the Bash script added by PR #1.

Run explicitly with: python3 -m unittest discover -s tests -p 'test_multi_vpn_proxy.py' -v
Requires Bash 4.2+ and GNU coreutils/grep/sed; no third party Python packages,
root privileges, VPN software, package installation, or network access.

The script performs privileged work even when sourced with 'help'. Load its
function definitions and command dispatcher separately, omitting the startup
prologue. Redirect hardcoded /tmp and /etc paths to each test's temporary
directory; leave the function logic intact. All process, network, account, and
package commands are mocks. Real file operations use disposable fixtures only.
"""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "VPN For project" / "More"

# These are the public server assignments, kept independently of the script so
# accidental port, UID/table, interface, filename, or ordering changes are caught.
SERVERS = (
    ("usa", 1080, 100, "tun0", "us-free-67.protonvpn.udp.ovpn"),
    ("netherlands", 1081, 101, "tun1", "nl-free-244.protonvpn.udp.ovpn"),
    ("switzerland", 1082, 102, "tun2", "ch-free-9.protonvpn.udp.ovpn"),
    ("mexico", 1083, 103, "tun3", "mx-free-8.protonvpn.udp.ovpn"),
    ("japan", 1084, 104, "tun4", "jp-free-3.protonvpn.udp.ovpn"),
    ("canada", 1085, 105, "tun5", "ca-free-14.protonvpn.udp.ovpn"),
    ("us2", 1086, 106, "tun6", "us-free-24.protonvpn.udp.ovpn"),
    ("us3", 1087, 107, "tun7", "us-free-26.protonvpn.udp.ovpn"),
    ("us4", 1088, 108, "tun8", "us-free-85.protonvpn.udp.ovpn"),
    ("mx2", 1089, 109, "tun9", "mx-free-2.protonvpn.udp.ovpn"),
    ("us5", 1090, 110, "tun10", "us-free-1.protonvpn.udp.ovpn"),
    ("nl2", 1091, 111, "tun11", "nl-free-209.protonvpn.udp.ovpn"),
)

MOCKS = r'''
record() {
    local entry=$1
    shift
    local arg
    for arg in "$@"; do entry+=$'\t'"$arg"; done
    printf '%s\n' "$entry" >> "$CALLS"
}
sudo() { "$@"; }
sleep() { record sleep "$@"; }
ip() { record ip "$@"; return 1; }
iptables() { record iptables "$@"; return 0; }
pkill() { record pkill "$@"; return 1; }
kill() { record kill "$@"; return 1; }
id() { record id "$@"; return 1; }
useradd() { record useradd "$@"; }
userdel() { record userdel "$@"; }
openvpn() { record openvpn "$@"; return 1; }
su() { record su "$@"; return 1; }
netstat() { record netstat "$@"; return 1; }
ps() { record ps "$@"; return 1; }
timeout() { record timeout "$@"; return 1; }
curl() { record curl "$@"; return 1; }
ping() { record ping "$@"; return 1; }
apt-get() { record apt-get "$@"; }
dnf() { record dnf "$@"; }
pacman() { record pacman "$@"; }
zypper() { record zypper "$@"; }
apk() { record apk "$@"; }
make() { record make "$@"; }
unzip() { record unzip "$@"; return 1; }
command() {
    if [[ ${1:-} == -v ]]; then
        case ${2:-} in
            apt-get|dnf|pacman|zypper|apk|microsocks)
                [[ " ${AVAILABLE_COMMANDS:-} " == *" $2 "* ]]
                return
                ;;
        esac
    fi
    builtin command "$@"
}
'''

# These replace only external collaborators of setup_vpn_proxy. Configuration
# copying/editing, retry decisions, PID files, active config, and polling remain
# real, so the tests verify behavior rather than a reimplementation of it.
PROXY_MOCKS = r'''
id() { record id "$@"; return 0; }
openvpn() {
    record openvpn "$@"
    cp "$2" "$ROOT/launched.ovpn"
    printf '424242\n' > "$RUN_DIR/openvpn-usa.pid"
}
ip() { record ip "$@"; return 0; }
test_vpn_connectivity() { record connectivity "$@"; return 0; }
get_vpn_gateway() { record gateway "$@"; echo 10.8.0.1; }
configure_routing_v3() { record routing "$@"; }
su() { record su "$@"; }
netstat() { echo 'tcp 0 0 127.0.0.1:1080 0.0.0.0:* LISTEN'; }
'''


class MultiVpnProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = shutil.which("bash")
        if cls.bash is None:
            raise unittest.SkipTest("Bash is required")
        source = SCRIPT.read_text(encoding="utf-8")
        # Fail clearly if the script is reorganized, instead of accidentally
        # executing its privileged initialization or testing an empty extract.
        start = "\nlog_info() {"
        dispatcher = '\ncase "${1:-help}" in\n'
        if source.count(start) != 1 or source.count(dispatcher) != 1:
            raise AssertionError("Update the test loader for the new script structure")
        functions, cls.dispatcher = source[source.index(start):].split(dispatcher)
        cls.dispatcher = dispatcher + cls.dispatcher
        cls.functions = functions
        for old, new in (
            ("/tmp/", "${TEST_TMP}/"),
            ("/etc/iproute2", "${ETC_DIR}/iproute2"),
            ("/etc/protonvpn", "${ETC_DIR}/protonvpn"),
            ("/etc/os-release", "${ETC_DIR}/os-release"),
            ("/etc/lsb-release", "${ETC_DIR}/lsb-release"),
        ):
            cls.functions = cls.functions.replace(old, new)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vpn-proxy-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("vpn", "logs", "run", "ovpn", "tmp", "etc/iproute2", "etc/protonvpn"):
            (self.root / name).mkdir(parents=True)
        self.calls = self.root / "calls"
        self.calls.touch()

    def fixture(self, name, content=""):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def run_bash(self, body, *, overrides="", args=(), dispatch=False, status=0):
        environment = {
            # Retain the platform's utility search path, but do not inherit
            # BASH_ENV, exported shell functions, credentials, or shell options.
            "PATH": os.defpath,
            "LC_ALL": "C.UTF-8",
            "ROOT": str(self.root),
        }
        prelude = r'''
set -euo pipefail
PROJECT_DIR=$ROOT
VPN_DIR=$ROOT/vpn
LOG_DIR=$ROOT/logs
RUN_DIR=$ROOT/run
CONFIG_FILE=$VPN_DIR/vpn-config.conf
OVPN_DIR=$ROOT/ovpn
TEST_TMP=$ROOT/tmp
ETC_DIR=$ROOT/etc
CALLS=$ROOT/calls
GREEN= RED= YELLOW= BLUE= CYAN= NC=
'''
        code = "\n".join((prelude, self.functions, MOCKS, overrides, body))
        if dispatch:
            code += self.dispatcher
        result = subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", code, "multi-vpn-proxy", *args],
            env=environment,
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        return result

    def events(self, command=None):
        events = [tuple(line.split("\t")) for line in self.calls.read_text().splitlines()]
        return [event for event in events if command is None or event[0] == command]

    def vpn_fixture(self, name="primary.ovpn"):
        self.fixture("vpn/credentials.txt", "synthetic-user\nsynthetic-password\n")
        return self.fixture(
            "vpn/" + name,
            "client\nremote vpn.invalid 1194\ndev tun9\nauth-user-pass\n",
        )

    def setup_proxy(self, overrides="", *, backup="", status=0):
        return self.run_bash(
            # start_system calls this function in an OR list; preserve that
            # context, including Bash's errexit behavior inside the function.
            'setup_vpn_proxy usa primary.ovpn ' + shlex.quote(backup)
            + ' 1080 100 tun0 || exit "$?"',
            overrides=PROXY_MOCKS + overrides,
            status=status,
        )

    def test_detects_supported_package_managers(self):
        self.fixture("etc/os-release", 'ID=fixture\nVERSION_ID="1.2"\n')
        for executable, manager in (
            ("apt-get", "apt"), ("dnf", "dnf"), ("pacman", "pacman"),
            ("zypper", "zypper"), ("apk", "apk"),
        ):
            with self.subTest(manager=manager):
                result = self.run_bash(
                    f"AVAILABLE_COMMANDS={executable}\ndetect_distro\n"
                    'printf "%s:%s:%s" "$DISTRO" "$DISTRO_VERSION" "$PKG_MANAGER"'
                )
                self.assertEqual(result.stdout, "fixture:1.2:" + manager)

    def test_distro_fallback_and_package_manager_precedence(self):
        self.fixture("etc/lsb-release", "DISTRIB_ID=Fallback\nDISTRIB_RELEASE=2\n")
        result = self.run_bash(
            "AVAILABLE_COMMANDS='dnf apt-get apk'\ndetect_distro\n"
            'printf "%s:%s:%s" "$DISTRO" "$DISTRO_VERSION" "$PKG_MANAGER"'
        )
        self.assertEqual(result.stdout, "Fallback:2:apt")

    def test_distro_detection_rejects_missing_release_and_unsupported_manager(self):
        result = self.run_bash("detect_distro", status=1)
        self.assertIn("No se pudo detectar", result.stdout)
        self.fixture("etc/os-release", "ID=fixture\nVERSION_ID=1\n")
        result = self.run_bash("detect_distro", status=1)
        self.assertIn("Gestor de paquetes no soportado", result.stdout)

    def test_installs_declared_packages_for_each_manager(self):
        cases = (
            ("apt", "apt-get", ("install", "-y", "openvpn", "curl", "iproute2", "iptables", "net-tools")),
            ("dnf", "dnf", ("install", "-y", "openvpn", "curl", "iproute", "iptables", "net-tools")),
            ("pacman", "pacman", ("-S", "--noconfirm", "openvpn", "curl", "iproute2", "iptables")),
            ("zypper", "zypper", ("install", "-y", "openvpn", "curl", "iproute2", "iptables")),
            ("apk", "apk", ("add", "openvpn", "curl", "iproute2", "iptables")),
        )
        for manager, executable, arguments in cases:
            with self.subTest(manager=manager):
                self.calls.write_text("")
                self.run_bash(f"PKG_MANAGER={manager}\nAVAILABLE_COMMANDS=microsocks\ninstall_dependencies")
                expected = [(executable, *arguments)]
                if manager == "apt":
                    expected.insert(0, ("apt-get", "update"))
                self.assertEqual(self.events(), expected)

    def test_microsocks_download_failure_is_reported_without_building(self):
        result = self.run_bash(
            "PKG_MANAGER=dnf\ninstall_dependencies",
            # Keep the installer's own temporary directory inside our fixture.
            overrides='mktemp() { mkdir "$ROOT/build"; echo "$ROOT/build"; }',
            status=1,
        )
        self.assertIn("No se pudo descargar microsocks", result.stdout)
        self.assertEqual(len(self.events("curl")), 1)
        self.assertFalse(self.events("make"))

    def test_microsocks_build_installs_and_removes_download_directory(self):
        result = self.run_bash(
            'PKG_MANAGER=dnf\ninstall_dependencies\npwd',
            overrides=r'''
mktemp() { mkdir "$ROOT/build"; echo "$ROOT/build"; }
curl() { record curl "$@"; }
unzip() { record unzip "$@"; mkdir microsocks-fixture; }
''',
        )
        self.assertEqual(result.stdout.strip(), str(self.root))
        self.assertFalse((self.root / "build").exists())
        self.assertEqual(self.events("make"), [("make",), ("make", "install")])
        self.assertEqual(self.events("unzip"), [("unzip", "-q", "microsocks.zip")])

    def test_microsocks_extraction_failure_never_builds_or_installs(self):
        result = self.run_bash(
            "PKG_MANAGER=dnf\ninstall_dependencies",
            overrides=r'''
mktemp() { mkdir "$ROOT/build"; echo "$ROOT/build"; }
curl() { record curl "$@"; }
''',
            status=1,
        )
        self.assertIn("No se pudo descomprimir microsocks", result.stdout)
        self.assertFalse(self.events("make"))

    def test_package_manager_failure_remains_best_effort(self):
        self.run_bash(
            "PKG_MANAGER=apt\nAVAILABLE_COMMANDS=microsocks\ninstall_dependencies",
            overrides='apt-get() { record apt-get "$@"; return 1; }',
        )
        self.assertEqual(len(self.events("apt-get")), 2)
        self.assertFalse(self.events("curl"))

    def test_setup_directories_registers_all_tables_once(self):
        tables = self.fixture("etc/iproute2/rt_tables", "255 local\n100 usa\n")
        self.run_bash("setup_directories\nsetup_directories")
        self.assertEqual(
            tables.read_text().splitlines(),
            ["255 local"] + [f"{table} {name}" for name, _, table, _, _ in SERVERS],
        )

    def test_credentials_are_assigned_in_pairs_with_fallback_and_private_permissions(self):
        for i in range(8):
            self.fixture(f"ovpn/{i:02}.ovpn", "client\nauth-user-pass old\nauth-user-pass duplicate\n")
        for name in ("credentials.txt", "credentials-2.txt", "credentials-4.txt"):
            self.fixture("ovpn/" + name, name + "\n")
        self.run_bash("integrate_credentials\nintegrate_credentials")
        expected = ("credentials.txt", "credentials-2.txt", "credentials.txt", "credentials-4.txt")
        for i in range(8):
            with self.subTest(config=i):
                self.assertEqual(
                    (self.root / f"vpn/{i:02}.ovpn").read_text().splitlines(),
                    ["client", f"auth-user-pass {self.root}/vpn/{expected[i // 2]}"],
                )
                self.assertIn("auth-user-pass old", (self.root / f"ovpn/{i:02}.ovpn").read_text())
        for name in ("credentials.txt", "credentials-2.txt", "credentials-4.txt"):
            copied = self.root / "vpn" / name
            self.assertEqual(copied.stat().st_mode & 0o777, 0o600)
            self.assertEqual(copied.read_text(), name + "\n")

    def test_credentials_require_source_directory(self):
        (self.root / "ovpn").rmdir()
        result = self.run_bash("integrate_credentials", status=1)
        self.assertIn("No existe", result.stdout)
        self.assertEqual(list((self.root / "vpn").iterdir()), [])

    def test_credentials_reject_missing_configs_or_credentials_without_copying(self):
        for present in ("credentials.txt", "only.ovpn"):
            with self.subTest(present=present):
                path = self.fixture("ovpn/" + present, "fixture\n")
                self.run_bash("integrate_credentials", status=1)
                self.assertEqual(list((self.root / "vpn").iterdir()), [])
                path.unlink()

    def test_create_users_skips_existing_account_and_uses_reserved_uids(self):
        self.run_bash(
            "create_users",
            overrides='id() { [[ $1 == vpnuser105 ]]; }',
        )
        self.assertEqual(self.events("useradd"), [
            ("useradd", "-r", "-s", "/bin/false", "-u", str(3000 + table), f"vpnuser{table}")
            for table in range(100, 112) if table != 105
        ])

    def test_discovers_all_servers_with_stable_assignments_and_order(self):
        for _, _, _, _, filename in reversed(SERVERS):
            self.fixture("vpn/" + filename)
        result = self.run_bash(
            'discover_vpn_servers\nfor name in "${VPN_ORDER[@]}"; do '
            'printf "%s=%s\\n" "$name" "${VPN_SERVERS[$name]}"; done'
        )
        self.assertEqual(result.stdout.splitlines(), [
            f"{name}={port}:{table}:{device}:{filename}::"
            for name, port, table, device, filename in SERVERS
        ])

    def test_discovery_ignores_unknown_configs_and_absent_servers(self):
        self.fixture("vpn/unknown.ovpn")
        result = self.run_bash('discover_vpn_servers\nprintf "%s" "${#VPN_ORDER[@]}"')
        self.assertEqual(result.stdout, "0")
        self.fixture("vpn/" + SERVERS[-1][-1])
        result = self.run_bash('discover_vpn_servers\nprintf "%s" "${VPN_ORDER[@]}"')
        self.assertEqual(result.stdout, "nl2")

    def test_discovery_rejects_missing_directory(self):
        (self.root / "vpn").rmdir()
        result = self.run_bash("discover_vpn_servers", status=1)
        self.assertIn("no existe", result.stdout)

    @unittest.expectedFailure
    def test_repeated_discovery_does_not_duplicate_servers_during_restart(self):
        # Known PR defect: stop_system and start_system both discover servers,
        # appending twice to VPN_ORDER in the same restart process.
        self.fixture("vpn/" + SERVERS[0][-1])
        result = self.run_bash(
            'discover_vpn_servers\ndiscover_vpn_servers\nprintf "%s\\n" "${VPN_ORDER[@]}"'
        )
        self.assertEqual(result.stdout.splitlines(), ["usa"])

    def test_gateway_prefers_latest_logged_route(self):
        self.fixture("logs/usa-openvpn.log", "route_gateway 10.8.0.1\nroute_gateway 10.9.0.1\n")
        result = self.run_bash('get_vpn_gateway tun0 usa || exit "$?"')
        self.assertEqual(result.stdout, "10.9.0.1\n")
        self.assertFalse(self.events("ip"))
        self.assertFalse(self.events("sleep"))

    def test_gateway_polls_until_log_becomes_ready(self):
        self.fixture("logs/usa-openvpn.log")
        result = self.run_bash(
            'get_vpn_gateway tun0 usa || exit "$?"',
            overrides=r'''sleep() {
                record sleep "$@"
                echo 'route_gateway 10.8.0.1' >> "$LOG_DIR/usa-openvpn.log"
            }''',
        )
        self.assertEqual(result.stdout, "10.8.0.1\n")
        self.assertEqual(self.events("sleep"), [("sleep", "1")])

    def test_gateway_falls_back_to_route_then_interface_then_remote(self):
        cases = (
            ("route", "10.20.0.1", "UDPv4 link remote: [AF_INET]198.51.100.9\n"),
            ("interface", "10.21.5.1", "UDPv4 link remote: [AF_INET]198.51.100.9\n"),
            ("remote", "198.51.100.9", "UDPv4 link remote: [AF_INET]198.51.100.9\n"),
        )
        for mode, expected, log in cases:
            with self.subTest(fallback=mode):
                self.calls.write_text("")
                self.fixture("logs/usa-openvpn.log", log)
                overrides = f"MODE={mode}\n" + r'''
ip() {
    record ip "$@"
    if [[ $MODE == route && $* == 'route show dev tun0' ]]; then
        echo 'default via 10.20.0.1 dev tun0'
    elif [[ $MODE == interface && $* == '-4 addr show tun0' ]]; then
        echo 'inet 10.21.5.42/24 scope global tun0'
    else
        return 1
    fi
}'''
                result = self.run_bash('get_vpn_gateway tun0 usa || exit "$?"', overrides=overrides)
                self.assertEqual(result.stdout.strip(), expected)
                self.assertEqual(self.events("sleep"), [("sleep", "1")] * 30)

    def test_gateway_failure_goes_to_stderr_without_a_fake_address(self):
        result = self.run_bash('get_vpn_gateway tun0 usa || exit "$?"', status=1)
        self.assertEqual(result.stdout, "")
        self.assertIn("No se pudo detectar gateway VPN para tun0", result.stderr)

    def test_connectivity_checks_interface_before_ping(self):
        self.run_bash("test_vpn_connectivity tun0", status=1)
        self.assertEqual(self.events(), [("ip", "addr", "show", "tun0")])

    def test_connectivity_uses_default_or_custom_timeout_and_returns_ping_status(self):
        for argument, seconds in (("", "5"), ("12", "12")):
            for exit_status in (0, 1):
                with self.subTest(timeout=seconds, ping_status=exit_status):
                    self.calls.write_text("")
                    self.run_bash(
                        "test_vpn_connectivity tun3 " + argument,
                        overrides='ip() { return 0; }\n'
                        + f'timeout() {{ record timeout "$@"; return {exit_status}; }}',
                        status=exit_status,
                    )
                    self.assertEqual(self.events(), [
                        ("timeout", seconds, "ping", "-I", "tun3", "-c", "2", "8.8.8.8")
                    ])

    def test_active_config_appends_uppercase_names_and_preserves_spaces(self):
        self.run_bash("save_active_config usa primary.ovpn\nsave_active_config nl2 'backup config.ovpn'")
        self.assertEqual(
            (self.root / "vpn/vpn-config.conf").read_text(),
            'ACTIVE_USA="primary.ovpn"\nACTIVE_NL2="backup config.ovpn"\n',
        )

    def test_routing_uses_isolated_table_uid_priorities_and_replaces_old_rules(self):
        self.run_bash(
            "configure_routing_v3 usa tun0 100 3100 10.8.0.1",
            overrides=r'''
deletions=0
ip() {
    record ip "$@"
    if [[ $* == '-4 addr show tun0' ]]; then
        echo 'inet 10.8.0.2/24 scope global tun0'
    elif [[ $1 == rule && $2 == del ]]; then
        deletions=$((deletions + 1))
        # Each loop must delete all duplicate rules until ip reports none.
        (( deletions == 1 || deletions == 3 ))
    fi
}''',
        )
        self.assertEqual(self.events(), [
            ("ip", "-4", "addr", "show", "tun0"),
            ("ip", "route", "add", "10.8.0.2/24", "dev", "tun0", "scope", "link", "table", "100"),
            ("ip", "route", "add", "default", "via", "10.8.0.1", "dev", "tun0", "table", "100"),
            ("ip", "rule", "del", "fwmark", "100"),
            ("ip", "rule", "del", "fwmark", "100"),
            ("ip", "rule", "del", "uidrange", "3100-3100"),
            ("ip", "rule", "del", "uidrange", "3100-3100"),
            ("ip", "rule", "add", "uidrange", "3100-3100", "table", "100", "priority", "10100"),
            ("iptables", "-t", "mangle", "-D", "OUTPUT", "-m", "owner", "--uid-owner", "3100", "-j", "MARK", "--set-mark", "100"),
            ("iptables", "-t", "mangle", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "3100", "-j", "MARK", "--set-mark", "100"),
            ("ip", "rule", "add", "fwmark", "100", "table", "100", "priority", "11100"),
        ])

    def test_proxy_success_rewrites_only_temporary_config_and_binds_localhost(self):
        original = self.vpn_fixture()
        before = original.read_text()
        self.setup_proxy()
        self.assertEqual(original.read_text(), before)
        launched = (self.root / "launched.ovpn").read_text().splitlines()
        self.assertIn("dev tun0", launched)
        self.assertNotIn("dev tun9", launched)
        self.assertIn("route-nopull", launched)
        self.assertIn('pull-filter ignore "dhcp-option DNS"', launched)
        self.assertFalse((self.root / "tmp/usa.ovpn").exists())
        self.assertEqual((self.root / "tmp/credentials.txt").read_text(),
                         (self.root / "vpn/credentials.txt").read_text())
        self.assertEqual((self.root / "vpn/vpn-config.conf").read_text(), 'ACTIVE_USA="primary.ovpn"\n')
        self.assertTrue((self.root / "run/microsocks-usa.pid").read_text().strip().isdigit())
        self.assertEqual(self.events("su"), [
            ("su", "-s", "/bin/bash", "vpnuser100", "-c", "microsocks -i 127.0.0.1 -p 1080")
        ])
        self.assertEqual(self.events("routing"), [("routing", "usa", "tun0", "100", "3100", "10.8.0.1")])
        self.assertEqual(self.events("openvpn"), [
            ("openvpn", "--config", str(self.root / "tmp/usa.ovpn"), "--daemon",
             "--writepid", str(self.root / "run/openvpn-usa.pid"),
             "--log", str(self.root / "logs/usa-openvpn.log"),
             "--status", str(self.root / "logs/usa-status.log"), "10", "--verb", "4")
        ])

    def test_proxy_creates_missing_user(self):
        self.vpn_fixture()
        self.setup_proxy('id() { return 1; }')
        self.assertEqual(self.events("useradd"), [
            ("useradd", "-r", "-s", "/bin/false", "-u", "3100", "vpnuser100")
        ])

    @unittest.expectedFailure
    def test_proxy_honors_custom_auth_user_pass_file(self):
        # Known PR defect: awk reads field 3, but auth-user-pass takes the
        # credential path in field 2, silently selecting credentials.txt instead.
        self.vpn_fixture()
        custom = self.fixture("vpn/credentials-2.txt", "different-user\ndifferent-password\n")
        self.fixture("vpn/primary.ovpn", f"client\nauth-user-pass {custom}\n")
        self.setup_proxy()
        self.assertTrue((self.root / "tmp/credentials-2.txt").exists())
        self.assertEqual((self.root / "tmp/credentials-2.txt").read_text(), custom.read_text())

    def test_proxy_missing_primary_uses_backup_and_saves_that_choice(self):
        self.vpn_fixture("backup.ovpn")
        self.setup_proxy(backup="backup.ovpn")
        self.assertEqual((self.root / "vpn/vpn-config.conf").read_text(), 'ACTIVE_USA="backup.ovpn"\n')
        self.assertEqual(len(self.events("openvpn")), 1)

    def test_proxy_rejects_missing_primary_and_backup_without_launching(self):
        self.setup_proxy(backup="missing.ovpn", status=1)
        self.assertFalse(self.events("openvpn"))
        self.assertFalse(self.events("su"))
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())

    def test_proxy_failed_connectivity_kills_attempt_and_uses_backup(self):
        self.vpn_fixture()
        self.vpn_fixture("backup.ovpn")
        self.setup_proxy(r'''
connectivity_attempt=0
test_vpn_connectivity() {
    connectivity_attempt=$((connectivity_attempt + 1))
    (( connectivity_attempt == 2 ))
}''', backup="backup.ovpn")
        self.assertEqual(len(self.events("openvpn")), 2)
        self.assertEqual(self.events("kill"), [("kill", "424242")])
        self.assertEqual(self.events("sleep"), [("sleep", "3")])
        self.assertEqual((self.root / "vpn/vpn-config.conf").read_text(), 'ACTIVE_USA="backup.ovpn"\n')

    def test_proxy_failed_connectivity_cleans_pid_and_never_starts_socks(self):
        self.vpn_fixture()
        self.setup_proxy('test_vpn_connectivity() { return 1; }', status=1)
        self.assertFalse((self.root / "run/openvpn-usa.pid").exists())
        self.assertFalse((self.root / "tmp/usa.ovpn").exists())
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())
        self.assertFalse(self.events("su"))

    def test_proxy_interface_timeout_tries_backup_then_returns_failure(self):
        self.vpn_fixture()
        self.vpn_fixture("backup.ovpn")
        self.setup_proxy('ip() { return 1; }', backup="backup.ovpn", status=1)
        self.assertEqual(len(self.events("openvpn")), 2)
        self.assertEqual(self.events("sleep"), [("sleep", "1")] * 60)
        self.assertFalse((self.root / "tmp/usa.ovpn").exists())
        self.assertFalse(self.events("routing"))
        self.assertFalse(self.events("su"))

    def test_proxy_gateway_failure_prevents_routing_and_socks_launch(self):
        self.vpn_fixture()
        self.setup_proxy('get_vpn_gateway() { return 1; }', status=1)
        self.assertFalse(self.events("routing"))
        self.assertFalse(self.events("su"))

    def test_proxy_port_polling_rejects_a_different_port(self):
        self.vpn_fixture()
        self.setup_proxy(
            "netstat() { echo 'tcp 0 0 127.0.0.1:10800 0.0.0.0:* LISTEN'; }", status=1,
        )
        self.assertEqual(self.events("sleep"), [("sleep", "1")] * 30)

    def test_cleanup_removes_pid_files_and_rules_when_processes_are_already_gone(self):
        self.fixture("run/openvpn-usa.pid", "424242\n")
        self.fixture("run/microsocks-usa.pid", "434343\n")
        self.fixture("tmp/usa.ovpn", "fixture\n")
        self.fixture("tmp/credentials-2.txt", "fixture\n")
        unrelated = self.fixture("tmp/keep.txt", "keep\n")
        self.run_bash("cleanup_vpn usa 100 1080\ncleanup_vpn usa 100 1080")
        self.assertEqual(list((self.root / "run").iterdir()), [])
        self.assertEqual(list((self.root / "tmp").iterdir()), [unrelated])
        self.assertIn(("kill", "-9", "434343"), self.events("kill"))
        self.assertNotIn(("kill", "-TERM", "424242"), self.events("kill"))
        self.assertEqual(self.events("pkill"), [("pkill", "-9", "-U", "3100")] * 2)
        self.assertIn(("ip", "route", "flush", "table", "100"), self.events("ip"))
        self.assertIn(("ip", "rule", "del", "uidrange", "3100-3100"), self.events("ip"))
        self.assertEqual(self.events("iptables"), [
            ("iptables", "-t", "mangle", "-D", "OUTPUT", "-m", "owner", "--uid-owner", "3100", "-j", "MARK", "--set-mark", "100")
        ] * 2)

    def test_cleanup_gives_openvpn_time_to_exit_before_escalating(self):
        for stubborn in (False, True):
            with self.subTest(stubborn=stubborn):
                self.calls.write_text("")
                self.fixture("run/openvpn-usa.pid", "424242\n")
                overrides = f"STUBBORN={int(stubborn)}\n" + r'''
terminated=0
kill() {
    record kill "$@"
    if [[ $1 == -TERM ]]; then
        terminated=1
    elif [[ $1 == -0 ]]; then
        (( STUBBORN || ! terminated ))
    fi
}'''
                self.run_bash("cleanup_vpn usa 100 1080", overrides=overrides)
                self.assertIn(("kill", "-TERM", "424242"), self.events("kill"))
                self.assertEqual(("kill", "-KILL", "424242") in self.events("kill"), stubborn)
                self.assertEqual(self.events("sleep"), [("sleep", "1")] * (10 if stubborn else 0))
                self.assertFalse((self.root / "run/openvpn-usa.pid").exists())

    def test_system_cleanup_covers_all_reserved_users_and_only_fixture_files(self):
        self.fixture("vpn/remove.ovpn")
        self.fixture("logs/remove.log")
        self.fixture("run/openvpn-usa.pid")
        self.fixture("run/microsocks-usa.pid")
        keep = self.fixture("run/unrelated.pid")
        self.fixture("etc/protonvpn/vpn-config.conf")
        self.run_bash("cleanup_system")
        self.assertEqual(self.events("userdel"), [("userdel", f"vpnuser{i}") for i in range(100, 112)])
        self.assertEqual(len(self.events("ip")), 36)
        for table in range(100, 112):
            self.assertIn(("ip", "route", "flush", "table", str(table)), self.events("ip"))
            self.assertIn(("ip", "rule", "del", "fwmark", str(table)), self.events("ip"))
            self.assertIn(("ip", "rule", "del", "uidrange", f"{3000 + table}-{3000 + table}"), self.events("ip"))
        self.assertEqual(list((self.root / "vpn").iterdir()), [])
        self.assertEqual(list((self.root / "logs").iterdir()), [])
        self.assertEqual(list((self.root / "run").iterdir()), [keep])
        self.assertFalse((self.root / "etc/protonvpn/vpn-config.conf").exists())

    def test_start_continues_after_one_server_fails_and_shows_status(self):
        for entry in SERVERS[:2]:
            self.fixture("vpn/" + entry[-1])
        self.fixture("vpn/vpn-config.conf", "stale\n")
        self.fixture("run/openvpn-old.pid")
        self.fixture("run/microsocks-old.pid")
        result = self.run_bash("start_system", overrides=r'''
setup_vpn_proxy() { record setup "$@"; [[ $1 != usa ]]; }
show_status() { record status; }
''')
        self.assertIn("No se pudo iniciar usa", result.stdout)
        self.assertEqual(self.events("setup"), [
            ("setup", name, filename, "", str(port), str(table), device)
            for name, port, table, device, filename in SERVERS[:2]
        ])
        self.assertEqual(self.events()[-1][0], "status")
        self.assertEqual(list((self.root / "run").iterdir()), [])
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())

    def test_stop_cleans_each_discovered_server_and_active_config(self):
        for entry in (SERVERS[0], SERVERS[-1]):
            self.fixture("vpn/" + entry[-1])
        self.fixture("vpn/vpn-config.conf", "stale\n")
        self.run_bash("stop_system", overrides='cleanup_vpn() { record cleanup "$@"; }')
        self.assertEqual(self.events("cleanup"), [("cleanup", "usa", "100", "1080"), ("cleanup", "nl2", "111", "1091")])
        self.assertEqual(self.events("pkill"), [("pkill", "-f", "microsocks"), ("pkill", "-f", "openvpn")])
        self.assertFalse((self.root / "vpn/vpn-config.conf").exists())

    def test_status_reports_live_interface_proxy_and_public_ip(self):
        self.fixture("vpn/" + SERVERS[0][-1])
        self.fixture("run/openvpn-usa.pid", "424242\n")
        result = self.run_bash("discover_vpn_servers\nshow_status", overrides=r'''
ps() { record ps "$@"; return 0; }
ip() { echo 'inet 10.8.0.2/24 scope global tun0'; }
netstat() { echo 'tcp 0 0 127.0.0.1:1080 0.0.0.0:* LISTEN'; }
timeout() {
    record timeout "$@"
    if [[ $1 == 10 ]]; then echo 198.51.100.7; else echo 192.0.2.8; fi
}''')
        for text in ("usa running", "Interface: tun0 (10.8.0.2)", "Proxy: 127.0.0.1:1080",
                     "Public IP: 198.51.100.7", "Direct IP: 192.0.2.8"):
            self.assertIn(text, result.stdout)
        self.assertEqual(self.events("timeout"), [
            ("timeout", "10", "curl", "--socks5", "127.0.0.1:1080", "-s", "https://ifconfig.me"),
            ("timeout", "5", "curl", "-s", "https://ifconfig.me"),
        ])

    def test_status_handles_stale_pid_and_failed_public_ip_lookup(self):
        self.fixture("vpn/" + SERVERS[0][-1])
        self.fixture("run/openvpn-usa.pid", "424242\n")
        result = self.run_bash("discover_vpn_servers\nshow_status")
        self.assertNotIn("usa running", result.stdout)
        self.assertIn("Direct IP: unknown", result.stdout)
        self.assertEqual(len(self.events("timeout")), 1)

    def test_system_connectivity_reports_success_and_failure_and_continues(self):
        for entry in SERVERS[:2]:
            self.fixture("vpn/" + entry[-1])
        result = self.run_bash("test_system", overrides=r'''
timeout() {
    record timeout "$@"
    if [[ $4 == 127.0.0.1:1080 ]]; then echo 198.51.100.7; else return 1; fi
}''')
        self.assertIn("Probando usa (1080)... ✓ 198.51.100.7", result.stdout)
        self.assertIn("Probando netherlands (1081)... ✗", result.stdout)
        self.assertEqual(self.events("timeout"), [
            ("timeout", "15", "curl", "--socks5", f"127.0.0.1:{port}", "-s", "https://ifconfig.me")
            for port in (1080, 1081)
        ])

    def test_help_aliases_and_default_list_supported_commands(self):
        for args in ((), ("help",), ("--help",), ("-h",), ("",)):
            with self.subTest(args=args):
                result = self.run_bash("", args=args, dispatch=True)
                self.assertIn("VPN Multi-Proxy Script", result.stdout)
                for name in ("install", "full", "start", "stop", "restart", "status", "test", "help"):
                    self.assertIn("multi-vpn-proxy " + name, result.stdout)
                self.assertEqual(self.events(), [])

    def test_unknown_command_returns_error_and_usage(self):
        result = self.run_bash("", args=("not-a-command",), dispatch=True, status=1)
        self.assertIn("Comando desconocido: not-a-command", result.stdout)
        self.assertIn("VPN Multi-Proxy Script", result.stdout)
        self.assertEqual(self.events(), [])

    def test_dispatch_preserves_install_cleanup_and_restart_order(self):
        functions = (
            "detect_distro", "install_dependencies", "setup_directories", "integrate_credentials",
            "create_users", "cleanup_system", "start_system", "stop_system", "discover_vpn_servers",
            "show_status", "test_system",
        )
        overrides = "\n".join(f'{name}() {{ record {name} invoked; }}' for name in functions)
        cases = {
            "install": functions[:5],
            "full": ("detect_distro", "cleanup_system", *functions[1:5]),
            "start": ("start_system",),
            "stop": ("stop_system",),
            "restart": ("stop_system", "sleep", "start_system"),
            "status": ("discover_vpn_servers", "show_status"),
            "test": ("test_system",),
        }
        for name, expected in cases.items():
            with self.subTest(command=name):
                self.calls.write_text("")
                self.run_bash("", overrides=overrides, args=(name,), dispatch=True)
                self.assertEqual([event[0] for event in self.events()], list(expected))
                if name == "restart":
                    self.assertEqual(self.events("sleep"), [("sleep", "3")])

    def test_install_dispatch_aborts_after_credential_failure(self):
        result = self.run_bash(
            "",
            overrides=r'''
detect_distro() { :; }
install_dependencies() { :; }
setup_directories() { :; }
integrate_credentials() { record credentials failed; return 1; }
create_users() { record users unexpected; }
''',
            args=("install",), dispatch=True, status=1,
        )
        self.assertEqual(self.events(), [("credentials", "failed")])
        self.assertNotIn("Instalación completada", result.stdout)


if __name__ == "__main__":
    unittest.main()
