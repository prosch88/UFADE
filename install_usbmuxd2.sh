#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# usbmuxd2 installer: Arch/Manjaro, Debian/Ubuntu/Raspberry Pi OS, Fedora.
# Source build is unprivileged; only package installation and activation use sudo.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="https://github.com/prosch88/usbmuxd2.git"
GENERAL_URL="https://github.com/tihmstar/libgeneral.git"
PLIST_URL="https://github.com/libimobiledevice/libplist.git"
GENERAL_REF="${LIBGENERAL_REF:-master}"
PLIST_REF="${LIBPLIST_REF:-master}"
FORK_REF="${USBMUXD_REF:-master}"
PREFIX=/opt/usbmuxd2
STATE=/var/lib/usbmuxd2-installer
UNIT=/etc/systemd/system/usbmuxd.service
RULE=/etc/udev/rules.d/39-usbmuxd.rules
JOBS="$(nproc)"
MODE=install
WIFI=0
WITH_LIMD=0
ASSUME_YES=0
SRC=""
WORK=""
LOG=""
RELEASE=""
ACTIVATED=0
BACKUP=""

usage() { cat <<'HELP'
Usage: ./install.sh [--check | --build-only | --rollback] [options]
  --jobs N             Limit make parallelism (e.g. 2 on Raspberry Pi)
  --yes                Permit package-manager installation without prompt
  --wifi               Enable Avahi Wi-Fi support (requires avahi-client >= 0.7)
  --with-libimobiledevice Enable optional preflight integration (requires >= 1.3.0)
  --source DIR         Use local usbmuxd2 checkout instead of cloning
  --ref REF            Fork Git branch/tag/commit (default master)
  --libgeneral-ref REF Dependency Git ref (default master)
  --libplist-ref REF   Dependency Git ref (default master)
  --check              Inspect environment and dependency versions; no modifications
  --build-only         Build everything in a temporary folder; no service changes
  --rollback           Restore last saved systemd/udev configuration and previous binary
  --help               This message
Environment: LIBGENERAL_REF, LIBPLIST_REF, USBMUXD_REF
HELP
}
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "${LOG:-/dev/null}"; }
fail() { log "ERROR: $*"; exit 1; }
run() {
 local quoted
 printf -v quoted '%q ' "$@"
 log "+ $quoted"
 # Process substitution keeps stdin and exit status intact; interactive package prompts remain visible.
 "$@" > >(tee -a "$LOG") 2> >(tee -a "$LOG" >&2) || fail "Command failed: $quoted (log: $LOG)"
}
need() { command -v "$1" >/dev/null 2>&1 || fail "Missing tool: $1"; }
rootcmd() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

while (($#)); do
 case "$1" in
  --check) MODE=check;; --build-only) MODE=build;; --rollback) MODE=rollback;;
  --jobs) JOBS="${2:?}"; shift;; --yes) ASSUME_YES=1;;
  --wifi) WIFI=1;; --with-libimobiledevice) WITH_LIMD=1;;
  --source) SRC="${2:?}"; shift;; --ref) FORK_REF="${2:?}"; shift;;
  --libgeneral-ref) GENERAL_REF="${2:?}"; shift;;
  --libplist-ref) PLIST_REF="${2:?}"; shift;;
  -h|--help) usage; exit 0;; *) echo "Unknown option: $1" >&2; usage; exit 2;;
 esac
 shift
done
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || fail '--jobs must be a positive integer'
[[ "$(uname -s)" == Linux ]] || fail 'Linux only'
[[ -f /etc/os-release ]] || fail 'Cannot identify distribution'
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in
 *arch*|*manjaro*) PM=pacman;; *debian*|*ubuntu*|*raspbian*) PM=apt;; *fedora*|*rhel*) PM=dnf;; *) fail "Unsupported distribution: ${ID:-unknown} (${ID_LIKE:-})";;
esac
case "$(uname -m)" in x86_64|aarch64) :;; *) fail "Unsupported architecture $(uname -m); supported: x86_64/aarch64";; esac
if [[ $MODE == rollback ]]; then
 need systemctl
 [[ -f "$STATE/last-backup/path" ]] || fail 'No rollback snapshot available'
 BACKUP="$(cat "$STATE/last-backup/path")"
 [[ -d "$BACKUP" ]] || fail "Snapshot missing: $BACKUP"
 log "Restoring $BACKUP"
 rootcmd systemctl stop usbmuxd.service || true
 rootcmd systemctl stop usbmuxd.socket || true
 for entry in unit rule; do
   if [[ -f "$BACKUP/$entry.present" ]]; then
     if [[ "$entry" == unit ]]; then rootcmd cp -a "$BACKUP/$entry" "$UNIT"; else rootcmd cp -a "$BACKUP/$entry" "$RULE"; fi
   else
     if [[ "$entry" == unit ]]; then rootcmd rm -f "$UNIT"; else rootcmd rm -f "$RULE"; fi
   fi
 done
 if [[ -f "$BACKUP/current.link" ]]; then rootcmd ln -sfn "$(cat "$BACKUP/current.link")" "$PREFIX/current"; else rootcmd rm -f "$PREFIX/current"; fi
 rootcmd systemctl daemon-reload
 rootcmd udevadm control --reload-rules
 rootcmd systemctl disable usbmuxd.service >/dev/null 2>&1 || true
 rootcmd systemctl disable usbmuxd.socket >/dev/null 2>&1 || true
 if [[ -f "$BACKUP/service.enabled" ]]; then rootcmd systemctl enable usbmuxd.service; fi
 if [[ -f "$BACKUP/socket.enabled" ]]; then rootcmd systemctl enable usbmuxd.socket; fi
 if [[ -f "$BACKUP/socket.active" ]]; then rootcmd systemctl start usbmuxd.socket; fi
 if [[ -f "$BACKUP/service.active" ]]; then rootcmd systemctl start usbmuxd.service; fi
 log 'Rollback completed. Existing vendor packages were not modified.'
 exit 0
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/usbmuxd2-build.XXXXXXXX")"
LOG="$WORK/install.log"
touch "$LOG"
cleanup() { rc=$?; if ((rc != 0)); then echo "Build failed; log retained: $LOG" >&2; elif [[ $MODE == install ]]; then rm -rf "$WORK"; else echo "Build directory retained: $WORK"; fi; }
trap cleanup EXIT
log "Detected $PRETTY_NAME / $(uname -m), package manager $PM; mode $MODE"

# For build-only and check do not modify the system, including package installation.
packages() {
 case "$PM" in
  pacman) local a=(base-devel git clang autoconf automake libtool pkgconf libusb systemd);;
  apt) local a=(build-essential clang git autoconf automake libtool pkg-config libusb-1.0-0-dev libsystemd-dev libudev-dev ca-certificates);;
  dnf) local a=(gcc gcc-c++ clang git make autoconf automake libtool pkgconf-pkg-config libusb1-devel systemd-devel systemd-udev ca-certificates);;
 esac
 # Check the ABI via pkg-config, not package name. Keep libplist-git, locally
 # built libplist, and equivalent providers when they satisfy the requirement.
 # Never let a package manager silently replace a conflicting development build.
 if pkg-config --exists 'libplist-2.0 >= 2.6.0' 2>/dev/null; then
   log "Using installed libplist-2.0 $(pkg-config --modversion libplist-2.0) (no package replacement)"
 else
   case "$PM" in
     pacman)
       if pacman -Qq libplist-git >/dev/null 2>&1; then
         log 'libplist-git is installed but pkg-config does not expose a compatible version; retaining package and building a private libplist.'
       else
         a+=(libplist)
       fi
       ;;
     apt)
       # A custom installation may already provide the library without a .pc file.
       # Avoid forcibly changing third-party packages; build a private copy instead.
       log 'No compatible libplist via pkg-config: will build private libplist if still unresolved after package installation.'
       ;;
     dnf)
       log 'No compatible libplist via pkg-config: will build private libplist if still unresolved after package installation.'
       ;;
   esac
 fi
 if ((WIFI)) && ! pkg-config --exists 'avahi-client >= 0.7' 2>/dev/null; then case "$PM" in pacman) a+=(avahi);; apt) a+=(libavahi-client-dev);; dnf) a+=(avahi-devel);; esac; fi
 if ((WITH_LIMD)) && ! pkg-config --exists 'libimobiledevice-1.0 >= 1.3.0' 2>/dev/null; then case "$PM" in pacman) a+=(libimobiledevice);; apt) a+=(libimobiledevice-dev);; dnf) a+=(libimobiledevice-devel);; esac; fi
 case "$PM" in
  pacman)
   # pacman -S (never -Sy) avoids a partial upgrade; users should do -Syu separately.
   if ((ASSUME_YES)); then run rootcmd pacman -S --needed --noconfirm "${a[@]}"; else run rootcmd pacman -S --needed "${a[@]}"; fi
   ;;
  apt)
   run rootcmd apt-get update
   if ((ASSUME_YES)); then run rootcmd env DEBIAN_FRONTEND=noninteractive apt-get install -y "${a[@]}"; else run rootcmd apt-get install "${a[@]}"; fi
   ;;
  dnf)
   if ((ASSUME_YES)); then run rootcmd dnf install -y "${a[@]}"; else run rootcmd dnf install "${a[@]}"; fi
   ;;
 esac
}
if [[ $EUID -eq 0 && $MODE != check ]]; then fail "Run as a normal user (without sudo); the installer requests sudo only when needed"; fi
if [[ $MODE == install ]]; then packages; fi
for cmd in git make pkg-config clang clang++ autoreconf sed install; do
 if ! command -v "$cmd" >/dev/null 2>&1; then
  if [[ $MODE == check ]]; then log "MISSING tool: $cmd"; else fail "Missing tool: $cmd (run installation mode to install packages)"; fi
 fi
done
if ! command -v pkg-config >/dev/null 2>&1; then fail "pkg-config missing; cannot inspect dependency versions"; fi
for spec in 'libusb-1.0 >= 1.0.9' 'libgeneral >= 92' 'libplist-2.0 >= 2.6.0'; do
 if pkg-config --exists "$spec" 2>/dev/null; then
  mod="${spec%% *}"; log "OK: $mod $(pkg-config --modversion "$mod")"
 else log "NEEDS PRIVATE BUILD or missing: $spec"; fi
done
if ((WIFI)); then pkg-config --exists 'avahi-client >= 0.7' || fail 'Wi-Fi requires avahi-client >= 0.7'; fi
if ((WITH_LIMD)); then pkg-config --exists 'libimobiledevice-1.0 >= 1.3.0' || fail 'Preflight requires libimobiledevice-1.0 >= 1.3.0'; fi
[[ $MODE == check ]] && { log 'Check complete (no changes made).'; exit 0; }

# The isolated build prefix is moved to /opt after all compilation succeeds.
STAGE="$WORK/stage"
mkdir -p "$STAGE"
export PKG_CONFIG_PATH="$STAGE/lib/pkgconfig:$STAGE/share/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="$STAGE/lib:${LD_LIBRARY_PATH:-}"

export CPPFLAGS="-I$STAGE/include ${CPPFLAGS:-}"
export LDFLAGS="-L$STAGE/lib -Wl,-rpath,$STAGE/lib ${LDFLAGS:-}"

export CC=clang
export CXX=clang++
clone() {
 local url="$1" ref="$2" dest="$3"
 run git clone --recursive "$url" "$dest"
 run git -C "$dest" checkout "$ref"
 run git -C "$dest" submodule update --init --recursive
 log "Source $(basename "$dest"): $(git -C "$dest" rev-parse --short HEAD)"
}
build_autotools() {
 local dir="$1"; shift
 ( cd "$dir"; run ./autogen.sh --prefix="$STAGE" --libdir="$STAGE/lib" "$@"; run make -j "$JOBS"; run make install )
}
# Avoid building new libplist against old system ABI: private libgeneral and libplist
# are always preferred when system versions fail minimum checks.
if ! pkg-config --exists 'libgeneral >= 92'; then
 clone "$GENERAL_URL" "$GENERAL_REF" "$WORK/libgeneral"
 build_autotools "$WORK/libgeneral"
fi
if ! pkg-config --exists 'libplist-2.0 >= 2.6.0'; then
 clone "$PLIST_URL" "$PLIST_REF" "$WORK/libplist"
 build_autotools "$WORK/libplist" --without-cython --without-tools --without-tests
fi
pkg-config --exists 'libgeneral >= 92' || fail 'libgeneral >= 92 unresolved after build'
pkg-config --exists 'libplist-2.0 >= 2.6.0' || fail 'libplist >= 2.6.0 unresolved after build'
pkg-config --exists 'libusb-1.0 >= 1.0.9' || fail 'libusb >= 1.0.9 unresolved'

if [[ -n "$SRC" ]]; then
 [[ -d "$SRC/.git" || -f "$SRC/.git" ]] || fail "Not a Git checkout: $SRC"
 run cp -a "$SRC" "$WORK/fork"
else
 clone "$REPO_URL" "$FORK_REF" "$WORK/fork"
fi
COMMIT="$(git -C "$WORK/fork" rev-parse --short=12 HEAD)"
# Never let make install overwrite the systemd unit or udev rules during the build.
# Install to private directories inside the temporary prefix.
configure_opts=(
 --with-systemd
 --with-systemdsystemunitdir="$STAGE/share/usbmuxd2/systemd"
 --with-systemduserunitdir="$STAGE/share/usbmuxd2/systemd-user"
 --with-udevrulesdir="$STAGE/share/usbmuxd2/udev"
)
if (( ! WIFI )); then configure_opts+=(--without-wifi); fi
if (( ! WITH_LIMD )); then configure_opts+=(--without-libimobiledevice); fi
build_autotools "$WORK/fork" "${configure_opts[@]}"
BIN="$(find "$STAGE" -type f -name usbmuxd -perm /111 -print -quit)"
[[ -n "$BIN" ]] || fail 'Built usbmuxd binary not found'
mkdir -p "$STAGE/bin"
cp "$BIN" "$STAGE/bin/usbmuxd"
chmod 755 "$STAGE/bin/usbmuxd"
log "Build succeeded: commit $COMMIT; binary $STAGE/bin/usbmuxd"
if [[ $MODE == build ]]; then exit 0; fi

need systemctl
need udevadm
[[ -d /run/systemd/system ]] || fail 'systemd is not running as PID 1'
# Do not change existing service until all build steps and binary dependencies are checked.
if command -v ldd >/dev/null; then
 ldd "$STAGE/bin/usbmuxd" >>"$LOG" 2>&1 || true
 if LD_LIBRARY_PATH="$STAGE/lib" ldd "$STAGE/bin/usbmuxd" | grep -q 'not found'; then fail 'Unresolved runtime shared library (ldd)'; fi
fi
rootcmd install -d -m 755 "$PREFIX/releases" "$STATE"
RELEASE="$PREFIX/releases/$(date -u +%Y%m%dT%H%M%SZ)-$COMMIT"
rootcmd mkdir -p "$RELEASE"
rootcmd cp -a "$STAGE/." "$RELEASE/"
# Existing config snapshot for rollback. Do not modify distribution-owned files.
BACKUP="$STATE/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
rootcmd mkdir -p "$BACKUP"
for item in unit rule; do
 if [[ "$item" == unit ]]; then f="$UNIT"; else f="$RULE"; fi
 if [[ -e "$f" || -L "$f" ]]; then rootcmd cp -a "$f" "$BACKUP/$item"; rootcmd touch "$BACKUP/$item.present"; fi
done
if [[ -L "$PREFIX/current" ]]; then readlink "$PREFIX/current" | rootcmd tee "$BACKUP/current.link" >/dev/null; fi
for name in service socket; do
 if systemctl is-enabled --quiet "usbmuxd.$name" 2>/dev/null; then rootcmd touch "$BACKUP/$name.enabled"; fi
 if systemctl is-active --quiet "usbmuxd.$name" 2>/dev/null; then rootcmd touch "$BACKUP/$name.active"; fi
done
rootcmd install -d -m 755 "$STATE/last-backup"
printf '%s\n' "$BACKUP" | rootcmd tee "$STATE/last-backup/path" >/dev/null
# Generate service with a fixed private lib path; existing distro socket is disabled.
cat >"$WORK/usbmuxd.service" <<'UNIT'
[Unit]
Description=usbmuxd2 (prosch88 fork, Apple USB and KIS)
After=systemd-udevd.service

[Service]
Type=simple
Environment=LD_LIBRARY_PATH=/opt/usbmuxd2/current/lib
ExecStart=/opt/usbmuxd2/current/bin/usbmuxd --user usbmux --systemd
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
# The fork's own udev rules were generated by configure with the correct activation.
RULE_SRC="$(find "$STAGE/share/usbmuxd2/udev" -name '*usbmuxd*.rules' -type f -print -quit 2>/dev/null || true)"
[[ -n "$RULE_SRC" ]] || fail 'No generated usbmuxd udev rule found; aborting before service replacement'
# Ensure the service account exists without removing an existing account.
if ! getent group usbmux >/dev/null; then rootcmd groupadd --system usbmux; fi
if ! id -u usbmux >/dev/null 2>&1; then
 rootcmd useradd --system --gid usbmux --no-create-home --home-dir / --shell /usr/sbin/nologin usbmux
fi
log 'Activating new daemon; previous systemd/udev configuration saved.'
rootcmd systemctl stop usbmuxd.service || true
rootcmd systemctl disable --now usbmuxd.socket >/dev/null 2>&1 || true
rootcmd ln -sfn "$RELEASE" "$PREFIX/current"
rootcmd install -m 644 "$WORK/usbmuxd.service" "$UNIT"
rootcmd install -m 644 "$RULE_SRC" "$RULE"
rootcmd systemctl daemon-reload
rootcmd udevadm control --reload-rules
rootcmd systemctl enable usbmuxd.service
if ! rootcmd systemctl restart usbmuxd.service; then
 log 'Service failed to start; restoring previous configuration.'
 "$0" --rollback || true
 fail 'Activation failed; rollback attempted'
fi
sleep 2
if ! systemctl is-active --quiet usbmuxd.service; then
 log 'Service not active after startup; restoring previous configuration.'
 "$0" --rollback || true
 fail 'Activation health check failed; rollback attempted'
fi
log "SUCCESS: usbmuxd2 $COMMIT is active. Rollback: $ROOT/install.sh --rollback"
log 'Check USB operation with an attached device: journalctl -u usbmuxd.service -b'
