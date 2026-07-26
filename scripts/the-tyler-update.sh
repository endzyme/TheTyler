#!/usr/bin/env bash
#
# the-tyler-update.sh — pull-based auto-updater for The Tyler.
#
# Polls the GitHub Releases API for the latest tagged release, and if it is
# strictly newer than what is installed, downloads the release tarball for this
# host's architecture, verifies it against checksums.txt, atomically swaps the
# managed binaries in place, and restarts the affected systemd units.
#
# Designed to be run as a root oneshot from a systemd timer. See the
# accompanying the-tyler-update.service / the-tyler-update.timer units.
#
# Configuration (via environment, typically an EnvironmentFile):
#   GITHUB_REPO   owner/repo to pull releases from   (default: endzyme/thetyler)
#   INSTALL_DIR   where the binaries live            (default: /opt/thetyler/bin)
#   COMPONENTS    space-separated "binary:unit" pairs this host manages, e.g.
#                 "thetyler:thetyler.service nftables-sync-client:thetyler-nftables.service"
#   SCRIPT_PATH   path to this script, for self-update
#                 (default: INSTALL_DIR/the-tyler-update.sh)
#   GITHUB_TOKEN  optional token to raise the API rate limit
#
set -euo pipefail

GITHUB_REPO="${GITHUB_REPO:-endzyme/thetyler}"
INSTALL_DIR="${INSTALL_DIR:-/opt/thetyler/bin}"
COMPONENTS="${COMPONENTS:-thetyler:thetyler.service nftables-sync-client:thetyler-nftables.service}"
SCRIPT_PATH="${SCRIPT_PATH:-${INSTALL_DIR}/the-tyler-update.sh}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

log() { printf '[the-tyler-update] %s\n' "$*"; }
die() { printf '[the-tyler-update] ERROR: %s\n' "$*" >&2; exit 1; }

# Serialize runs so an overlapping timer firing can't race a swap in progress.
LOCK_FILE="/run/the-tyler-update.lock"
exec 9>"$LOCK_FILE" || die "cannot open lock file $LOCK_FILE"
if ! flock -n 9; then
	log "another update run holds the lock; exiting"
	exit 0
fi

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

# --- Architecture -----------------------------------------------------------
case "$(uname -m)" in
	x86_64 | amd64) ARCH="amd64" ;;
	aarch64 | arm64) ARCH="arm64" ;;
	*) die "unsupported architecture: $(uname -m)" ;;
esac

# --- curl helper (adds auth header only when a token is set) ----------------
gh_curl() {
	if [ -n "$GITHUB_TOKEN" ]; then
		curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$@"
	else
		curl -fsSL "$@"
	fi
}

# --- Latest released tag ----------------------------------------------------
API_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
RELEASE_JSON="$(gh_curl "$API_URL")" || die "failed to query $API_URL"
# Extract "tag_name": "vX.Y.Z" without depending on jq.
LATEST_TAG="$(printf '%s' "$RELEASE_JSON" \
	| grep -m1 '"tag_name"' \
	| sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
[ -n "$LATEST_TAG" ] || die "could not parse tag_name from GitHub API response"
LATEST_VER="${LATEST_TAG#v}"

# --- Installed version (first managed binary is the reference) --------------
FIRST_BIN="${COMPONENTS%%:*}"
REF_BIN="${INSTALL_DIR}/${FIRST_BIN}"
if [ -x "$REF_BIN" ]; then
	INSTALLED_VER="$("$REF_BIN" --version 2>/dev/null | head -n1 | tr -d '[:space:]')"
else
	INSTALLED_VER=""
fi
INSTALLED_VER="${INSTALLED_VER#v}"

log "installed=${INSTALLED_VER:-none} latest=${LATEST_VER}"

if [ "$INSTALLED_VER" = "$LATEST_VER" ]; then
	log "already up to date"
	exit 0
fi

# Only move forward: refuse to "update" to an older tag (e.g. a yanked release).
if [ -n "$INSTALLED_VER" ]; then
	NEWEST="$(printf '%s\n%s\n' "$INSTALLED_VER" "$LATEST_VER" | sort -V | tail -n1)"
	if [ "$NEWEST" != "$LATEST_VER" ]; then
		log "latest ($LATEST_VER) is not newer than installed ($INSTALLED_VER); skipping"
		exit 0
	fi
fi

# --- Download + verify ------------------------------------------------------
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

ARCHIVE="the-tyler_${LATEST_VER}_linux_${ARCH}.tar.gz"
BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_TAG}"

log "downloading ${ARCHIVE}"
gh_curl -o "${TMP_DIR}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}" || die "failed to download ${ARCHIVE}"
gh_curl -o "${TMP_DIR}/checksums.txt" "${BASE_URL}/checksums.txt" || die "failed to download checksums.txt"

log "verifying checksum"
(
	cd "$TMP_DIR"
	# Check only the line for our archive so unrelated assets don't fail the run.
	grep -E "  ${ARCHIVE}\$" checksums.txt >checksums.filtered \
		|| die "no checksum entry for ${ARCHIVE}"
	sha256sum -c checksums.filtered
) || die "checksum verification failed for ${ARCHIVE}"

log "extracting"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"

# --- Swap changed binaries --------------------------------------------------
RESTART_UNITS=""
for pair in $COMPONENTS; do
	bin="${pair%%:*}"
	unit="${pair##*:}"
	new="${TMP_DIR}/${bin}"
	cur="${INSTALL_DIR}/${bin}"

	if [ ! -f "$new" ]; then
		log "warning: ${bin} not present in release archive; skipping"
		continue
	fi

	# Skip if byte-identical to what's already installed.
	if [ -f "$cur" ] && cmp -s "$new" "$cur"; then
		log "${bin} unchanged"
		continue
	fi

	install -m 0755 "$new" "${cur}.new"
	[ -f "$cur" ] && cp -p "$cur" "${cur}.bak"
	mv -f "${cur}.new" "$cur" # atomic rename on the same filesystem
	log "${bin} updated -> ${LATEST_VER}"
	RESTART_UNITS="${RESTART_UNITS} ${unit}"
done

# --- Self-update the script (last, right before restarts) -------------------
if [ -f "${TMP_DIR}/the-tyler-update.sh" ] && [ -n "$SCRIPT_PATH" ]; then
	if ! cmp -s "${TMP_DIR}/the-tyler-update.sh" "$SCRIPT_PATH"; then
		install -m 0755 "${TMP_DIR}/the-tyler-update.sh" "${SCRIPT_PATH}.new"
		mv -f "${SCRIPT_PATH}.new" "$SCRIPT_PATH"
		log "updater script refreshed"
	fi
fi

if [ -z "$RESTART_UNITS" ]; then
	log "no managed binaries changed; nothing to restart"
	exit 0
fi

# --- Restart affected units -------------------------------------------------
for unit in $RESTART_UNITS; do
	log "restarting ${unit}"
	systemctl restart "$unit" || log "warning: failed to restart ${unit}"
done

log "update to ${LATEST_VER} complete"
