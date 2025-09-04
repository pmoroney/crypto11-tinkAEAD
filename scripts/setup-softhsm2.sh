#!/usr/bin/env bash
set -euo pipefail

# Setup a local SoftHSM2 store under ./.softhsm2 and initialize a token.
# Defaults can be overridden via env vars.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_DIR="${REPO_ROOT}/.softhsm2"
TOKENS_DIR="${CONF_DIR}/tokens"
CONF_FILE="${CONF_DIR}/softhsm2.conf"

LABEL="${SOFTHSM2_LABEL:-tinktest}"
SO_PIN="${SOFTHSM2_SO_PIN:-so-secret}"
USER_PIN="${SOFTHSM2_USER_PIN:-user-secret}"

if ! command -v softhsm2-util >/dev/null 2>&1; then
  echo "Error: softhsm2-util not found. Please install SoftHSM2." >&2
  echo "On Debian/Ubuntu: sudo apt-get install softhsm2" >&2
  exit 1
fi

mkdir -p "${TOKENS_DIR}"

cat >"${CONF_FILE}" <<EOF
directories.tokendir = ${TOKENS_DIR}
objectstore.backend = file
log.level = INFO
EOF

echo "SoftHSM2 config written to: ${CONF_FILE}"

# Ensure the current process uses the local config
export SOFTHSM2_CONF="${CONF_FILE}"

# Detect if a token with the desired label already exists (SoftHSM prints 'Label: <name>')
if softhsm2-util --show-slots | grep -Eq "^[[:space:]]*Label:[[:space:]]*${LABEL}[[:space:]]*$"; then
  echo "Token with label '${LABEL}' already exists. Skipping initialization."
else
  echo "Initializing new SoftHSM2 token with label '${LABEL}'..."
  softhsm2-util --init-token --free --label "${LABEL}" --so-pin "${SO_PIN}" --pin "${USER_PIN}"
fi

echo "Done. To use this config in the current shell, run:"
echo "  export SOFTHSM2_CONF=${CONF_FILE}"
echo "The tests look for ${CONF_FILE} automatically."
