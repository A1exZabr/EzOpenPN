#!/usr/bin/env bash

set +x
set -Eeuo pipefail
umask 077

installer_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
bundle_root="${EZOPENPN_BUNDLE_ROOT:-$(cd "${installer_directory}/.." && pwd -P)}"
export EZOPENPN_BUNDLE_ROOT="$bundle_root"

# shellcheck disable=SC1091
source "${installer_directory}/lib/common.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/state.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/lock.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/preflight.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/docker.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/firewall.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/configure.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/credentials.sh"
# shellcheck disable=SC1091
source "${installer_directory}/lib/install.sh"

unset bundle_root installer_directory
installer_main "$@"
