#!/usr/bin/env bash

release_library_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "${release_library_directory}/../install.sh"
unset release_library_directory
