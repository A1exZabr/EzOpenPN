#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export TEST_PUBLISHED_ROOT="$BATS_TEST_TMPDIR/release"
  export TEST_PUBLISHED_REQUESTS="$BATS_TEST_TMPDIR/requests"
  export TEST_PUBLISHED_COMMIT=0123456789abcdef0123456789abcdef01234567
  SOURCE_DATE_EPOCH=1800000000 bash "$REPOSITORY_ROOT/tools/build_release.sh" \
    --version v0.1.0 --source-commit "$TEST_PUBLISHED_COMMIT" \
    --images-manifest "$REPOSITORY_ROOT/tests/release/fixtures/images.release.json" \
    --output "$TEST_PUBLISHED_ROOT" >/dev/null
  printf '%s\n' '{}' >"$TEST_PUBLISHED_ROOT/ezopenpn-bundle.sigstore.json"
  printf '%s\n' '{}' >"$TEST_PUBLISHED_ROOT/SHA256SUMS.sigstore.json"
  printf '%s\n' '{"spdxVersion":"SPDX-2.3"}' >"$TEST_PUBLISHED_ROOT/ezopenpn-bundle.spdx.json"
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  cp "$REPOSITORY_ROOT/tests/shell/helpers/published-curl.bash" "$BATS_TEST_TMPDIR/bin/curl"
  printf '%s\n' '#!/usr/bin/env bash' '[[ "${TEST_BAD_SIGNATURE:-0}" == 0 ]]' \
    >"$BATS_TEST_TMPDIR/bin/cosign"
  chmod 0700 "$BATS_TEST_TMPDIR/bin/"*
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

@test "published release checks the anonymous Forgejo assets and their commit" {
  run bash "$REPOSITORY_ROOT/tools/verify_release.sh" --published v0.1.0 "$TEST_PUBLISHED_COMMIT"

  [ "$status" -eq 0 ]
  [ "$(wc -l <"$TEST_PUBLISHED_REQUESTS" | tr -d ' ')" = 6 ]
  [[ "$output" == *"Published release v0.1.0 verified"* ]]
}

@test "published release rejects artifacts from another commit" {
  run bash "$REPOSITORY_ROOT/tools/verify_release.sh" --published v0.1.0 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  [ "$status" -ne 0 ]
  [[ "$output" == *"published release does not match the requested tag and commit"* ]]
}

@test "published release rejects a bad signature" {
  export TEST_BAD_SIGNATURE=1
  run bash "$REPOSITORY_ROOT/tools/verify_release.sh" --published v0.1.0 "$TEST_PUBLISHED_COMMIT"

  [ "$status" -ne 0 ]
  [[ "$output" == *"release signature identity is invalid"* ]]
}

@test "published release fails closed when any required asset is missing" {
  rm "$TEST_PUBLISHED_ROOT/SHA256SUMS.sigstore.json"
  run bash "$REPOSITORY_ROOT/tools/verify_release.sh" --published v0.1.0 "$TEST_PUBLISHED_COMMIT"

  [ "$status" -ne 0 ]
  [[ "$output" != *"Published release v0.1.0 verified"* ]]
}
