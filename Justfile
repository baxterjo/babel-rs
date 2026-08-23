default-package := "babel_proto"

# List available recipes.
default:
    @just --list

# Format the workspace.
fmt:
    cargo +nightly fmt

# Verify formatting without writing changes (CI / pre-commit).
fmt-check:
    cargo +nightly fmt --check

# One-time setup for a fresh clone: opt in to the repo's committed git config.
setup:
    git config --local include.path {{ justfile_directory() }}/.gitconfig

# Serve the workspace docs with live reload: bacon rebuilds, browser-sync refreshes.
watch-doc crate=default-package:
    #!/usr/bin/env bash
    set -euo pipefail

    # make sure target/doc exists before browser-sync tries to serve it
    cargo doc --no-deps --color always

    # kill both background jobs when this script exits (Ctrl+C, error, etc.)
    trap 'kill 0' EXIT

    bacon doc --headless &
    # rustdoc writes no index.html at the root of a workspace's target/doc, so the
    # server has nothing to answer "/" with -- open the crate's own index instead,
    # and enable directory listings so the root is still browsable.
    npx browser-sync start \
        --server "target/doc" \
        --startPath "/{{ crate }}/index.html" \
        --directory \
        --files "target/doc/**/*.html, target/doc/**/*.js, target/doc/**/*.css" \
        --reload-debounce 500 \
        --no-notify &

    wait
