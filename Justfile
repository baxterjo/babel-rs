
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
