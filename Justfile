
# List available recipes.
default:
    @just --list

# Format the workspace.
fmt:
    cargo +nightly fmt

# Verify formatting without writing changes (CI / pre-commit).
fmt-check:
    cargo +nightly fmt --check
