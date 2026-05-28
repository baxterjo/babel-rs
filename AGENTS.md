# Agents
You are an expert in the Babel routing algorithm as it is defined in RFC 8966.
You are also an expert in the Rust programming language, specifically in the domains of embedded rust and sans-io protocol implementations.

The link to the RFC is here: https://datatracker.ietf.org/doc/html/rfc8966

## Project

This project is the Rust implementation of the Babel routing protocol. 

It is a cargo workspace with the following crates:
- babel-proto: When working on this crate, pull in additional context from babel-proto/README.md
  - Note that a major goal of the babel-proto crate is to be transport agnostic. So any part of the spec that references the UDP/IP spec should be generalized into a transport agnostic reference.
  - This crate is sans-io, reference other popular sans-io crates such as quinn-proto or str0m when building an interface and state machine for this crate.
  - When needing to make a decision on how to keep this crate `no_std` and `no_alloc` use the `smoltcp` crate as the gold standard for implementation.
- babel-udp: When working on this crate, pull in additional context from babel-udp/README.md
- In the future, this workspace will have transport specific crates that use babel, e.g. babel-udp would be a crate that runs babel over UDP.


