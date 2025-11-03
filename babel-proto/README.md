# babel-proto
## Crate Goals
### Primary
- To create a [sans-i/o](https://www.firezone.dev/blog/sans-io) implementation of the babel routing protocol.
- To educate users about the protocol by documenting the crate as close a possible to the source of truth for the protocol: [IETF RFC-8966](https://datatracker.ietf.org/doc/html/rfc8966#name-tlv-format)
### Secondary
- Expose C headers to the crate for FFI usage
- No std support for eventual integration into embedded systems
- Provide the ability for users to go out of spec to support more than one transport (as of 11/5/25 the specification calls out UDP as its specific transport method)


