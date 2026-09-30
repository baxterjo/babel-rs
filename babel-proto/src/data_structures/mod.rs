//! Implementaion of the data structures described in section [3.2](https://datatracker.ietf.org/doc/html/rfc8966#name-data-structures) of the spec.

/// Implementation of the interface table as described in [3.2.3](https://datatracker.ietf.org/doc/html/rfc8966#name-the-interface-table)
pub mod interface;

/// Implementation of the neighbour table as described in [3.2.4](https://datatracker.ietf.org/doc/html/rfc8966#name-the-neighbour-table)
pub mod neighbour;

/// Implementation of the source table as described in [3.2.5](https://datatracker.ietf.org/doc/html/rfc8966#name-the-source-table)
pub mod source;

/// Implementation of the route table as described in [3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub mod route;

/// Implementation of the table of pending sequence requests as described in [3.2.7](https://datatracker.ietf.org/doc/html/rfc8966#name-the-table-of-pending-seqno-)
pub mod pending_seqno;

/// Table containing pending updates.
pub mod updates;
