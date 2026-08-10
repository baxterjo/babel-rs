# Babel Proto
A Sans-IO implementation of the Babel routing protocol as defined in IETF RFC 8966.

# Namespace Reservation

I am publishing a non-working version of this crate to reserve the namespace. If there is no activity in this crate for 6 months and you have a working version. Pleas contact me and I will transfer ownership of the crate to you.

## Attributions
### smoltcp
A lot of this crate's design around how to implement a `no_std` `no_alloc` crate are heavily inspired by [`smoltcp`](https://github.com/smoltcp-rs/smoltcp), with some of the crate setup and macros straight copy / pasta'd from them. Thanks a bunch to the maintainers of `smoltcp`.
