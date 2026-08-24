# babel-rs
A sans I/O, no_std, no_alloc Rust implementation of the Babel routing protocol.


# Project Goals
## Function
- sans-i/o, sans-time crate allows babel to be plugged into any transport that can support the required bandwidth of the control packets.
- no_std, no_alloc crate allows babel to be used in embedded environments.
- Provide ready-made common transport implementations of the babel protocol that both demonstrates how to user babel-proto
## Learning
- Learn the babel routing protocol.
- Learn how to write a sans-i/o crate.
- Learn how to write a no_std, no_alloc crate.
- Doc comments structured in a way that helps teach the babel routing protocol.

# LLM Use
The initial implementation of babel-rs involves minimal LLM use. The development of this crate is partially for learning, and I will get the most out of it if I write much of the code myself, LLMs will be used for rubber ducking, writing tests, reviewing code that I have written, or when things start to get boilerplate-y (e.g.:TLV parsing in babel-proto). This stance is not a condemnation of the use of LLM's in general, there is no denying their usefulness in day to day code authorship and I have used them in other projects I have published. 

