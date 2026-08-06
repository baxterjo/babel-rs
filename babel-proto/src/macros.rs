#[cfg(feature = "log")]
macro_rules! blog {
    (trace, $(arg:expr),*) => {log::trace!($($arg),*)};
    (debug, $(arg:expr),*) => {log::debug!($($arg),*)};
}

#[cfg(feature = "defmt")]
macro_rules! blog {
    (trace, $(arg:expr),*) => {defmt::trace!($($arg),*)};
    (debug, $(arg:expr),*) => {defmt::debug!($($arg),*)};
}

#[cfg(not(any(feature = "log", feature = "defmt")))]
macro_rules! blog {
    ($level:ident, $($arg:expr),*) => {{ $( let _ = $arg; )* }}
}

macro_rules! b_trace {
    ($(arg:expr),*) => {blog!(trace, $($arg),*)};
}

macro_rules! b_debug {
    ($(arg:expr),*) => {blog!(debug, $($arg),*)};
}
