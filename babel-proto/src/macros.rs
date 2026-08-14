#[cfg(not(test))]
#[cfg(feature = "log")]
macro_rules! b_log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*) };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*) };
}

#[cfg(test)]
#[cfg(feature = "log")]
macro_rules! b_log {
    (trace, $($arg:expr),*) => { println!($($arg),*) };
    (debug, $($arg:expr),*) => { println!($($arg),*) };
}

#[cfg(feature = "defmt")]
macro_rules! b_log {
    (trace, $($arg:expr),*) => {defmt::trace!($($arg),*)};
    (debug, $($arg:expr),*) => {defmt::debug!($($arg),*)};
}

#[cfg(not(any(feature = "log", feature = "defmt")))]
macro_rules! b_log {
    ($level:ident, $($arg:expr),*) => {{ $( let _ = $arg; )* }}
}

macro_rules! b_trace {
    ($($arg:expr),*) => {b_log!(trace, $($arg),*)};
}

macro_rules! b_debug {
    ($($arg:expr),*) => (b_log!(debug, $($arg),*));
}

macro_rules! parse_body {
    ($body:ident, $size_of:ty) => {
        $body
            .split_at_checked(size_of::<$size_of>())
            .ok_or(TlvParseError::BodyNotLongEnough)?
    };
}
