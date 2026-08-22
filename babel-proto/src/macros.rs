#[cfg(not(test))]
#[cfg(feature = "log")]
macro_rules! b_log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*) };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*) };
}

#[cfg(test)]
#[cfg(all(feature = "log", feature = "std"))]
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

macro_rules! ok_or_continue {
    ($result:expr) => {
        match $result {
            Ok(val) => val,
            Err(err) => {
                b_debug!("{:?} : {}", err, err);
                continue;
            }
        }
    };
}
