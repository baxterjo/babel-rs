#[cfg(feature = "log")]
macro_rules! b_log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*) };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*) };
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

/// Used to unwrap packet writer errors
macro_rules! writer_ok_or_debug_break {
    ($result:expr) => {
        match $result {
            Ok(wr) => wr,
            Err((err, wr)) => {
                b_debug!("{:?} : {}", err, err);
                break wr;
            }
        }
    };
}
