// Attribution: Etherparse version 0.21.0

use crate::packet::{error::layer::Layer, len_source::LenSource};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LenError {
    /// Expected minimum or maximum length conflicting with the
    /// `len` value.
    pub required_len: usize,

    /// Length limiting or exceeding the required length.
    pub len: usize,

    /// Source of the outer length (e.g. Slice or a length specified by
    /// an upper level protocol).
    pub len_source: LenSource,

    /// Layer in which the length error was encountered.
    pub layer: Layer,

    /// Offset from the start of the parsed data to the layer where the
    /// length error occurred.
    pub layer_start_offset: usize,
}

impl LenError {
    /// Adds an offset value to the `layer_start_offset` field.
    #[inline]
    pub const fn add_offset(self, offset: usize) -> Self {
        LenError {
            required_len: self.required_len,
            layer: self.layer,
            len: self.len,
            len_source: self.len_source,
            layer_start_offset: self.layer_start_offset + offset,
        }
    }
}

impl core::fmt::Display for LenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let len_source: &'static str = {
            match self.len_source {
                LenSource::Slice => "slice length",
                LenSource::BabelPacketBodyLength => "length retrieved from the Babel packet header",
                LenSource::BabelTlvBodyLength => "length retrieved from the Babel TLV header",
            }
        };

        if self.required_len > self.len {
            if self.layer_start_offset > 0 {
                write!(
                    f,
                    "{}: Not enough data to decode '{}'. {} byte(s) would be required, but only {} byte(s) are available based on the {} ('{}' starts at overall parsed byte {}).",
                    self.layer.error_title(),
                    self.layer,
                    self.required_len,
                    self.len,
                    len_source,
                    self.layer,
                    self.layer_start_offset
                )
            } else {
                write!(
                    f,
                    "{}: Not enough data to decode '{}'. {} byte(s) would be required, but only {} byte(s) are available based on the {}.",
                    self.layer.error_title(),
                    self.layer,
                    self.required_len,
                    self.len,
                    len_source
                )
            }
        } else if self.layer_start_offset > 0 {
            write!(
                f,
                "{}: Length of {} byte(s) is too big for an '{}' (maximum is {} bytes). The {} was used to determine the length ('{}' starts at overall parsed byte {}).",
                self.layer.error_title(),
                self.len,
                self.layer,
                self.required_len,
                len_source,
                self.layer,
                self.layer_start_offset
            )
        } else {
            write!(
                f,
                "{}: Length of {} byte(s) is too big for an '{}' (maximum is {} bytes). The {} was used to determine the length.",
                self.layer.error_title(),
                self.len,
                self.layer,
                self.required_len,
                len_source
            )
        }
    }
}

impl core::error::Error for LenError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;
    use std::{
        collections::hash_map::DefaultHasher,
        error::Error,
        hash::{Hash, Hasher},
    };

    #[test]
    fn add_offset() {
        assert_eq!(
            LenError {
                required_len: 2,
                layer: Layer::BabelPacketHeader,
                len: 1,
                len_source: LenSource::Slice,
                layer_start_offset: 20,
            }
            .add_offset(100),
            LenError {
                required_len: 2,
                layer: Layer::BabelPacketHeader,
                len: 1,
                len_source: LenSource::Slice,
                layer_start_offset: 120,
            }
        );
    }

    #[test]
    fn debug() {
        assert_eq!(
            format!(
                "{:?}",
                LenError {
                    required_len: 2,
                    layer: Layer::BabelPacketHeader,
                    len: 1,
                    len_source: LenSource::Slice,
                    layer_start_offset: 0
                }
            ),
            format!(
                "LenError {{ required_len: {:?}, len: {:?}, len_source: {:?}, layer: {:?}, layer_start_offset: {:?} }}",
                2,
                1,
                LenSource::Slice,
                Layer::BabelPacketHeader,
                0
            ),
        );
    }

    #[test]
    fn clone_eq_hash() {
        let err = LenError {
            required_len: 2,
            layer: Layer::BabelPacketHeader,
            len: 1,
            len_source: LenSource::Slice,
            layer_start_offset: 20,
        };
        assert_eq!(err, err.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            err.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            err.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn fmt() {
        // len sources based tests (not enough data)
        {
            let len_source_tests = [
                (
                    LenSource::Slice,
                    "Babel Header Error: Not enough data to decode 'IPv4 header'. 2 byte(s) would be required, but only 1 byte(s) are available based on the slice length.",
                ),
                (LenSource::BabelPacketBodyLength, ""),
            ];

            for test in len_source_tests {
                assert_eq!(
                    test.1,
                    format!(
                        "{}",
                        LenError {
                            required_len: 2,
                            layer: Layer::BabelPacketHeader,
                            len: 1,
                            len_source: test.0,
                            layer_start_offset: 0
                        }
                    )
                );
            }
        }

        // start offset based test
        assert_eq!(
            "IPv4 Header Error: Not enough data to decode 'IPv4 header'. 2 byte(s) would be required, but only 1 byte(s) are available based on the slice length ('IPv4 header' starts at overall parsed byte 4).",
            format!(
                "{}",
                LenError {
                    required_len: 2,
                    len: 1,
                    len_source: LenSource::Slice,
                    layer: Layer::BabelPacketHeader,
                    layer_start_offset: 4
                }
            )
        );

        // len sources based tests (length too big)
        {
            let len_source_tests = [(
                LenSource::Slice,
                "IPv4 Header Error: Length of 2 byte(s) is too big for an 'IPv4 header' (maximum is 1 bytes). The slice length was used to determine the length.",
            )];

            for (idx, test) in len_source_tests.iter().enumerate() {
                assert_eq!(
                    test.1,
                    format!(
                        "{}",
                        LenError {
                            required_len: 1,
                            layer: Layer::BabelPacketHeader,
                            len: 2,
                            len_source: test.0,
                            layer_start_offset: 0
                        }
                    ),
                    "test {}",
                    idx
                );
            }
        }

        // start offset based test
        assert_eq!(
            "IPv4 Header Error: Length of 2 byte(s) is too big for an 'IPv4 header' (maximum is 1 bytes). The slice length was used to determine the length ('IPv4 header' starts at overall parsed byte 4).",
            format!(
                "{}",
                LenError {
                    required_len: 1,
                    len: 2,
                    len_source: LenSource::Slice,
                    layer: Layer::BabelPacketHeader,
                    layer_start_offset: 4
                }
            )
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(LenError {
            required_len: 0,
            len: 0,
            len_source: LenSource::Slice,
            layer: Layer::BabelPacketHeader,
            layer_start_offset: 0
        }
        .source()
        .is_none());
    }
}
