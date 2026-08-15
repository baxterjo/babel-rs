// Attribution: etherparse version 0.21.0

// NOTE: This error is implemented a bit different from others because it mirrors the etherparse
// crate errors. There is an open question on whether to include the Babel Packet in ehterparse
// [here](https://github.com/JulianSchmid/etherparse/discussions/164)

/// Layers on which an error can occur.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Layer {
    /// Error occured in the Babel packet header.
    BabelPacketHeader,
    /// Error occured in the Babel TLV header.
    BabelTlvHeader,
    /// Error occured verifying the length of the babel packet body.
    BabelPacketBody,
    /// Error occured verifying the length of the Babel TLV body.
    BabelTlvBody,
}

impl Layer {
    /// String that is used as a title for the error.
    pub fn error_title(&self) -> &'static str {
        use Layer::*;
        match self {
            BabelPacketHeader => "Babel packet header error",
            BabelPacketBody => "Babel packet body error",
            BabelTlvHeader => "Babel TLV header error",
            BabelTlvBody => "Babel TLV body error",
        }
    }
}

impl core::fmt::Display for Layer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use Layer::*;
        match self {
            BabelPacketHeader => write!(f, "Babel routing protocol packet header"),
            BabelPacketBody => write!(f, "Babel routing protocol packet body"),
            BabelTlvHeader => write!(f, "Babel routing protocol tlv header"),
            BabelTlvBody => write!(f, "Babel routing protocol tlv body"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Layer::*;
    use alloc::format;

    #[test]
    fn error_title() {
        let tests = [
            (BabelPacketHeader, "Babel packet header error"),
            (BabelPacketBody, "Babel packet body error"),
            (BabelTlvHeader, "Babel TLV header error"),
            (BabelTlvBody, "Babel TLV body error"),
        ];
        for test in tests {
            assert_eq!(test.0.error_title(), test.1);
        }
    }

    #[test]
    fn fmt() {
        let tests = [
            (BabelPacketHeader, "Babel routing protocol packet header"),
            (BabelPacketBody, "Babel routing protocol packet body"),
            (BabelTlvHeader, "Babel routing protocol tlv header"),
            (BabelTlvBody, "Babel routing protocol tlv body"),
        ];
        for test in tests {
            assert_eq!(format!("{}", test.0), test.1);
        }
    }
}
