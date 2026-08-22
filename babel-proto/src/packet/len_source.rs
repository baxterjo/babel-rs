// Attribution: etherparse 0.21.0

/// Sources of length limiting values (e.g. "packet body length field").
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LenSource {
    /// Limiting length was the slice length (we don't know what determined
    /// that one originally).
    Slice,
    /// Body length field in the Babel packet header.
    BabelPacketBodyLength,
    /// Body length field in the Babel TLV header.
    BabelTlvBodyLength,
    /// Expected address length based on address encoding
    AddressEncoding,
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use super::*;
    use alloc::format;
    use std::{
        cmp::Ordering,
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!("Slice", format!("{:?}", LenSource::Slice));
    }

    #[test]
    fn clone_eq_hash_ord() {
        let layer = LenSource::Slice;
        assert_eq!(layer, layer.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            layer.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            layer.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
        assert_eq!(Ordering::Equal, layer.cmp(&layer));
        assert_eq!(Some(Ordering::Equal), layer.partial_cmp(&layer));
    }
}
