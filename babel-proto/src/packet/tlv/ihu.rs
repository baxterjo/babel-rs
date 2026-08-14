use crate::{
    data_types::{address::AddressExtension, address_encoding::AddressEncoding, Address, Interval},
    packet::tlv::{TlvEncodeError, TlvHeaderT, TlvParseError},
    utils::{cursor::ManagedSliceCursor, rx_cost::RxCost},
};

/// IHU TLV as defined in section
/// [4.6.6](https://datatracker.ietf.org/doc/html/rfc8966#name-ihu)
///
/// An IHU ("I Heard You") TLV is used for confirming bidirectional reachability and carrying a
/// link's transmission cost.
///
/// Conceptually, an IHU is destined to a single neighbour. However, IHU TLVs contain an explicit
/// destination address, and MAY be sent to a multicast address, as this allows aggregation of IHUs
/// destined to distinct neighbours into a single packet and avoids the need for an ARP or Neighbour
/// Discovery exchange when a neighbour is not being used for data traffic.
///
/// # Wire Format
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 5   |    Length     |       AE      |    Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Rxcost             |          Interval             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Address...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// Note: `Type`, `Length`, and `Reserved` fields are not held by the struct as they have no value
/// beyond parsing and encoding.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ihu<'input, E: AddressExtension> {
    /// The encoding of the Address field. This should be 1 or 3 in most cases. As an optimisation,
    /// it MAY be 0 if the TLV is sent to a unicast address, if the association is over a
    /// point-to-point link, or when bidirectional reachability is ascertained by means outside of
    /// the Babel protocol.
    ae: AddressEncoding<E>,
    /// The rxcost according to the sending node of the interface whose address is specified in the
    /// Address field. The value FFFF hexadecimal (infinity) indicates that this interface is
    /// unreachable.
    rx_cost: RxCost,
    /// An upper bound, expressed in centiseconds, on the time after which the sending node will
    /// send a new IHU; this MUST NOT be 0. The receiving node will use this value in order to
    /// compute a hold time for this symmetric association.
    interval: Interval,
    /// The address of the destination node, in the format specified by the AE field. Address
    /// compression is not allowed.
    address: Option<Address<E>>,
    /// This TLV is self-terminating and allows sub-TLVs.
    sub_tlvs: &'input [u8],
}

impl<E: AddressExtension> TlvHeaderT for Ihu<'_, E> {
    /// Set to 5 to indicate an IHU TLV.
    const TYPE_ID: u8 = 5;
}

impl<'input, E: AddressExtension> Ihu<'input, E> {
    /// Parses the entire tlv INCLUDING the already checked type field.
    ///
    /// Mutates the buffer as it parses bytes.
    // The reason this takes the `Type` field is for unit testing symetric parse / encode.
    pub(crate) fn parse(
        input: &mut &'input [u8],
        codec: AddressEncoding<E>,
    ) -> Result<Self, TlvParseError> {
        let (_headers, mut body, remainder) = Self::parse_header(input)?;

        *input = remainder;

        // Parse address encoding
        let (ae_bytes, rest) = parse_body!(body, u8);
        body = rest;
        let ae = AddressEncoding::from_wire(ae_bytes.try_into()?)?;

        // Parse and ignore reserved byte
        let (_reserved_byte, rest) = parse_body!(body, u8);
        body = rest;

        // Parse RxCost
        let (rx_cost_bytes, rest) = parse_body!(body, u16);
        body = rest;
        let rx_cost = RxCost::from_wire(rx_cost_bytes.try_into()?);

        // Parse interval
        let (interval_bytes, sub_tlvs) = parse_body!(body, u16);
        body = rest;
        let interval = Interval::from_wire(interval_bytes.try_into()?);

        let ((_address_bytes, sub_tlvs), address) = codec.decode(&ae, body)?;

        let stlv_opt = if sub_tlvs.len() > 0 {
            Some(sub_tlvs)
        } else {
            None
        };

        Ok(Self {
            ae,
            rx_cost,
            interval,
            address,
            sub_tlvs,
        })
    }

    /// Encodes the entire tlv into buf.
    ///
    /// Returns the position of the cursor when it succeeds.
    pub(crate) fn encode<'output>(
        &self,
        cursor: &mut ManagedSliceCursor<'output>,
    ) -> Result<usize, TlvEncodeError> {
        // Write type id
        cursor.write(&Self::TYPE_ID.to_be_bytes())?;

        // Skip and mark length
        let length_idx = cursor.mark_and_skip::<1>()?;
        let mut length = 0;

        // Write flags.
        length += cursor.write(&self.flags.0.to_be_bytes())?;

        // Write seqno
        length += cursor.write(&self.seqno.0.to_be_bytes())?;

        // Write interval
        length += cursor.write(&(self.interval.as_centis() as u16).to_be_bytes())?;

        // Write sub TLVS
        if let Some(stlv) = self.sub_tlvs {
            length += cursor.write(&stlv)?;
        }

        // Backfill length at the marked location
        cursor.backfill_at(length_idx, &[length as u8])?;

        Ok(cursor.position())
    }
}
