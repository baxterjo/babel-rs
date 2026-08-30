use thiserror::Error;

use crate::utils::ManagedSlice;

pub(crate) mod finished_packet_body;
pub(crate) mod packet_state;
pub(crate) mod ready;
pub(crate) mod tlv;

use packet_state::PacketState;
use ready::Ready;

use crate::packet::packet_header_slice::PacketHeaderSlice;

// Attribution: Typestate writer inspired by [etherparse](https://docs.rs/etherparse/latest/etherparse/index.html)

/// A cursor utility to write to buffers easily.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct PacketWriter;

impl PacketWriter {
    pub(crate) fn new_packet<'a, T>(
        magic: u8,
        version: u8,
        buf: T,
    ) -> Result<PacketWriterStep<'a, Ready>, PacketWriterError>
    where
        T: Into<ManagedSlice<'a, u8>>,
    {
        let mut state = PacketState::new(buf.into());
        state.write(&[magic, version])?;
        state.mark_and_skip::<2>()?;

        Ok(PacketWriterStep {
            state,
            step_state: Ready {},
        })
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct PacketWriterStep<'a, LastStep> {
    state: PacketState<'a>,
    step_state: LastStep,
}

impl<LastStep> PacketWriterStep<'_, LastStep> {
    /// Helper function backtracks buff to starting position if write fails.
    fn write_or_backtrack(
        mut self,
        data: &[u8],
        start_position: usize,
    ) -> Result<(usize, Self), (PacketWriterError, Self)> {
        match self.state.write(data) {
            Ok(v) => Ok((v, self)),
            Err(err) => {
                self.state.roll_back(start_position);
                Err((err, self))
            }
        }
    }

    /// Helper function backtracks buff to starting position if mark and skip fails.
    fn mark_and_skip_or_backtrack<const N: usize>(
        mut self,
        start_position: usize,
    ) -> Result<(usize, Self), (PacketWriterError, Self)> {
        match self.state.mark_and_skip::<N>() {
            Ok(v) => Ok((v, self)),
            Err(err) => {
                self.state.roll_back(start_position);
                Err((err, self))
            }
        }
    }

    pub(crate) fn has_tlvs(&self) -> bool {
        self.state.position() - PacketHeaderSlice::LEN != 0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketWriterError {
    #[error("Buffer is too small, needed {need}, have {remaining}")]
    BufferTooSmall { need: usize, remaining: usize },
    #[error(
        "Tlv length is larger than max that can go in length field - len: {0}, max: {max}",
        max = u8::MAX
    )]
    TlvLengthLargerThanMax(usize),
    #[error(
        "Packet body length is larger than max that can go in length field - len: {0}, max: {max}",
        max = u16::MAX
    )]
    PacketBodyLengthLargerThanMax(usize),
    #[error("Failed to index at bounds {0}..{1}")]
    IndexError(usize, usize),
    #[error("Tried to finish an empty packet")]
    CannotFinishEmptyPacket,
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;

    use super::*;
    use crate::data_types::address_encoding::AddressEncoding;
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Address, RouterId};
    use crate::extension::NoExtension;
    use crate::metric::{Metric, RxCost};
    use crate::output::DatagramSend;
    use crate::packet::packet_slice::PacketSlice;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::packet::tlv::tlv_header::TlvHeader;
    use crate::packet::tlv::update_slice::UpdateFlags;
    use crate::packet::tlv::{RouterIdSlice, Tlv, TypedTlv};
    use crate::utils::Duration;

    /// The Router-Id used throughout these tests. It is neither all zeroes nor all ones, so
    /// [`RouterId::new`] accepts it.
    const ROUTER_ID: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

    fn router_id() -> RouterId {
        RouterId::new(ROUTER_ID).expect("Router id should be valid")
    }

    #[test]
    fn packet_writer_and_slice_yield_same_results() {
        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_hello(
                HelloFlags::new(true),
                SeqNo(0),
                Duration::from_centis(200).into(),
            )
            .expect("Could not write hello")
            .finish_tlv()
            .expect("Could not finish TLV")
            .write_ihu(
                1,
                RxCost::from_raw(5),
                Duration::from_centis(300).into(),
                &[192, 168, 0, 5],
            )
            .expect("Could not write IHU")
            .finish_tlv()
            .expect("Could not finish IHU tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");
        assert_eq!(
            packet_slice.trailer(),
            &[],
            "There should be no packet trailer."
        );

        for (idx, tlv) in packet_slice.body_reader().enumerate() {
            match idx {
                0 => {
                    let Tlv::Hello(hello) = tlv else {
                        panic!("First TLV should have been hello");
                    };
                    assert_eq!(hello.flags(), HelloFlags::new(true));
                    assert_eq!(hello.seqno(), SeqNo(0));
                    assert_eq!(hello.interval(), Duration::from_centis(200).into());
                    assert_eq!(hello.sub_tlvs(), &[]);
                }
                1 => {
                    let Tlv::Ihu(ihu) = tlv else {
                        panic!("Second TLV should have been ihu");
                    };
                    assert_eq!(ihu.ae(), 1);
                    assert_eq!(ihu.rx_cost(), RxCost::from_raw(5));
                    assert_eq!(ihu.interval(), Duration::from_centis(300).into());
                    assert_eq!(
                        ihu.address(4).expect("Failed to retrieve address from ihu"),
                        &[192, 168, 0, 5]
                    );
                    assert_eq!(
                        ihu.sub_tlvs(4)
                            .expect("Failed to retrieve sub_tlvs from ihu."),
                        &[]
                    );
                }
                _other => {
                    panic!("Should only have 2 packets");
                }
            }
        }
    }

    #[test]
    fn router_id_writer_and_slice_yield_same_results() {
        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_router_id(router_id())
            .expect("Could not write router id")
            .finish_tlv()
            .expect("Could not finish router id tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        // The Reserved octets are sent as zeroes, and the Length field counts the TLV body only, so
        // it is the 2 Reserved octets plus the 8 octet Router-Id.
        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 12, // Magic, Version, Body length
                6, 10, // Router-Id Type ID, Length
                0, 0, // Reserved
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            ],
            "Unexpected wire form"
        );

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");
        assert_eq!(
            packet_slice.trailer(),
            &[],
            "There should be no packet trailer."
        );

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::RouterId(slice) = tlv else {
                panic!("TLV should have been a router id");
            };
            assert_eq!(slice.router_id(), &ROUTER_ID, "Incorrect router id");
            assert_eq!(slice.sub_tlvs(), &[], "Should have no sub tlvs");
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    #[test]
    fn next_hop_writer_and_slice_yield_same_results() {
        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_next_hop(1, &[192, 168, 0, 5])
            .expect("Could not write next hop")
            .finish_tlv()
            .expect("Could not finish next hop tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 8, // Magic, Version, Body length
                7, 6, // Next Hop Type ID, Length
                1, 0, // AE, Reserved
                192, 168, 0, 5, // Next hop
            ],
            "Unexpected wire form"
        );

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");
        assert_eq!(
            packet_slice.trailer(),
            &[],
            "There should be no packet trailer."
        );

        let address_len = AddressEncoding::<NoExtension>::Ipv4.address_len();

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::NextHop(slice) = tlv else {
                panic!("TLV should have been a next hop");
            };
            assert_eq!(slice.ae(), 1, "Incorrect AE");
            assert_eq!(
                slice
                    .next_hop(address_len)
                    .expect("Should be able to get next hop"),
                &[192, 168, 0, 5],
                "Incorrect next hop"
            );
            assert_eq!(
                slice
                    .sub_tlvs(address_len)
                    .expect("Should be able to get sub tlvs"),
                &[],
                "Should have no sub tlvs"
            );
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    #[test]
    fn update_writer_and_slice_yield_same_results() {
        let prefix: Address<NoExtension> = core::net::Ipv4Addr::new(192, 168, 0, 5).into();

        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_update(
                1,
                UpdateFlags::new(true, true),
                32,
                0,
                Duration::from_centis(200).into(),
                SeqNo(42),
                Metric::from_raw(0x0100),
                prefix.as_wire(),
            )
            .expect("Could not write update")
            .finish_tlv()
            .expect("Could not finish update tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 16, // Magic, Version, Body length
                8, 14, // Update Type ID, Length
                1, 0xC0, // AE, Flags (Prefix | Router-Id)
                32, 0, // Plen, Omitted
                0, 200, // Interval
                0, 42, // Seqno
                0x01, 0x00, // Metric
                192, 168, 0, 5, // Prefix
            ],
            "Unexpected wire form"
        );

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");
        assert_eq!(
            packet_slice.trailer(),
            &[],
            "There should be no packet trailer."
        );

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::Update(slice) = tlv else {
                panic!("TLV should have been an update");
            };
            assert_eq!(slice.ae(), 1, "Incorrect AE");
            assert!(slice.flags().is_prefix(), "Prefix flag should be set");
            assert!(slice.flags().is_router_id(), "Router-Id flag should be set");
            assert_eq!(slice.plen(), 32, "Incorrect plen");
            assert_eq!(slice.ommitted(), 0, "Incorrect omitted");
            assert_eq!(
                slice.interval(),
                Duration::from_centis(200).into(),
                "Incorrect interval"
            );
            assert_eq!(slice.seqno(), SeqNo(42), "Incorrect seqno");
            assert_eq!(slice.metric(), Metric::from_raw(0x0100), "Incorrect metric");
            assert!(!slice.is_retraction(), "Should not be a retraction");
            assert_eq!(
                slice.prefix(0).expect("Should be able to get prefix"),
                &[192, 168, 0, 5],
                "Incorrect prefix"
            );
            assert_eq!(
                slice.sub_tlvs(0).expect("Should be able to get sub tlvs"),
                &[],
                "Should have no sub tlvs"
            );
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    /// A link-local address goes on the wire as the 8 octet suffix under `fe80::/64`, but Plen
    /// counts the whole 128 bit prefix. Dropping the implied octets is the caller's job —
    /// [`Address::as_wire`] does it here — and the reader recovers the field length by subtracting
    /// the octets AE 3 implies, so the two only agree if the caller really did drop them.
    #[test]
    fn update_writes_a_link_local_prefix_as_its_suffix() {
        let addr = core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0102, 0x0304, 0x0506, 0x0708);
        let prefix: Address<NoExtension> = addr.into();

        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_update(
                3,
                UpdateFlags::new(false, true),
                128,
                0,
                Duration::from_centis(200).into(),
                SeqNo(42),
                Metric::from_raw(0x0100),
                prefix.as_wire(),
            )
            .expect("Could not write update")
            .finish_tlv()
            .expect("Could not finish update tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 20, // Magic, Version, Body length
                8, 18, // Update Type ID, Length
                3, 0x40, // AE, Flags (Router-Id)
                128, 0, // Plen, Omitted
                0, 200, // Interval
                0, 42, // Seqno
                0x01, 0x00, // Metric
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Prefix
            ],
            "Unexpected wire form"
        );

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");
        let implied_octets = AddressEncoding::<NoExtension>::LocalIpv6.implied_prefix_octets();

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::Update(slice) = tlv else {
                panic!("TLV should have been an update");
            };
            assert_eq!(slice.ae(), 3, "Incorrect AE");
            assert_eq!(slice.plen(), 128, "Incorrect plen");

            let wire_prefix = slice
                .prefix(implied_octets)
                .expect("Should be able to get prefix");
            assert_eq!(
                wire_prefix,
                &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                "Incorrect prefix"
            );
            assert_eq!(
                slice
                    .sub_tlvs(implied_octets)
                    .expect("Should be able to get sub tlvs"),
                &[],
                "Should have no sub tlvs"
            );

            // The suffix on the wire has to rebuild the address the writer was handed, or the
            // receiver installs a route to a different destination.
            assert_eq!(
                Address::<NoExtension>::from_bytes(AddressEncoding::LocalIpv6, wire_prefix)
                    .expect("Wire prefix should parse"),
                prefix,
                "Round trip changed the address"
            );
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    /// A Plen shorter than the address only puts the octets it reaches on the wire: a /24 carries 3
    /// of the 4 an IPv4 address has. The writer copies the Prefix field it is handed, so trimming
    /// it is the caller's job.
    #[test]
    fn update_writes_only_the_octets_plen_reaches() {
        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_update(
                1,
                UpdateFlags::new(false, false),
                24,
                0,
                Duration::from_centis(200).into(),
                SeqNo(42),
                Metric::from_raw(0x0100),
                &[192, 168, 0],
            )
            .expect("Could not write update")
            .finish_tlv()
            .expect("Could not finish update tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 15, // Magic, Version, Body length
                8, 13, // Update Type ID, Length
                1, 0, // AE, Flags
                24, 0, // Plen, Omitted
                0, 200, // Interval
                0, 42, // Seqno
                0x01, 0x00, // Metric
                192, 168, 0, // Prefix
            ],
            "Unexpected wire form"
        );

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::Update(slice) = tlv else {
                panic!("TLV should have been an update");
            };
            assert_eq!(slice.plen(), 24, "Incorrect plen");
            assert_eq!(
                slice.prefix(0).expect("Should be able to get prefix"),
                &[192, 168, 0],
                "Incorrect prefix"
            );
            assert_eq!(
                slice.sub_tlvs(0).expect("Should be able to get sub tlvs"),
                &[],
                "Should have no sub tlvs"
            );
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    /// A non-zero Omitted drops leading octets the receiver takes from an earlier default prefix.
    /// The reader subtracts Omitted from the field length, so a caller that sets it without
    /// trimming the same octets off `prefix` would have the surplus read back as sub-TLVs.
    #[test]
    fn update_writes_a_prefix_with_omitted_octets() {
        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_update(
                1,
                UpdateFlags::new(false, false),
                24,
                2,
                Duration::from_centis(200).into(),
                SeqNo(42),
                Metric::from_raw(0x0100),
                &[5],
            )
            .expect("Could not write update")
            .finish_tlv()
            .expect("Could not finish update tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 13, // Magic, Version, Body length
                8, 11, // Update Type ID, Length
                1, 0, // AE, Flags
                24, 2, // Plen, Omitted
                0, 200, // Interval
                0, 42, // Seqno
                0x01, 0x00, // Metric
                5,    // Prefix
            ],
            "Unexpected wire form"
        );

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::Update(slice) = tlv else {
                panic!("TLV should have been an update");
            };
            assert_eq!(slice.ommitted(), 2, "Incorrect omitted");
            assert_eq!(
                slice.prefix(0).expect("Should be able to get prefix"),
                &[5],
                "Incorrect prefix"
            );
            assert_eq!(
                slice.sub_tlvs(0).expect("Should be able to get sub tlvs"),
                &[],
                "Should have no sub tlvs"
            );
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    /// An AE 0 blanket retraction withdraws every route the sender advertised on the interface. It
    /// carries no prefix at all, which the old `Address` parameter had no way to name.
    #[test]
    fn update_writes_a_blanket_retraction() {
        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_update(
                0,
                UpdateFlags::new(false, false),
                0,
                0,
                Duration::from_centis(200).into(),
                SeqNo(0),
                Metric::INFINITY,
                &[],
            )
            .expect("Could not write update")
            .finish_tlv()
            .expect("Could not finish update tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 12, // Magic, Version, Body length
                8, 10, // Update Type ID, Length
                0, 0, // AE, Flags
                0, 0, // Plen, Omitted
                0, 200, // Interval
                0, 0, // Seqno
                0xFF, 0xFF, // Metric
            ],
            "Unexpected wire form"
        );

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::Update(slice) = tlv else {
                panic!("TLV should have been an update");
            };
            assert!(
                slice.is_blanket_retraction(),
                "Should be a blanket retraction"
            );
            assert_eq!(
                slice.prefix(0).expect("Should be able to get prefix"),
                &[],
                "Should have an empty prefix"
            );
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    /// A retraction is an Update with an infinite metric, and it is the one Update whose Seqno and
    /// router-id are not used by the receiver, so the writer still has to frame it like any other.
    #[test]
    fn update_writes_a_retraction() {
        let prefix: Address<NoExtension> = core::net::Ipv4Addr::new(192, 168, 0, 5).into();

        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_update(
                1,
                UpdateFlags::new(false, false),
                32,
                0,
                Duration::from_centis(200).into(),
                SeqNo(42),
                Metric::INFINITY,
                prefix.as_wire(),
            )
            .expect("Could not write update")
            .finish_tlv()
            .expect("Could not finish update tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");

        let mut count = 0;
        for tlv in packet_slice.body_reader() {
            let Tlv::Update(slice) = tlv else {
                panic!("TLV should have been an update");
            };
            assert_eq!(slice.metric(), Metric::INFINITY, "Incorrect metric");
            assert!(slice.is_retraction(), "Should be a retraction");
            assert!(
                !slice.is_blanket_retraction(),
                "A retraction with a non-zero AE retracts one route, not all of them"
            );
            count += 1;
        }
        assert_eq!(count, 1, "Should have written exactly one TLV");
    }

    /// Router-Id and Next Hop set the parser state that the Update behind them inherits, so the
    /// three have to come back out of the packet in the order they went in.
    #[test]
    fn router_id_next_hop_and_update_round_trip_in_one_packet() {
        let prefix: Address<NoExtension> = core::net::Ipv4Addr::new(192, 168, 0, 5).into();

        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");
        let datagram: DatagramSend<'_> = writer
            .write_router_id(router_id())
            .expect("Could not write router id")
            .finish_tlv()
            .expect("Could not finish router id tlv")
            .write_next_hop(1, &[10, 0, 0, 1])
            .expect("Could not write next hop")
            .finish_tlv()
            .expect("Could not finish next hop tlv")
            .write_update(
                1,
                UpdateFlags::new(false, false),
                32,
                0,
                Duration::from_centis(200).into(),
                SeqNo(7),
                Metric::from_raw(96),
                prefix.as_wire(),
            )
            .expect("Could not write update")
            .finish_tlv()
            .expect("Could not finish update tlv")
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        let packet_slice = PacketSlice::from_slice(&datagram).expect("Packet should slice.");
        assert_eq!(
            packet_slice.trailer(),
            &[],
            "There should be no packet trailer."
        );
        // 12 octets of Router-Id, 8 of Next Hop and 16 of Update, each including its 2 octet header.
        assert_eq!(packet_slice.body_length(), 36, "Incorrect body length");

        let address_len = AddressEncoding::<NoExtension>::Ipv4.address_len();

        let mut count = 0;
        for (idx, tlv) in packet_slice.body_reader().enumerate() {
            match idx {
                0 => {
                    let Tlv::RouterId(slice) = tlv else {
                        panic!("First TLV should have been a router id");
                    };
                    assert_eq!(slice.router_id(), &ROUTER_ID, "Incorrect router id");
                }
                1 => {
                    let Tlv::NextHop(slice) = tlv else {
                        panic!("Second TLV should have been a next hop");
                    };
                    assert_eq!(slice.ae(), 1, "Incorrect AE");
                    assert_eq!(
                        slice
                            .next_hop(address_len)
                            .expect("Should be able to get next hop"),
                        &[10, 0, 0, 1],
                        "Incorrect next hop"
                    );
                }
                2 => {
                    let Tlv::Update(slice) = tlv else {
                        panic!("Third TLV should have been an update");
                    };
                    assert_eq!(slice.seqno(), SeqNo(7), "Incorrect seqno");
                    assert_eq!(slice.metric(), Metric::from_raw(96), "Incorrect metric");
                    assert_eq!(
                        slice.prefix(0).expect("Should be able to get prefix"),
                        &[192, 168, 0, 5],
                        "Incorrect prefix"
                    );
                }
                _other => {
                    panic!("Should only have 3 TLVs");
                }
            }
            count += 1;
        }
        assert_eq!(count, 3, "Should have written exactly three TLVs");
    }

    /// A borrowed buffer that cannot hold the smallest possible Router-Id TLV is rejected before
    /// anything is written, and the writer is handed back so the caller can finish the packet with
    /// the TLVs it already has.
    #[test]
    fn write_router_id_rejects_a_buffer_that_cannot_hold_it() {
        // 4 octets of packet header leaves 11, one short of the 12 a Router-Id TLV needs.
        let mut buf = [0u8; 15];
        let writer = PacketWriter::new_packet(42, 2, buf.as_mut_slice())
            .expect("Should create packet writer");

        let (err, writer) = writer
            .write_router_id(router_id())
            .expect_err("Router id should not fit");

        assert_eq!(
            err,
            PacketWriterError::BufferTooSmall {
                need: TlvHeader::LEN + RouterIdSlice::MIN_LEN,
                remaining: 11
            },
            "Incorrect error"
        );
        assert!(!writer.has_tlvs(), "Nothing should have been written");

        drop(writer);
        assert_eq!(&buf[4..], &[0u8; 11], "The body should be untouched");
    }

    /// The escape hatch only checks for the *minimum* TLV size, so an address longer than the
    /// remaining buffer gets past it and fails partway through. Everything written so far has to be
    /// rolled back, or `finish_packet` would emit a truncated TLV.
    #[test]
    fn write_next_hop_rolls_back_a_partial_tlv() {
        // 4 octets of packet header leaves 8: enough for the 4 octet minimum, but not for the 4
        // octet fixed part plus a 16 octet address.
        let mut buf = [0u8; 12];
        let writer = PacketWriter::new_packet(42, 2, buf.as_mut_slice())
            .expect("Should create packet writer");

        let (err, writer) = writer
            .write_next_hop(2, &[0xFD; 16])
            .expect_err("Next hop should not fit");

        assert_eq!(
            err,
            PacketWriterError::BufferTooSmall {
                need: 16,
                remaining: 4
            },
            "Incorrect error"
        );
        assert!(
            !writer.has_tlvs(),
            "The partial TLV should have been rolled back"
        );

        drop(writer);
        assert_eq!(&buf[4..], &[0u8; 8], "The partial TLV should be erased");
    }

    /// Same partial-write path as [`write_next_hop_rolls_back_a_partial_tlv`], but for the Update
    /// TLV, which gets all the way to its Prefix field before it runs out of room.
    #[test]
    fn write_update_rolls_back_a_partial_tlv() {
        let prefix: Address<NoExtension> = core::net::Ipv4Addr::new(192, 168, 0, 5).into();

        // 4 octets of packet header leaves 13: past the 12 octet minimum, but 3 short of the 16 the
        // whole TLV needs.
        let mut buf = [0u8; 17];
        let writer = PacketWriter::new_packet(42, 2, buf.as_mut_slice())
            .expect("Should create packet writer");

        let (err, writer) = writer
            .write_update(
                1,
                UpdateFlags::new(false, false),
                32,
                0,
                Duration::from_centis(200).into(),
                SeqNo(42),
                Metric::from_raw(0x0100),
                prefix.as_wire(),
            )
            .expect_err("Update should not fit");

        assert_eq!(
            err,
            PacketWriterError::BufferTooSmall {
                need: 4,
                remaining: 1
            },
            "Incorrect error"
        );
        assert!(
            !writer.has_tlvs(),
            "The partial TLV should have been rolled back"
        );

        drop(writer);
        assert_eq!(&buf[4..], &[0u8; 13], "The partial TLV should be erased");
    }

    /// A rolled back TLV must leave the writer usable: the packet it goes on to finish is framed by
    /// the TLVs that did fit, not by the one that did not.
    #[test]
    fn a_rejected_tlv_leaves_the_writer_usable() {
        // Room for the packet header, a Next Hop TLV with a 4 octet address, and nothing more.
        let mut buf = [0u8; 12];
        let writer = PacketWriter::new_packet(42, 2, buf.as_mut_slice())
            .expect("Should create packet writer");

        let writer = writer
            .write_next_hop(1, &[192, 168, 0, 5])
            .expect("Could not write next hop")
            .finish_tlv()
            .expect("Could not finish next hop tlv");

        let (_err, writer) = writer
            .write_router_id(router_id())
            .expect_err("Router id should not fit");
        assert!(writer.has_tlvs(), "The next hop should have survived");

        let datagram: DatagramSend<'_> = writer
            .finish_packet()
            .expect("Could not finish packet")
            .into();

        assert_eq!(
            &datagram[..],
            &[
                42, 2, 0, 8, // Magic, Version, Body length
                7, 6, // Next Hop Type ID, Length
                1, 0, // AE, Reserved
                192, 168, 0, 5, // Next hop
            ],
            "The rejected TLV should not appear in the packet"
        );
    }

    #[test]
    fn finishing_an_empty_packet_is_an_error() {
        let buf = Vec::new();
        let writer = PacketWriter::new_packet(42, 2, buf).expect("Should create packet writer");

        assert!(!writer.has_tlvs(), "A new packet has no TLVs");
        assert_eq!(
            writer
                .finish_packet()
                .expect_err("An empty packet should not finish"),
            PacketWriterError::CannotFinishEmptyPacket,
            "Incorrect error"
        );
    }
}
