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
    use crate::data_types::seqno::SeqNo;
    use crate::metric::RxCost;
    use crate::output::DatagramSend;
    use crate::packet::packet_slice::PacketSlice;
    use crate::packet::tlv::Tlv;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::utils::Duration;
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
}
