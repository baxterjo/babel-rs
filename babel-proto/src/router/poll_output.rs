use managed::ManagedSlice;

use crate::data_structures::interface::InterfaceHandle;
use crate::extension::{address::AddressExt, parser_state::ParserStateExt};
use crate::output::Transmit;
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriter, PacketWriterError, PacketWriterStep};
use crate::utils::destination::{Claim, DestAddr};
use crate::utils::storage::ManagedSliceExt;
use crate::utils::Duration;
use crate::{error::BabelError, output::Output, utils::Instant};

use super::BabelRouter;

impl<'storage, A, P, const MN: u8, const V: u8> BabelRouter<'storage, P, A, MN, V>
where
    A: AddressExt,
    P: ParserStateExt,
{
    /// Polls output from the router.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn poll_output(&mut self, now: Instant) -> Result<Output<'_, A>, BabelError<A>> {
        let buf = Vec::new();
        self.poll_output_with_buf(now, buf)
    }

    /// Polls output for the given interface from the router.
    ///
    /// This is a useful optimization if other interfaces are busy. If the returned [`Output`] is
    /// of the `SetTimer` variant. That duration **is not** specific to the provided interface.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn poll_output_for_iface(
        &mut self,
        now: Instant,
        iface: InterfaceHandle,
    ) -> Result<Output<'_, A>, BabelError<A>> {
        let buf = Vec::new();
        self.poll_output_inner(now, Some(iface), buf)
    }

    /// Polls output for the router to transmit with a user allocated buffer.
    ///
    /// Ideally the size of this buffer is equal to the MTU of your platform to ensure network
    /// efficiency with packed packets.
    pub fn poll_output_with_buf<'output, B>(
        &mut self,
        now: Instant,
        buf: B,
    ) -> Result<Output<'output, A>, BabelError<A>>
    where
        B: Into<ManagedSlice<'output, u8>>,
    {
        self.poll_output_inner(now, None, buf)
    }

    /// Polls output for the router to transmit with a user allocated buffer.
    ///
    /// Ideally the size of this buffer is equal to the MTU of your platform to ensure network
    /// efficiency with packed packets.
    ///
    /// This is a useful optimization if other interfaces are busy. If the returned [`Output`] is
    /// of the `SetTimer` variant. That duration **is not** specific to the provided interface.
    pub fn poll_output_for_iface_with_buf<'output, B>(
        &mut self,
        now: Instant,
        iface: InterfaceHandle,
        buf: B,
    ) -> Result<Output<'output, A>, BabelError<A>>
    where
        B: Into<ManagedSlice<'output, u8>>,
    {
        self.poll_output_inner(now, Some(iface), buf)
    }

    /// Where polling for output takes place.
    ///
    /// If an active interface is given, the poll will skip all other interfaces for polling.
    fn poll_output_inner<'output, B>(
        &mut self,
        now: Instant,
        active_interface: Option<InterfaceHandle>,
        buf: B,
    ) -> Result<Output<'output, A>, BabelError<A>>
    where
        B: Into<ManagedSlice<'output, u8>>,
    {
        b_debug!(
            "{} polling for output - active_iface: {:?}",
            self.id,
            active_interface
        );
        // If active address ever becomes Some, then it is a unicast packet.
        let mut active_dest = DestAddr::default();
        let mut active_iface = active_interface;
        let writer = PacketWriter::new_packet(MN, V, buf.into())?;
        let mut next_poll = Duration::from_micros(u64::MAX);

        let body = match self.build_packet_body(
            now,
            &mut active_iface,
            &mut active_dest,
            &mut next_poll,
            writer,
        ) {
            Ok(writer) => writer,
            Err((err, writer)) => {
                b_debug!("Err building packet body: {}", err);
                writer
            }
        };

        let Some(finished_packet) = body.finish_packet()? else {
            return Ok(Output::SetTimer(next_poll));
        };

        let output = Output::Transmit(Transmit {
            iface: active_iface.expect("Somehow built a packet with no interface?"),
            destination: active_dest
                .try_into()
                .expect("Somehow built a packet with no destination?"),
            contents: finished_packet.into(),
        });

        b_debug!("{} - {:?}", self.id, output);

        Ok(output)
    }

    fn build_packet_body<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        b_trace!("Polling for IHUs");
        writer = self.poll_for_due_ihu(now, active_iface, active_dest, next_poll, writer)?;

        b_trace!("Polling for UCAST Hellos");
        writer = self.poll_for_ucast_hello(now, active_iface, active_dest, next_poll, writer)?;

        // At the very end of polling for potential TLV's check for MCAST hello.
        b_trace!("Polling for MCAST Hellos");
        writer = self.poll_for_mcast_hello(now, active_iface, active_dest, next_poll, writer)?;

        Ok(writer)
    }

    //  ___  ___  _    _      ___ _  _ _   _
    // | _ \/ _ \| |  | |    |_ _| || | | | |
    // |  _/ (_) | |__| |__   | || __ | |_| |
    // |_|  \___/|____|____| |___|_||_|\___/

    fn poll_for_due_ihu<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);

        for neighbour in self.neighbor_table.iter_mut() {
            // If this neighbour has not yet set it's IHU timer, skip it.
            //
            // This timer is set when a hello is received, neighbours that have not received hellos
            // will expire.
            let Some(ihu_timer) = &mut neighbour.pending.ihu_timer else {
                continue;
            };

            // If there is some time remaining in the timer, update local min and skip it.
            if let Some(remaining) = ihu_timer.time_remaining(now) {
                local_min = local_min.min(remaining);
                continue;
            }

            // If the active interface has been set and is not the interface for this neighbour,
            // skip it.
            if active_iface.is_some_and(|iface| neighbour.iface != iface) {
                continue;
            }

            // If the active address has been claimed and it is not destined for this neighbour
            // then skip.
            if active_dest
                .unicast_addr()
                .is_some_and(|addr| *addr != neighbour.address)
            {
                continue;
            }

            // Get the interface for this neighbour.
            let iface = self
                .iface_table
                .inner
                .get_by_key(&neighbour.iface)
                .expect("Neighbour exists on unregistered interface?");

            // If the active address is multicast and this interface wants unicast IHUs, then skip.
            if active_dest.is_multicast() && iface.config.unicast_ihu {
                continue;
            }

            // At this point
            //
            // The neighbour:
            // - Has an IHU timer that exists and has expired
            // The active interface is either:
            // - Free
            // - Matches this neighbour's interface.
            // The active address is either:
            // - Free
            // - Unicast and matches this address
            // - Multicast and this neighbour's interface does not want unicast ihus

            // TODO: Figure out error handling
            let ae: u8 = iface.config.address.encoding().try_into().unwrap();
            let rx_cost = iface.config.starting_rx_cost;
            let duration = ihu_timer.duration();
            let address = iface.config.address;
            b_debug!(
                "[SEND] IHU - iface: {}, dest_addr: {:?} - ae: {}, rx_cost: {:?}, interval: {}, addr: {:?}",
                iface.handle,
                active_dest,
                ae,
                rx_cost,
                duration.as_centis(),
                address
            );
            writer = writer
                .write_ihu(ae, rx_cost, duration.into(), address.as_wire())?
                .finish_tlv()?;

            // Claim the active address after the write succeeds.
            if iface.config.unicast_ihu {
                // Otherwise this neighbour can claim the address.
                // TODO error handling.
                active_dest
                    .claim(DestAddr::Unicast(neighbour.address))
                    .unwrap();
            } else {
                active_dest.claim(DestAddr::Multicast).unwrap()
            }
            // Claim the active interface after the write succeeds.
            active_iface.claim(iface.handle).unwrap();
            // Once the packet has been written, reset the IHU timer
            ihu_timer.restart(now);
        }

        // Choose the minimum between next poll and local min.
        *next_poll = local_min.min(*next_poll);

        Ok(writer)
    }

    //  ___  ___  _    _      _   _  ___   _   ___ _____   _  _ ___ _    _    ___
    // | _ \/ _ \| |  | |    | | | |/ __| /_\ / __|_   _| | || | __| |  | |  / _ \
    // |  _/ (_) | |__| |__  | |_| | (__ / _ \\__ \ | |   | __ | _|| |__| |_| (_) |
    // |_|  \___/|____|____|  \___/ \___/_/ \_\___/ |_|   |_||_|___|____|____\___/

    fn poll_for_ucast_hello<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_addr: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);
        for (neighbour, ucast) in self
            .neighbor_table
            .iter_mut()
            // Neighbour wants to send ucast hellos
            .filter_map(|n| n.pending.ucast_hello.map(|u| (n, u)))
        {
            // If the timer is not done, update local min and skip.
            if let Some(remaining) = ucast.timer.time_remaining(now) {
                local_min = local_min.min(remaining);
                continue;
            }
            // Skip if active interface is not this neighbour's.
            if active_iface.is_some_and(|iface| iface != neighbour.iface) {
                continue;
            }

            if active_addr.is_free()
                || active_addr
                    .unicast_addr()
                    .is_some_and(|addr| *addr == neighbour.address)
            {
                let flags = HelloFlags::new_unicast();
                let seqno = ucast.seqno;
                let duration = ucast.timer.duration();
                let dest = DestAddr::Unicast(neighbour.address);

                b_trace!(
                    "[SEND] MCAST HELLO - iface {}, dest: {} - {:?}, {:?}, interval: {}",
                    neighbour.iface,
                    dest,
                    flags,
                    seqno,
                    duration.as_centis()
                );
                writer = writer
                    .write_hello(flags, seqno, duration.into())?
                    .finish_tlv()?;
            }
        }

        *next_poll = local_min.min(*next_poll);

        Ok(writer)
    }
    //  ___  ___  _    _      __  __  ___   _   ___ _____   _  _ ___ _    _    ___
    // | _ \/ _ \| |  | |    |  \/  |/ __| /_\ / __|_   _| | || | __| |  | |  / _ \
    // |  _/ (_) | |__| |__  | |\/| | (__ / _ \\__ \ | |   | __ | _|| |__| |_| (_) |
    // |_|  \___/|____|____| |_|  |_|\___/_/ \_\___/ |_|   |_||_|___|____|____\___/

    /// Polls for multicast hellos by interface.
    fn poll_for_mcast_hello<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);
        for iface in self.iface_table.iter_mut() {
            // If the timer on the interface hello has not fired, get the minimum between it and
            // min_dur.
            if let Some(remaining) = iface.hello_timer.time_remaining(now) {
                local_min = local_min.min(remaining);
                continue;
            }

            if active_iface.is_some_and(|active| active != iface.handle) {
                // If active interface has been claimed and is not this one, skip
                continue;
            }

            // At this point in execution:
            //
            // The interface:
            // - Hello timer has expired
            // The active interface is either:
            // - Free
            // - Has been claimed and matches this one.

            // If the active destination is free or multicast write a multicast hello.
            if active_dest.is_free() || active_dest.is_multicast() {
                let flags = HelloFlags::new_multicast();
                let seqno = iface.hello_seqno;
                let duration = iface.hello_timer.duration();
                let dest: DestAddr<A> = DestAddr::Multicast;

                b_trace!(
                    "[SEND] MCAST HELLO - iface {}, dest: {} - {:?}, {:?}, interval: {}",
                    iface.handle,
                    dest,
                    flags,
                    seqno,
                    duration.as_centis()
                );

                writer = writer
                    .write_hello(flags, seqno, duration.into())?
                    .finish_tlv()?;

                // Update the active interface, this will be the same value if it was given.
                active_iface.claim(iface.handle).unwrap();
                active_dest.claim(dest).unwrap();

                // Restart hello timer
                iface.hello_timer.restart(now);
                // Increment the seqno
                iface.hello_seqno += 1;
            }
        }

        *next_poll = local_min.min(*next_poll);

        Ok(writer)
    }
}

#[cfg(test)]
mod test {}
