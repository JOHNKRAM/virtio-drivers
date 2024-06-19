use super::{
    Config, EthernetAddress, Features, VirtioNetCtrlClass, VirtioNetCtrlCmd, VirtioNetCtrlHdr,
    VirtioNetCtrlMQPairsSet, VirtioNetCtrlResult, VirtioNetHdr,
};
use super::{MIN_BUFFER_LEN, NET_HDR_SIZE, QUEUE_RECEIVE, QUEUE_TRANSMIT, SUPPORTED_FEATURES};
use crate::hal::Hal;
use crate::queue::VirtQueue;
use crate::transport::Transport;
use crate::volatile::volread;
use crate::{Error, Result};
use alloc::vec::Vec;
use log::{debug, info, warn};
use zerocopy::AsBytes;

/// Raw driver for a VirtIO block device.
///
/// This is a raw version of the VirtIONet driver. It provides non-blocking
/// methods for transmitting and receiving raw slices, without the buffer
/// management. For more higher-level fucntions such as receive buffer backing,
/// see [`VirtIONet`].
///
/// [`VirtIONet`]: super::VirtIONet
pub struct VirtIONetRaw<H: Hal, T: Transport, const QUEUE_SIZE: usize> {
    transport: T,
    mac: EthernetAddress,
    recv_queues: Vec<VirtQueue<H, QUEUE_SIZE>>,
    send_queues: Vec<VirtQueue<H, QUEUE_SIZE>>,
    ctrl_queue: Option<VirtQueue<H, QUEUE_SIZE>>,
}

impl<H: Hal, T: Transport, const QUEUE_SIZE: usize> VirtIONetRaw<H, T, QUEUE_SIZE> {
    /// Create a new VirtIO-Net driver.
    pub fn new(mut transport: T) -> Result<Self> {
        let negotiated_features = transport.begin_init(SUPPORTED_FEATURES);
        info!("negotiated_features {:?}", negotiated_features);
        // read configuration space
        let config = transport.config_space::<Config>()?;
        let mac;
        let max_virtqueue_pairs;
        // Safe because config points to a valid MMIO region for the config space.
        unsafe {
            mac = volread!(config, mac);
            max_virtqueue_pairs = if negotiated_features.intersects(Features::MQ) {
                volread!(config, max_virtqueue_pairs)
            } else {
                1
            };
            debug!(
                "Got MAC={:02x?}, status={:?}",
                mac,
                volread!(config, status)
            );
        }
        let mut send_queues = Vec::new();
        let mut recv_queues = Vec::new();
        for id in 0..max_virtqueue_pairs {
            let send_queue = VirtQueue::new(
                &mut transport,
                Self::send_queue_idx(id),
                false,
                negotiated_features.contains(Features::RING_EVENT_IDX),
            )?;
            let recv_queue = VirtQueue::new(
                &mut transport,
                Self::recv_queue_idx(id),
                false,
                negotiated_features.contains(Features::RING_EVENT_IDX),
            )?;
            send_queues.push(send_queue);
            recv_queues.push(recv_queue);
        }

        let ctrl_queue = if negotiated_features.contains(Features::CTRL_VQ) {
            Some(VirtQueue::new(
                &mut transport,
                max_virtqueue_pairs << 1,
                false,
                negotiated_features.contains(Features::RING_EVENT_IDX),
            )?)
        } else {
            None
        };

        transport.finish_init();

        Ok(VirtIONetRaw {
            transport,
            mac,
            recv_queues,
            send_queues,
            ctrl_queue,
        })
    }

    /// Acknowledge interrupt.
    pub fn ack_interrupt(&mut self) -> bool {
        self.transport.ack_interrupt()
    }

    /// Disable interrupts.
    pub fn disable_interrupts(&mut self, id: usize) {
        self.send_queues[id].set_dev_notify(false);
        self.recv_queues[id].set_dev_notify(false);
    }

    /// Enable interrupts.
    pub fn enable_interrupts(&mut self, id: usize) {
        self.send_queues[id].set_dev_notify(true);
        self.recv_queues[id].set_dev_notify(true);
    }

    /// Get MAC address.
    pub fn mac_address(&self) -> EthernetAddress {
        self.mac
    }

    /// Whether can send packet.
    pub fn can_send(&self, id: usize) -> bool {
        self.send_queues[id].available_desc() >= 2
    }

    /// Whether the length of the receive buffer is valid.
    fn check_rx_buf_len(rx_buf: &[u8]) -> Result<()> {
        if rx_buf.len() < MIN_BUFFER_LEN {
            warn!("Receive buffer len {} is too small", rx_buf.len());
            Err(Error::InvalidParam)
        } else {
            Ok(())
        }
    }

    /// Whether the length of the transmit buffer is valid.
    fn check_tx_buf_len(tx_buf: &[u8]) -> Result<()> {
        if tx_buf.len() < NET_HDR_SIZE {
            warn!("Transmit buffer len {} is too small", tx_buf.len());
            Err(Error::InvalidParam)
        } else {
            Ok(())
        }
    }

    /// Fill the header of the `buffer` with [`VirtioNetHdr`].
    ///
    /// If the `buffer` is not large enough, it returns [`Error::InvalidParam`].
    pub fn fill_buffer_header(&self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.len() < NET_HDR_SIZE {
            return Err(Error::InvalidParam);
        }
        let header = VirtioNetHdr::default();
        buffer[..NET_HDR_SIZE].copy_from_slice(header.as_bytes());
        Ok(NET_HDR_SIZE)
    }

    /// Submits a request to transmit a buffer immediately without waiting for
    /// the transmission to complete.
    ///
    /// It will submit request to the VirtIO net device and return a token
    /// identifying the position of the first descriptor in the chain. If there
    /// are not enough descriptors to allocate, then it returns
    /// [`Error::QueueFull`].
    ///
    /// The caller needs to fill the `tx_buf` with a header by calling
    /// [`fill_buffer_header`] before transmission. Then it calls [`poll_transmit`]
    /// with the returned token to check whether the device has finished handling
    /// the request. Once it has, the caller must call [`transmit_complete`] with
    /// the same buffer before reading the result (transmitted length).
    ///
    /// # Safety
    ///
    /// `tx_buf` is still borrowed by the underlying VirtIO net device even after
    /// this method returns. Thus, it is the caller's responsibility to guarantee
    /// that they are not accessed before the request is completed in order to
    /// avoid data races.
    ///
    /// [`fill_buffer_header`]: Self::fill_buffer_header
    /// [`poll_transmit`]: Self::poll_transmit
    /// [`transmit_complete`]: Self::transmit_complete
    pub unsafe fn transmit_begin(&mut self, id: usize, tx_buf: &[u8]) -> Result<u16> {
        Self::check_tx_buf_len(tx_buf)?;
        let token = self.send_queues[id].add(&[tx_buf], &mut [])?;
        if self.send_queues[id].should_notify() {
            self.transport.notify(QUEUE_TRANSMIT);
        }
        Ok(token)
    }

    /// Fetches the token of the next completed transmission request from the
    /// used ring and returns it, without removing it from the used ring. If
    /// there are no pending completed requests it returns [`None`].
    pub fn poll_transmit(&mut self, id: usize) -> Option<u16> {
        self.send_queues[id].peek_used()
    }

    /// Completes a transmission operation which was started by [`transmit_begin`].
    /// Returns number of bytes transmitted.
    ///
    /// # Safety
    ///
    /// The same buffer must be passed in again as was passed to
    /// [`transmit_begin`] when it returned the token.
    ///
    /// [`transmit_begin`]: Self::transmit_begin
    pub unsafe fn transmit_complete(
        &mut self,
        id: usize,
        token: u16,
        tx_buf: &[u8],
    ) -> Result<usize> {
        let len = self.send_queues[id].pop_used(token, &[tx_buf], &mut [])?;
        Ok(len as usize)
    }

    /// Submits a request to receive a buffer immediately without waiting for
    /// the reception to complete.
    ///
    /// It will submit request to the VirtIO net device and return a token
    /// identifying the position of the first descriptor in the chain. If there
    /// are not enough descriptors to allocate, then it returns
    /// [`Error::QueueFull`].
    ///
    /// The caller can then call [`poll_receive`] with the returned token to
    /// check whether the device has finished handling the request. Once it has,
    /// the caller must call [`receive_complete`] with the same buffer before
    /// reading the response.
    ///
    /// # Safety
    ///
    /// `rx_buf` is still borrowed by the underlying VirtIO net device even after
    /// this method returns. Thus, it is the caller's responsibility to guarantee
    /// that they are not accessed before the request is completed in order to
    /// avoid data races.
    ///
    /// [`poll_receive`]: Self::poll_receive
    /// [`receive_complete`]: Self::receive_complete
    pub unsafe fn receive_begin(&mut self, id: usize, rx_buf: &mut [u8]) -> Result<u16> {
        Self::check_rx_buf_len(rx_buf)?;
        let token = self.recv_queues[id].add(&[], &mut [rx_buf])?;
        if self.recv_queues[id].should_notify() {
            self.transport.notify(QUEUE_RECEIVE);
        }
        Ok(token)
    }

    /// Fetches the token of the next completed reception request from the
    /// used ring and returns it, without removing it from the used ring. If
    /// there are no pending completed requests it returns [`None`].
    pub fn poll_receive(&self, id: usize) -> Option<u16> {
        self.recv_queues[id].peek_used()
    }

    /// Completes a transmission operation which was started by [`receive_begin`].
    ///
    /// After completion, the `rx_buf` will contain a header followed by the
    /// received packet. It returns the length of the header and the length of
    /// the packet.
    ///
    /// # Safety
    ///
    /// The same buffer must be passed in again as was passed to
    /// [`receive_begin`] when it returned the token.
    ///
    /// [`receive_begin`]: Self::receive_begin
    pub unsafe fn receive_complete(
        &mut self,
        id: usize,
        token: u16,
        rx_buf: &mut [u8],
    ) -> Result<(usize, usize)> {
        let len = self.recv_queues[id].pop_used(token, &[], &mut [rx_buf])? as usize;
        let packet_len = len.checked_sub(NET_HDR_SIZE).ok_or(Error::IoError)?;
        Ok((NET_HDR_SIZE, packet_len))
    }

    /// Sends a packet to the network, and blocks until the request completed.
    pub fn send(&mut self, id: usize, tx_buf: &[u8]) -> Result {
        let header = VirtioNetHdr::default();
        if tx_buf.is_empty() {
            // Special case sending an empty packet, to avoid adding an empty buffer to the
            // virtqueue.
            self.send_queues[id].add_notify_wait_pop(
                &[header.as_bytes()],
                &mut [],
                &mut self.transport,
            )?;
        } else {
            self.send_queues[id].add_notify_wait_pop(
                &[header.as_bytes(), tx_buf],
                &mut [],
                &mut self.transport,
            )?;
        }
        Ok(())
    }

    /// Blocks and waits for a packet to be received.
    ///
    /// After completion, the `rx_buf` will contain a header followed by the
    /// received packet. It returns the length of the header and the length of
    /// the packet.
    pub fn receive_wait(&mut self, id: usize, rx_buf: &mut [u8]) -> Result<(usize, usize)> {
        let token = unsafe { self.receive_begin(id, rx_buf)? };
        while self.poll_receive(id).is_none() {
            core::hint::spin_loop();
        }
        unsafe { self.receive_complete(id, token, rx_buf) }
    }

    /// Get the number of send/recv queue pairs.
    pub fn queue_count(&self) -> usize {
        self.send_queues.len()
    }

    fn recv_queue_idx(id: u16) -> u16 {
        id << 1 | QUEUE_RECEIVE
    }

    fn send_queue_idx(id: u16) -> u16 {
        id << 1 | QUEUE_TRANSMIT
    }

    fn send_cmd(
        &mut self,
        class: VirtioNetCtrlClass,
        cmd: VirtioNetCtrlCmd,
        data: Option<&[u8]>,
    ) -> Result<bool> {
        let transport = &mut self.transport;
        self.ctrl_queue
            .as_mut()
            .map_or(Err(Error::Unsupported), |ctrl_queue| {
                let ctrl_hdr = VirtioNetCtrlHdr { class, cmd };
                let mut status: VirtioNetCtrlResult = Default::default();
                ctrl_queue.add_notify_wait_pop(
                    data.map(|data| [ctrl_hdr.as_bytes(), data])
                        .as_ref()
                        .map(|inputs| inputs as &[&[u8]])
                        .unwrap_or(&[ctrl_hdr.as_bytes()] as &[&[u8]]),
                    &mut [status.as_bytes_mut()],
                    transport,
                )?;
                Ok(status == VirtioNetCtrlResult::OK)
            })
    }

    /// Set the number of using send/recv queue pairs.
    pub fn set_queues(&mut self, queue_num: usize) -> Result<bool> {
        let queue_num = VirtioNetCtrlMQPairsSet(queue_num as u16);
        if queue_num >= VirtioNetCtrlMQPairsSet::MIN && queue_num <= VirtioNetCtrlMQPairsSet::MAX {
            self.send_cmd(
                VirtioNetCtrlClass::MQ,
                VirtioNetCtrlCmd::MQ_VQ_PAIRS_SET,
                Some(VirtioNetCtrlMQPairsSet(queue_num.0.to_le()).as_bytes()),
            )
        } else {
            Err(Error::InvalidParam)
        }
    }
}

impl<H: Hal, T: Transport, const QUEUE_SIZE: usize> Drop for VirtIONetRaw<H, T, QUEUE_SIZE> {
    fn drop(&mut self) {
        // Clear any pointers pointing to DMA regions, so the device doesn't try to access them
        // after they have been freed.
        let max_queue_pairs = self.queue_count() as u16;
        for id in 0..max_queue_pairs {
            self.transport.queue_unset(Self::recv_queue_idx(id));
            self.transport.queue_unset(Self::send_queue_idx(id));
        }
        if self.ctrl_queue.is_some() {
            self.transport.queue_unset(max_queue_pairs << 1);
        }
    }
}
