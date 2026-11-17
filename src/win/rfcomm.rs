//! Blocking `Read + Write` transport over a WinRT RFCOMM socket.
//!
//! `obex-protocol` is synchronous, so this adapter performs the WinRT async
//! stream operations on the caller's worker thread. Callers must hold a
//! [`super::ComGuard`] for the duration of the transfer.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail};
use windows::Devices::Bluetooth::Rfcomm::RfcommServiceId;
use windows::Devices::Bluetooth::{BluetoothCacheMode, BluetoothDevice, BluetoothError};
use windows::Networking::Sockets::StreamSocket;
use windows::Storage::Streams::{DataReader, DataWriter};

/// A connected RFCOMM stream implementing the blocking traits OBEX expects.
pub(crate) struct RfcommStream {
    socket: StreamSocket,
    reader: DataReader,
    writer: DataWriter,
}

impl RfcommStream {
    /// Connect to the OBEX Object Push service on `address`.
    pub(crate) fn connect(address: u64) -> Result<Self> {
        let device = BluetoothDevice::FromBluetoothAddressAsync(address)
            .context("look up the Bluetooth device")?
            .join()
            .context("device is not available (is it paired, in range and turned on?)")?;

        let service_id = RfcommServiceId::ObexObjectPush()?;
        let services = device
            .GetRfcommServicesForIdWithCacheModeAsync(&service_id, BluetoothCacheMode::Uncached)
            .context("query the OBEX Object Push service")?
            .join()
            .context("query the OBEX Object Push service")?;
        let error = services.Error()?;
        if error != BluetoothError::Success {
            bail!("the device does not offer OBEX Object Push ({error:?})");
        }
        let services = services.Services()?;
        if services.Size()? == 0 {
            bail!("the device does not expose an OBEX Object Push channel");
        }
        let service = services.GetAt(0)?;

        let socket = StreamSocket::new()?;
        let host = service.ConnectionHostName()?;
        let service_name = service.ConnectionServiceName()?;
        socket
            .ConnectAsync(&host, &service_name)
            .context("open the RFCOMM connection")?
            .join()
            .context("open the RFCOMM connection")?;

        Self::from_socket(socket)
    }

    /// Wrap an accepted RFCOMM connection.
    pub(crate) fn from_socket(socket: StreamSocket) -> Result<Self> {
        let input = socket.InputStream()?;
        let output = socket.OutputStream()?;
        let reader = DataReader::CreateDataReader(&input)?;
        let writer = DataWriter::CreateDataWriter(&output)?;
        Ok(Self {
            socket,
            reader,
            writer,
        })
    }

    pub(crate) fn socket(&self) -> &StreamSocket {
        &self.socket
    }
}

impl Read for RfcommStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let load = self.reader.LoadAsync(buf.len() as u32).map_err(io_error)?;
        load.join().map_err(io_error)?;
        let available = self.reader.UnconsumedBufferLength().map_err(io_error)? as usize;
        if available == 0 {
            return Ok(0);
        }
        let count = available.min(buf.len());
        self.reader.ReadBytes(&mut buf[..count]).map_err(io_error)?;
        Ok(count)
    }
}

impl Write for RfcommStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // DataWriter buffers in memory; store in bounded chunks so a 64 KiB
        // OBEX packet cannot exceed the internal buffer.
        for chunk in buf.chunks(32 * 1024) {
            self.writer.WriteBytes(chunk).map_err(io_error)?;
            self.writer
                .StoreAsync()
                .map_err(io_error)?
                .join()
                .map_err(io_error)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let flushed = self
            .writer
            .FlushAsync()
            .map_err(io_error)?
            .join()
            .map_err(io_error)?;
        if flushed {
            Ok(())
        } else {
            Err(io::Error::other("RFCOMM flush failed"))
        }
    }
}

impl Drop for RfcommStream {
    fn drop(&mut self) {
        let _ = self.socket.Close();
    }
}

fn io_error(error: windows::core::Error) -> io::Error {
    io::Error::other(error)
}
