use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::http::find_header_end;
use super::tls::record_payload_length;
use super::CONNECT_TIMEOUT_SECS;

#[derive(Debug)]
pub(super) enum HeaderReadError {
    TooLarge,
    Io,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum TransferError {
    #[error("transfer reached its idle timeout")]
    IdleTimeout,
    #[error("transfer I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub(super) async fn read_client_hello_record(client: &mut TcpStream) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), async {
        let mut header = [0u8; 5];
        client
            .read_exact(&mut header)
            .await
            .context("failed to read TLS record header")?;
        let payload_length = record_payload_length(&header)?;
        let mut record = Vec::with_capacity(5 + payload_length);
        record.extend_from_slice(&header);
        record.resize(5 + payload_length, 0);
        client
            .read_exact(&mut record[5..])
            .await
            .context("failed to read complete TLS ClientHello record")?;
        Ok(record)
    })
    .await
    .context("timed out reading TLS ClientHello")?
}

pub(super) async fn read_through_headers(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<usize, HeaderReadError> {
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| HeaderReadError::Io)?;
        if n == 0 {
            return Err(HeaderReadError::Io);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(position) = bounded_header_end(buf, limit)? {
            return Ok(position);
        }
    }
}

pub(super) async fn copy_with_idle_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
) -> Result<u64, TransferError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    let mut copied = 0u64;
    loop {
        let read = tokio::time::timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| TransferError::IdleTimeout)??;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        tokio::time::timeout(idle_timeout, writer.write_all(&buffer[..read]))
            .await
            .map_err(|_| TransferError::IdleTimeout)??;
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("transfer byte count overflow"))?;
    }
}

pub(super) async fn relay_with_idle_timeout<A, B>(
    left: A,
    right: B,
    idle_timeout: Duration,
) -> Result<(u64, u64), TransferError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut left_reader, mut left_writer) = tokio::io::split(left);
    let (mut right_reader, mut right_writer) = tokio::io::split(right);
    let (activity_tx, mut activity_rx) = mpsc::channel(1);

    let left_to_right =
        copy_reporting_activity(&mut left_reader, &mut right_writer, activity_tx.clone());
    let right_to_left =
        copy_reporting_activity(&mut right_reader, &mut left_writer, activity_tx.clone());
    drop(activity_tx);
    tokio::pin!(left_to_right, right_to_left);

    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut left_result = None;
    let mut right_result = None;

    loop {
        tokio::select! {
            biased;
            Some(()) = activity_rx.recv() => {
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            result = &mut left_to_right, if left_result.is_none() => {
                left_result = Some(result?);
            }
            result = &mut right_to_left, if right_result.is_none() => {
                right_result = Some(result?);
            }
            () = &mut idle => return Err(TransferError::IdleTimeout),
        }

        if let (Some(left), Some(right)) = (left_result, right_result) {
            return Ok((left, right));
        }
    }
}

async fn copy_reporting_activity<R, W>(
    reader: &mut R,
    writer: &mut W,
    activity: mpsc::Sender<()>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    let mut copied = 0u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        writer.write_all(&buffer[..read]).await?;
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("relay byte count overflow"))?;
        let _ = activity.try_send(());
    }
}

fn bounded_header_end(buf: &[u8], limit: usize) -> Result<Option<usize>, HeaderReadError> {
    if let Some(position) = find_header_end(buf) {
        return if position <= limit {
            Ok(Some(position))
        } else {
            Err(HeaderReadError::TooLarge)
        };
    }
    if buf.len() >= limit {
        return Err(HeaderReadError::TooLarge);
    }
    Ok(None)
}

pub(super) async fn write_error(
    mut stream: TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

pub(super) async fn write_error_logged(stream: TcpStream, status: u16, reason: &str, body: &str) {
    if let Err(error) = write_error(stream, status, reason, body).await {
        tracing::debug!(%error, status, "proxy error response was not delivered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn header_limit_ignores_already_buffered_body_bytes() {
        let header = b"POST http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut request = header.to_vec();
        request.extend_from_slice(&vec![b'x'; 1024]);

        assert_eq!(
            bounded_header_end(&request, header.len()).unwrap(),
            Some(header.len())
        );
        assert!(matches!(
            bounded_header_end(&[b'x'; 16], 16),
            Err(HeaderReadError::TooLarge)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn bidirectional_relay_times_out_only_after_inactivity() {
        let idle_timeout = Duration::from_secs(10);
        let (mut client, proxy_client) = tokio::io::duplex(64);
        let (proxy_upstream, mut upstream) = tokio::io::duplex(64);
        let relay = tokio::spawn(relay_with_idle_timeout(
            proxy_client,
            proxy_upstream,
            idle_timeout,
        ));
        tokio::task::yield_now().await;

        for byte in b"abc" {
            tokio::time::advance(Duration::from_secs(9)).await;
            client.write_all(&[*byte]).await.unwrap();
            let mut received = [0u8; 1];
            upstream.read_exact(&mut received).await.unwrap();
            assert_eq!(received[0], *byte);
            assert!(!relay.is_finished());
        }

        drop(client);
        drop(upstream);
        assert_eq!(relay.await.unwrap().unwrap(), (3, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn bidirectional_relay_closes_an_idle_tunnel() {
        let (_client, proxy_client) = tokio::io::duplex(64);
        let (proxy_upstream, _upstream) = tokio::io::duplex(64);
        let relay = tokio::spawn(relay_with_idle_timeout(
            proxy_client,
            proxy_upstream,
            Duration::from_secs(10),
        ));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(matches!(
            relay.await.unwrap(),
            Err(TransferError::IdleTimeout)
        ));
    }
}
