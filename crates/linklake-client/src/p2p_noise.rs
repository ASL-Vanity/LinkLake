//! P2P 直连的 Noise 握手和加密字节流封装。

use anyhow::Context;
use snow::{params::NoiseParams, Builder, TransportState};
use std::{str::FromStr, sync::Arc};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const NOISE_PROLOGUE: &[u8] = b"LinkLake-P2P-v1";
const MAX_HANDSHAKE_MESSAGE: usize = 512;
const MAX_TRANSPORT_MESSAGE: usize = 65_535;
const TRANSPORT_TAG_BYTES: usize = 16;
const PLAINTEXT_CHUNK_BYTES: usize = 32 * 1024;
const REKEY_MESSAGE_INTERVAL: u64 = 1 << 20;

pub(crate) async fn initiate(
    stream: &mut TcpStream,
    psk: &[u8; 32],
) -> anyhow::Result<TransportState> {
    let mut handshake = noise_builder(psk)?.build_initiator()?;
    let mut message = [0_u8; MAX_HANDSHAKE_MESSAGE];
    let written = handshake.write_message(&[], &mut message)?;
    write_frame(stream, &message[..written]).await?;
    let response = read_frame(stream, MAX_HANDSHAKE_MESSAGE).await?;
    handshake.read_message(&response, &mut message)?;
    anyhow::ensure!(
        handshake.is_handshake_finished(),
        "Noise handshake did not finish"
    );
    handshake.into_transport_mode().map_err(Into::into)
}

pub(crate) async fn respond(
    stream: &mut TcpStream,
    psk: &[u8; 32],
) -> anyhow::Result<TransportState> {
    let mut handshake = noise_builder(psk)?.build_responder()?;
    let request = read_frame(stream, MAX_HANDSHAKE_MESSAGE).await?;
    let mut message = [0_u8; MAX_HANDSHAKE_MESSAGE];
    handshake.read_message(&request, &mut message)?;
    let written = handshake.write_message(&[], &mut message)?;
    write_frame(stream, &message[..written]).await?;
    anyhow::ensure!(
        handshake.is_handshake_finished(),
        "Noise handshake did not finish"
    );
    handshake.into_transport_mode().map_err(Into::into)
}

pub(crate) async fn relay_encrypted(
    local: &mut TcpStream,
    direct: &mut TcpStream,
    transport: TransportState,
) -> anyhow::Result<()> {
    let transport = Arc::new(Mutex::new(transport));
    let (local_reader, local_writer) = split(local);
    let (direct_reader, direct_writer) = split(direct);
    let outgoing = encrypt_direction(local_reader, direct_writer, transport.clone());
    let incoming = decrypt_direction(direct_reader, local_writer, transport);
    tokio::try_join!(outgoing, incoming)?;
    Ok(())
}

fn noise_builder(psk: &[u8; 32]) -> anyhow::Result<Builder<'_>> {
    let parameters = NoiseParams::from_str(NOISE_PATTERN).context("invalid Noise parameters")?;
    Builder::new(parameters)
        .prologue(NOISE_PROLOGUE)?
        .psk(0, psk)
        .map_err(Into::into)
}

async fn encrypt_direction<R, W>(
    mut plaintext: R,
    mut encrypted: W,
    transport: Arc<Mutex<TransportState>>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut input = vec![0_u8; PLAINTEXT_CHUNK_BYTES];
    let mut output = vec![0_u8; PLAINTEXT_CHUNK_BYTES + TRANSPORT_TAG_BYTES];
    let mut messages = 0_u64;
    loop {
        let read = plaintext.read(&mut input).await?;
        if read == 0 {
            encrypted.shutdown().await?;
            return Ok(());
        }
        let written = {
            let mut state = transport.lock().await;
            let written = state.write_message(&input[..read], &mut output)?;
            messages = messages.saturating_add(1);
            if messages % REKEY_MESSAGE_INTERVAL == 0 {
                state.rekey_outgoing();
            }
            written
        };
        write_frame(&mut encrypted, &output[..written]).await?;
    }
}

async fn decrypt_direction<R, W>(
    mut encrypted: R,
    mut plaintext: W,
    transport: Arc<Mutex<TransportState>>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut output = vec![0_u8; MAX_TRANSPORT_MESSAGE];
    let mut messages = 0_u64;
    loop {
        let frame = match read_frame_or_eof(&mut encrypted, MAX_TRANSPORT_MESSAGE).await? {
            Some(frame) => frame,
            None => {
                plaintext.shutdown().await?;
                return Ok(());
            }
        };
        anyhow::ensure!(
            frame.len() >= TRANSPORT_TAG_BYTES,
            "encrypted P2P frame is too short"
        );
        let read = {
            let mut state = transport.lock().await;
            let read = state.read_message(&frame, &mut output)?;
            messages = messages.saturating_add(1);
            if messages % REKEY_MESSAGE_INTERVAL == 0 {
                state.rekey_incoming();
            }
            read
        };
        plaintext.write_all(&output[..read]).await?;
    }
}

async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    anyhow::ensure!(
        !payload.is_empty() && payload.len() <= MAX_TRANSPORT_MESSAGE,
        "invalid Noise frame length"
    );
    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R, maximum: usize) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    read_frame_or_eof(reader, maximum)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Noise stream closed before a frame arrived"))
}

async fn read_frame_or_eof<R>(reader: &mut R, maximum: usize) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    let mut offset = 0;
    while offset < length.len() {
        let read = reader.read(&mut length[offset..]).await?;
        if read == 0 {
            anyhow::ensure!(offset == 0, "truncated Noise frame length");
            return Ok(None);
        }
        offset += read;
    }
    let length = usize::from(u16::from_be_bytes(length));
    anyhow::ensure!(
        length != 0 && length <= maximum,
        "invalid Noise frame length"
    );
    let mut frame = vec![0_u8; length];
    reader.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        net::TcpListener,
        time::{timeout, Duration},
    };

    #[tokio::test]
    async fn noise_psk_handshake_encrypts_bidirectional_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("address should exist");
        let psk = [7_u8; 32];
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("connection should arrive");
            let mut transport = respond(&mut stream, &psk)
                .await
                .expect("responder should handshake");
            let request = read_frame(&mut stream, MAX_TRANSPORT_MESSAGE)
                .await
                .expect("frame should read");
            let mut plaintext = vec![0_u8; request.len()];
            let read = transport
                .read_message(&request, &mut plaintext)
                .expect("request should decrypt");
            assert_eq!(&plaintext[..read], b"encrypted-p2p");
            let mut encrypted = vec![0_u8; 64];
            let written = transport
                .write_message(b"response", &mut encrypted)
                .expect("response should encrypt");
            write_frame(&mut stream, &encrypted[..written])
                .await
                .expect("response should write");
        });
        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        let mut transport = initiate(&mut client, &psk)
            .await
            .expect("initiator should handshake");
        let mut encrypted = vec![0_u8; 64];
        let written = transport
            .write_message(b"encrypted-p2p", &mut encrypted)
            .expect("request should encrypt");
        write_frame(&mut client, &encrypted[..written])
            .await
            .expect("request should write");
        let response = read_frame(&mut client, MAX_TRANSPORT_MESSAGE)
            .await
            .expect("response should read");
        let mut plaintext = vec![0_u8; 64];
        let read = transport
            .read_message(&response, &mut plaintext)
            .expect("response should decrypt");
        assert_eq!(&plaintext[..read], b"response");
        server.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn wrong_psk_cannot_complete_the_noise_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("address should exist");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("connection should arrive");
            respond(&mut stream, &[1_u8; 32]).await
        });
        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        let result = timeout(Duration::from_secs(2), initiate(&mut client, &[2_u8; 32])).await;
        assert!(result.is_err() || result.expect("timeout result should exist").is_err());
        assert!(server.await.expect("server task should finish").is_err());
    }
}
