//! QUIC hello world: a server and a client in one process, talking over 127.0.0.1.

use std::{error::Error, sync::Arc};

use quinn::{
    ClientConfig, Endpoint, ServerConfig,
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    rustls::{self, RootCertStore, pki_types::PrivatePkcs8KeyDer},
};

type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Application protocol both sides must agree on during the TLS handshake (RFC 9001 §8.1).
const ALPN: &[u8] = b"hello-quic";

/// Runs one full QUIC exchange and returns the reply the client received.
async fn hello_exchange() -> Res<String> {
    // QUIC always runs over TLS 1.3, so the server needs a certificate. We make one in memory.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // --- Server ---
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key.into())?;
    server_tls.alpn_protocols = vec![ALPN.to_vec()];
    let server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?));
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let server_addr = server.local_addr()?;
    println!("[server] listening on {server_addr} (UDP)");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.ok_or("server endpoint closed")?.await?;
        println!("[server] accepted connection from {}", conn.remote_address());
        let (mut send, mut recv) = conn.accept_bi().await?;
        let msg = recv.read_to_end(64).await?;
        println!("[server] received: {:?}", String::from_utf8_lossy(&msg));
        send.write_all(b"Hello, world!").await?;
        send.finish()?;
        // Keep the connection up until the client has read the reply and closes it.
        conn.closed().await;
        Res::Ok(())
    });

    // --- Client --- trusts exactly the server's certificate, nothing else.
    let mut roots = RootCertStore::empty();
    roots.add(cert_der)?;
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut client = Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?)));

    let conn = client.connect(server_addr, "localhost")?.await?;
    let alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .map(|p| String::from_utf8_lossy(&p).into_owned());
    println!("[client] handshake complete: ALPN={alpn:?}, RTT={:?}", conn.rtt());

    let (mut send, mut recv) = conn.open_bi().await?;
    println!("[client] sending \"Hello\" on {}", send.id());
    send.write_all(b"Hello").await?;
    send.finish()?;
    let reply = String::from_utf8(recv.read_to_end(64).await?)?;
    println!("[client] received: {reply:?}");

    conn.close(0u32.into(), b"done");
    server_task.await??;
    client.wait_idle().await;
    println!("[client] connection closed");
    Ok(reply)
}

#[tokio::main]
async fn main() -> Res<()> {
    hello_exchange().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn server_replies_hello_world() {
        assert_eq!(super::hello_exchange().await.unwrap(), "Hello, world!");
    }
}
