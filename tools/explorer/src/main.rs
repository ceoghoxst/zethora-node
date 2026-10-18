use kaspa_grpc_client::GrpcClient;
use prettytable::{format, Cell, Row, Table};
use kaspa_rpc_core::api::rpc::RpcApi;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Zethora node at 127.0.0.1:26610...");
    
    // Connect to the local node
    let client = match GrpcClient::connect("grpc://127.0.0.1:26610".to_string()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return Ok(());
        }
    };

    println!("Connected! Fetching latest blocks...\n");

    // Get the current DAG info
    let dag_info = client.get_block_dag_info().await?;
    println!("Network: Devnet | Virtual DAA Score: {}", dag_info.virtual_daa_score);

    // Get the last 10 blocks from the sink
    let blocks = client.get_blocks(Some(dag_info.sink), true, true).await?;

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_BOX_CHARS);
    
    table.add_row(Row::new(vec![
        Cell::new("DAA Score"),
        Cell::new("Blue Score"),
        Cell::new("Hash"),
        Cell::new("Txs"),
    ]));

    for block in blocks.block_hashes.iter().take(10) {
        // Fetch detailed block data
        if let Ok(block_data) = client.get_block(*block, true).await {
            let header = &block_data.header;
            table.add_row(Row::new(vec![
                Cell::new(&header.daa_score.to_string()),
                Cell::new(&header.blue_score.to_string()),
                Cell::new(&format!("{:.10}...", block.to_string())),
                Cell::new(&block_data.transactions.len().to_string()),
            ]));
        }
    }

    table.printstd();
    Ok(())
}
