pub mod p2p;
pub mod tee;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let p2p_port = std::env::var("P2P_NODE_PORT").unwrap_or_else(|_| "9011".to_string());
    let p2p_node_name = std::env::var("P2P_NODE_NAME").unwrap_or_else(|_| "node_a".to_string());
    let port = p2p_port
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse P2P port: {}", e))?;
    let mut node = p2p::node::NetworkNode::new(port, p2p_node_name).await?;
    node.run().await?;
    Ok(())
}
