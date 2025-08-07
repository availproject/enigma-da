pub mod p2p;
pub mod tee;

#[cfg(test)]
mod tests;

pub struct NodeConfig {
    pub port: u16,
    pub node_name: String,
}

pub async fn run(config: NodeConfig) -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut node = p2p::node::NetworkNode::new(config.port, config.node_name).await?;
    node.run().await?;
    println!("P2P node completed");
    Ok(())
}
