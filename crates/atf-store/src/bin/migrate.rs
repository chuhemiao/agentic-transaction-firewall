use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL is required for atf-store-migrate")?;
    let schema = atf_store::migrate(&database_url).await?;
    println!(
        "ATF durable-state schema {} is ready (minimum reader {}, minimum writer {})",
        schema.schema_version, schema.minimum_reader_version, schema.minimum_writer_version
    );
    Ok(())
}
