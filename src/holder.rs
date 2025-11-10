use std::io::stdin;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use color_eyre::{Result, eyre::eyre};
use common::{VerifyRequest, VerifyResponse};
use ed25519_dalek::{SigningKey, ed25519::signature::AsyncSigner};
use rand::{TryRngCore, rngs::OsRng};

async fn request_nonce(base_url: &str) -> Result<String> {
    println!("Requesting nonce...");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/nonce", base_url))
        .send()
        .await?
        .json::<common::NonceResponse>()
        .await?;

    println!(
        "Received nonce (expiring in {} seconds): {}",
        response.expires_in_seconds, response.nonce
    );

    Ok(response.nonce)
}

async fn verify(base_url: &str, signing_key: &SigningKey, nonce: &str) -> Result<bool> {
    println!("Verifying key...");

    let signature = signing_key.sign_async(nonce.as_bytes()).await?;
    let public_key = signing_key.verifying_key();
    let request = VerifyRequest {
        public_key: BASE64_URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
        nonce: nonce.to_string(),
        signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };

    println!("Sending payload: {:#?}", request);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/verify", base_url))
        .json(&request)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await?;
        return Err(eyre!("Server returned error {}: {}", status, error_text));
    }

    let verify_response = response.json::<VerifyResponse>().await?;

    println!("Got response: {:#?}", verify_response);

    if let Some(message) = verify_response.message {
        println!("{}", message);
    }

    match verify_response.verified {
        true => Ok(verify_response.verified),
        false => Err(eyre!("Signature verification failed")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    println!("Hello Holder");

    let url = "http://127.0.0.1:3000";
    let signing_key = SigningKey::generate(&mut OsRng.unwrap_err());
    let nonce = request_nonce(url).await?;

    loop {
        println!("Press enter to attempt verification (Ctrl+C to quit)");

        stdin().read_line(&mut String::new()).unwrap();

        match verify(url, &signing_key, &nonce).await {
            Ok(_) => println!("Successfully verified key ownership!"),
            Err(e) => eprintln!("{}", e),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_generation() -> Result<()> {
        let signing_key = SigningKey::generate(&mut OsRng.unwrap_err());
        let public_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign_async(message).await?;

        assert!(public_key.verify_strict(message, &signature).is_ok());
        Ok(())
    }
}
