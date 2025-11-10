use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use color_eyre::Result;
use common::{ErrorResponse, NonceResponse, VerifyRequest, VerifyResponse};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::StatusCode;
use tokio::sync::Mutex;

// NonceStore handles generation and storage of nonces
#[derive(Clone)]
struct NonceStore {
    nonces: Arc<Mutex<HashMap<String, u64>>>,
    ttl: u64,
}

impl NonceStore {
    fn new(ttl: u64) -> Self {
        Self {
            nonces: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    async fn generate(&self) -> String {
        let timestamp = now();
        let random: u64 = rand::random::<u64>();

        let nonce = format!("{}-{}", timestamp, random);
        self.nonces.lock().await.insert(nonce.clone(), timestamp);
        nonce
    }

    async fn consume(&self, nonce: &str) -> bool {
        let mut store = self.nonces.lock().await;

        if let Some(timestamp) = store.remove(nonce) {
            now() - timestamp < self.ttl
        } else {
            false
        }
    }

    async fn cleanup(&self) {
        let mut store = self.nonces.lock().await;
        store.retain(|_, &mut timestamp| now() - timestamp < self.ttl);
    }
}

// now is a helper function to generate u64s representing seconds
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

// get_nonce handles GET `/nonce`
async fn get_nonce(State(store): State<NonceStore>) -> Json<NonceResponse> {
    Json(NonceResponse {
        nonce: store.generate().await,
        expires_in_seconds: store.ttl,
    })
}

// verify handles POST `/verify`
async fn verify(
    State(store): State<NonceStore>,
    Json(request): Json<VerifyRequest>,
) -> std::result::Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    println!("Got request: {:#?}", request);

    println!("Checking nonce...");
    if !store.consume(&request.nonce).await {
        return Err(unauthorized("Invalid or expired nonce".to_string()));
    }
    println!("Nonce is valid");

    println!("Decoding...");
    let signature_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(&request.signature)
        .map_err(|e| bad_request(format!("Could not get signature bytes: {}", e)))?;

    let decoded_signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| bad_request(format!("Could not decode signature: {}", e)))?;

    let public_key_array: [u8; 32] = BASE64_URL_SAFE_NO_PAD
        .decode(request.public_key)
        .map_err(|e| bad_request(format!("Could not decode public key: {}", e)))?
        .as_slice()
        .try_into()
        .map_err(|_| bad_request("Public key is incorrect size".to_string()))?;

    let decoded_public_key: VerifyingKey = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|e| bad_request(format!("Invalid public key: {}", e)))?;

    println!("Verifying...");
    match decoded_public_key.verify_strict(request.nonce.as_bytes(), &decoded_signature) {
        Ok(_) => {
            let response = VerifyResponse {
                verified: true,
                message: Some("Key ownership verified successfully".to_string()),
            };
            println!("Sending response: {:#?}", response);
            Ok(Json(response))
        }
        Err(e) => Err(unauthorized(format!(
            "Signature verification failed: {}",
            e
        ))),
    }
}

// Helper functions for returning errors

fn error_response(status_code: StatusCode, error: String) -> (StatusCode, Json<ErrorResponse>) {
    println!("Sending error: {}", error);
    (status_code, Json(ErrorResponse { error }))
}

fn bad_request(error: String) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::BAD_REQUEST, error)
}

fn unauthorized(error: String) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::UNAUTHORIZED, error)
}

// Very simply sets up a server with axum
#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    println!("Hello Verifier");

    let nonce_timeout_secs = 5;
    let store = NonceStore::new(nonce_timeout_secs);

    let cleanup_store = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_store.cleanup().await;
        }
    });

    let app = Router::new()
        .route("/nonce", get(get_nonce))
        .route("/verify", post(verify))
        .with_state(store);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    println!("Verifier service listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{SigningKey, ed25519::signature::AsyncSigner};
    use rand::{TryRngCore, rngs::OsRng};
    use tokio::sync::oneshot;

    use super::*;

    async fn setup_test_app(port: &str) -> Result<oneshot::Sender<()>> {
        let nonce_timeout_secs = 5;
        let store = NonceStore::new(nonce_timeout_secs);

        let cleanup_store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_store.cleanup().await;
            }
        });

        let app = Router::new()
            .route("/nonce", get(get_nonce))
            .route("/verify", post(verify))
            .with_state(store);

        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        let (tx, rx): (oneshot::Sender<()>, oneshot::Receiver<()>) = oneshot::channel();

        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = rx.await;
        });

        tokio::spawn(async {
            let _ = server.await;
        });

        Ok(tx)
    }

    #[tokio::test]
    async fn test_nonce_generation() -> Result<()> {
        let tx = setup_test_app("3001").await?;
        let client = reqwest::Client::new();
        let response = client
            .get("http://127.0.0.1:3001/nonce")
            .send()
            .await?
            .json::<NonceResponse>()
            .await?;

        assert!(!response.nonce.is_empty());

        let _ = tx.send(());

        Ok(())
    }

    #[tokio::test]
    async fn test_verify() -> Result<()> {
        let tx = setup_test_app("3002").await?;

        let client = reqwest::Client::new();
        let response = client
            .get("http://127.0.0.1:3002/nonce")
            .send()
            .await?
            .json::<NonceResponse>()
            .await?;
        let nonce = response.nonce;

        let signing_key = SigningKey::generate(&mut OsRng.unwrap_err());
        let signature = signing_key.sign_async(nonce.as_bytes()).await?;
        let public_key = signing_key.verifying_key();
        let request = VerifyRequest {
            public_key: BASE64_URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
            nonce: nonce.to_string(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };

        let response = client
            .post("http://127.0.0.1:3002/verify")
            .json(&request)
            .send()
            .await?;

        assert!(response.status().is_success());

        let verify_response = response.json::<VerifyResponse>().await?;

        assert!(verify_response.verified);

        let _ = tx.send(());
        Ok(())
    }
}
