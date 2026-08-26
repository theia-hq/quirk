use quirk::Endpoint;

/// A persisted secret yields a stable public key: two binds of the same 32 bytes present the same
/// ed25519 verifying key, so a node keeps one identity across runs (and across transports, since iroh
/// derives the same key from the same secret). A fresh bind differs, confirming the key is the secret's
/// and not a constant.
#[tokio::test]
async fn bind_with_secret_is_deterministic() {
    let secret = [7u8; 32];

    let first = Endpoint::bind_with_secret(secret).await.unwrap();
    let second = Endpoint::bind_with_secret(secret).await.unwrap();
    assert_eq!(
        first.public_key().to_bytes(),
        second.public_key().to_bytes(),
        "the same secret yields the same identity"
    );

    let fresh = Endpoint::bind().await.unwrap();
    assert_ne!(
        first.public_key().to_bytes(),
        fresh.public_key().to_bytes(),
        "a fresh bind is a different identity"
    );
}

/// The verifying key quirk derives from a secret matches the one `ed25519-dalek` derives directly from
/// the same secret. This is the cross-transport invariant in miniature: iroh binds the identical
/// ed25519 key from the identical bytes, so the resulting `NodeId` is the same over both transports.
#[tokio::test]
async fn public_key_is_the_ed25519_key_of_the_secret() {
    let secret = [42u8; 32];
    let expected = ed25519_dalek::SigningKey::from_bytes(&secret)
        .verifying_key()
        .to_bytes();

    let endpoint = Endpoint::bind_with_secret(secret).await.unwrap();
    assert_eq!(endpoint.public_key().to_bytes(), expected);
}
