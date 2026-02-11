use super::*;
use coset::{
    iana::{Algorithm, EllipticCurve},
    CoseKeyBuilder,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use passkey_authenticator::public_key_der_from_cose_key;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[test]
fn test_verify_webauthn_response_with_generated_data() {
    let authenticator_data = b"example authenticator data";
    let client_data_json = br#"{
        "challenge": "test-challenge",
        "origin": "https://example.com",
        "type": "webauthn.get"
    }"#;

    // Step 1: Generate a private key using the P-256 curve
    let private_key = SigningKey::random(&mut OsRng);
    let public_key = private_key.verifying_key().to_encoded_point(false); // Uncompressed point

    // Step 2: Extract the affine coordinates (x, y)
    // SAFETY: These unwraps are safe because the public_key above is not compressed (false
    // parameter) therefore x and y are guaranteed to contain values.
    let x = public_key.x().unwrap().to_vec();
    let y = public_key.y().unwrap().to_vec();

    // Step 3: Construct the COSE key pair
    let public_key_cose = CoseKeyBuilder::new_ec2_pub_key(EllipticCurve::P_256, x, y)
        .algorithm(Algorithm::ES256)
        .build();

    // Step 4: Convert to DER from COSE
    // TODO: Is this conversion from COSE really necessary? Or is it possible to build the DER key from
    // scratch using another library?
    let public_key_der = public_key_der_from_cose_key(&public_key_cose)
        .map_err(|_| VerifyError::ExtractPublicKey)
        .expect("Conversion from COSE to DER failed");

    // Step 5: Compute client_data_hash and message
    let client_data_hash = Sha256::digest(client_data_json);
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&client_data_hash);

    // Step 6: Sign the message to get the signature in DER format
    // ? Should this be in COSE format? I couldn't get coset::CoseSign1 to work
    // ? https://github.com/google/coset/blob/main/examples/signature.rs
    // ? Check the above link for an example of how to sign a message in COSE format
    let signature: Signature = private_key.sign(&message);
    let signature_der = signature.to_der();

    // Step 7: Verify the signature
    webauthn_verify(
        authenticator_data,
        client_data_json,
        signature_der.as_bytes(),
        public_key_der.as_slice(),
    )
    .expect("Verifying signature failed");
}

#[test]
fn test_verify_webauthn_response_with_invalid_signature() {
    let authenticator_data = b"example authenticator data";
    let client_data_json = br#"{
        "challenge": "test-challenge",
        "origin": "https://example.com",
        "type": "webauthn.get"
    }"#;

    // Step 1: Generate a private key using the P-256 curve
    let private_key = SigningKey::random(&mut OsRng);
    let public_key = private_key.verifying_key().to_encoded_point(false); // Uncompressed point

    // Step 2: Extract the affine coordinates (x, y)
    let x = public_key.x().unwrap().to_vec();
    let y = public_key.y().unwrap().to_vec();

    // Step 3: Construct the COSE key pair
    let public_key_cose = CoseKeyBuilder::new_ec2_pub_key(EllipticCurve::P_256, x, y)
        .algorithm(Algorithm::ES256)
        .build();

    // Step 4: Convert to DER from COSE
    // TODO: Is this conversion from COSE really necessary? Or is it possible to build the DER key from
    // scratch using another library?
    let public_key_der = public_key_der_from_cose_key(&public_key_cose)
        .map_err(|_| VerifyError::ExtractPublicKey)
        .expect("Conversion from COSE to DER failed");

    // Step 5: Compute client_data_hash and message
    let client_data_hash = Sha256::digest(client_data_json);
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&client_data_hash);

    // Step 6: Sign the message to get the signature in DER format
    let signature: Signature = private_key.sign(&message);
    let signature_der = signature.to_der();

    // Step 7: Tamper with the signature to make it invalid
    let mut tampered_signature_der = signature_der.as_bytes().to_vec();
    tampered_signature_der[0] ^= 0xFF; // Flip some bits

    // Step 8: Verify the signature (should fail)
    assert!(
        webauthn_verify(
            authenticator_data,
            client_data_json,
            &tampered_signature_der,
            public_key_der.as_slice(),
        )
        .is_err(),
        "The signature verification should fail with an invalid signature."
    );
}
