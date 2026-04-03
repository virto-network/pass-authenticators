use crate::mock::*;
use frame::{
    deps::sp_core::{ecdsa, ed25519, Pair},
    testing_prelude::*,
    traits::TxBaseImplication,
};
use sp_io::hashing::keccak_256;
use traits_authn::{Challenger, ExtrinsicContext, HashedUserId};

// ---------- Helpers ----------

const ETH_USER: HashedUserId = *b"eth_user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const SOL_USER: HashedUserId = *b"sol_user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const BTC_USER: HashedUserId = *b"btc_user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const SSH_USER: HashedUserId = *b"ssh_user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

parameter_types! {
    pub EthKey: ecdsa::Pair = ecdsa::Pair::from_seed(&[10u8; 32]);
    pub SolKey: ed25519::Pair = ed25519::Pair::from_seed(&[11u8; 32]);
    pub SshKey: ed25519::Pair = ed25519::Pair::from_seed(&[12u8; 32]);
    pub BtcKey: ecdsa::Pair = ecdsa::Pair::from_seed(&[13u8; 32]);
    pub EthUserAddress: AccountId = PassPallet::address_for(ETH_USER);
    pub SolUserAddress: AccountId = PassPallet::address_for(SOL_USER);
    pub BtcUserAddress: AccountId = PassPallet::address_for(BTC_USER);
    pub SshUserAddress: AccountId = PassPallet::address_for(SSH_USER);
}

fn eth_address_of(pair: &ecdsa::Pair) -> pass_ethereum::EthAddress {
    let dummy = [0u8; 32];
    let sig = pair.sign_prehashed(&dummy);
    let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig.0, &dummy)
        .ok()
        .unwrap();
    let hash = keccak_256(&pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    pass_ethereum::EthAddress::from_raw(addr)
}

fn btc_pubkey_hash_of(pair: &ecdsa::Pair) -> pass_bitcoin::BtcPubkeyHash {
    use ripemd::{Digest, Ripemd160};
    let dummy = [0u8; 32];
    let sig = pair.sign_prehashed(&dummy);
    let pubkey = sp_io::crypto::secp256k1_ecdsa_recover_compressed(&sig.0, &dummy)
        .ok()
        .unwrap();
    let sha = sp_io::hashing::sha2_256(&pubkey);
    let mut hasher = Ripemd160::new();
    hasher.update(sha);
    let h160: [u8; 20] = hasher.finalize().into();
    pass_bitcoin::BtcPubkeyHash::from_hash160(h160)
}

fn make_eth_registration(
    xtc: &impl ExtrinsicContext,
) -> (pass_ethereum::EthAddress, PassDeviceAttestation) {
    let context = System::block_number();
    let message = pass_ethereum::SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: PassAuthority::get(),
    };
    let pair = EthKey::get();
    let address = eth_address_of(&pair);
    let signature = message.sign(&pair);
    let attestation = PassDeviceAttestation::Eth(pass_ethereum::EthRegistration {
        address,
        message,
        signature,
    });
    (address, attestation)
}

fn make_sol_registration(
    xtc: &impl ExtrinsicContext,
) -> (pass_solana::SolPubkey, PassDeviceAttestation) {
    let context = System::block_number();
    let message = pass_solana::SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: PassAuthority::get(),
    };
    let pair = SolKey::get();
    let pubkey = pass_solana::SolPubkey(pair.public().0);
    let signature = message.sign(&pair);
    let attestation = PassDeviceAttestation::Sol(pass_solana::SolRegistration {
        pubkey,
        message,
        signature,
    });
    (pubkey, attestation)
}

fn make_btc_registration(
    xtc: &impl ExtrinsicContext,
) -> (pass_bitcoin::BtcPubkeyHash, PassDeviceAttestation) {
    let context = System::block_number();
    let message = pass_bitcoin::SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: PassAuthority::get(),
    };
    let pair = BtcKey::get();
    let pubkey_hash = btc_pubkey_hash_of(&pair);
    let signature = message.sign(&pair);
    let attestation = PassDeviceAttestation::Btc(pass_bitcoin::BtcRegistration {
        pubkey_hash,
        message,
        signature,
    });
    (pubkey_hash, attestation)
}

fn make_ssh_registration(
    xtc: &impl ExtrinsicContext,
) -> (pass_ssh::SshPubkey, PassDeviceAttestation) {
    let context = System::block_number();
    let message = pass_ssh::SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: PassAuthority::get(),
    };
    let pair = SshKey::get();
    let pubkey = pass_ssh::SshPubkey(pair.public().0);
    let signature = message.sign(&pair);
    let attestation = PassDeviceAttestation::Ssh(pass_ssh::SshRegistration {
        pubkey,
        message,
        signature,
    });
    (pubkey, attestation)
}

fn make_eth_credential(xtc: &impl ExtrinsicContext) -> (pass_ethereum::EthAddress, PassCredential) {
    let context = System::block_number();
    let message = pass_ethereum::SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: PassAuthority::get(),
    };
    let pair = EthKey::get();
    let address = eth_address_of(&pair);
    let signature = message.sign(&pair);
    let credential = PassCredential::Eth(pass_ethereum::EthSignature {
        user_id: ETH_USER,
        message,
        signature,
    });
    (address, credential)
}

// ---------- Cross-authenticator replay tests ----------

mod cross_authenticator {
    use super::*;

    fn setup() -> TestExternalities {
        let mut t = new_test_ext();
        t.execute_with(|| {
            let (_, att) = make_eth_registration(&EthUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), ETH_USER, att));

            let (_, att) = make_sol_registration(&SolUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), SOL_USER, att));

            let (_, att) = make_btc_registration(&BtcUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), BTC_USER, att));

            let (_, att) = make_ssh_registration(&SshUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), SSH_USER, att));
        });
        t
    }

    #[test]
    fn eth_credential_cannot_authenticate_sol_account() {
        setup().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let xtc =
                TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);

            let context = System::block_number();
            let eth_msg = pass_ethereum::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let eth_sig = eth_msg.sign(&EthKey::get());

            // Use SOL device_id with ETH credential → must fail
            let sol_pubkey = pass_solana::SolPubkey(SolKey::get().public().0);
            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                sol_pubkey.0,
                PassCredential::Eth(pass_ethereum::EthSignature {
                    user_id: SOL_USER,
                    message: eth_msg,
                    signature: eth_sig,
                }),
            );

            assert_noop!(
                ext.validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()),
                InvalidTransaction::BadSigner
            );
        })
    }

    #[test]
    fn sol_credential_cannot_authenticate_eth_account() {
        setup().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let xtc =
                TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);

            let context = System::block_number();
            let sol_msg = pass_solana::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let sol_sig = sol_msg.sign(&SolKey::get());

            let eth_addr = eth_address_of(&EthKey::get());
            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                *eth_addr.as_ref(),
                PassCredential::Sol(pass_solana::SolSignature {
                    user_id: ETH_USER,
                    message: sol_msg,
                    signature: sol_sig,
                }),
            );

            assert_noop!(
                ext.validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()),
                InvalidTransaction::BadSigner
            );
        })
    }

    #[test]
    fn btc_credential_cannot_authenticate_ssh_account() {
        setup().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let xtc =
                TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);

            let context = System::block_number();
            let btc_msg = pass_bitcoin::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let btc_sig = btc_msg.sign(&BtcKey::get());

            let ssh_pubkey = pass_ssh::SshPubkey(SshKey::get().public().0);
            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                ssh_pubkey.0,
                PassCredential::Btc(pass_bitcoin::BtcSignature {
                    user_id: SSH_USER,
                    message: btc_msg,
                    signature: btc_sig,
                }),
            );

            assert_noop!(
                ext.validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()),
                InvalidTransaction::BadSigner
            );
        })
    }

    #[test]
    fn correct_authenticator_works_in_composite() {
        setup().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let xtc =
                TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);

            let (address, credential) = make_eth_credential(&xtc);
            let ext = pallet_pass::PassAuthenticate::<Test>::from(*address.as_ref(), credential);

            assert_ok!(ext
                .validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()));
        })
    }

    #[test]
    fn all_authenticators_work_independently_in_composite() {
        setup().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let xtc =
                TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);
            let context = System::block_number();

            // SOL
            let sol_msg = pass_solana::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let sol_sig = sol_msg.sign(&SolKey::get());
            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                SolKey::get().public().0,
                PassCredential::Sol(pass_solana::SolSignature {
                    user_id: SOL_USER,
                    message: sol_msg,
                    signature: sol_sig,
                }),
            );
            assert_ok!(ext
                .validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()));

            // SSH
            let ssh_msg = pass_ssh::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let ssh_sig = ssh_msg.sign(&SshKey::get());
            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                SshKey::get().public().0,
                PassCredential::Ssh(pass_ssh::SshSignature {
                    user_id: SSH_USER,
                    message: ssh_msg,
                    signature: ssh_sig,
                }),
            );
            assert_ok!(ext
                .validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()));
        })
    }
}

// ---------- DeviceId collision ----------

mod device_isolation {
    use super::*;

    #[test]
    fn duplicate_device_id_across_accounts_is_rejected() {
        new_test_ext().execute_with(|| {
            // Use the SAME ed25519 key for both SOL and SSH.
            // DeviceId is the raw 32-byte pubkey — identical for both.
            let shared_key = ed25519::Pair::from_seed(&[20u8; 32]);
            let pubkey_bytes = shared_key.public().0;

            let sol_user: HashedUserId = *b"sol_shared\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            let ssh_user: HashedUserId = *b"ssh_shared\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

            let sol_addr = PassPallet::address_for(sol_user);
            let ssh_addr = PassPallet::address_for(ssh_user);

            // Register SOL device
            let context = System::block_number();
            let sol_msg = pass_solana::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &sol_addr.encode()),
                authority_id: PassAuthority::get(),
            };
            let sol_sig = sol_msg.sign(&shared_key);
            assert_ok!(PassPallet::register(
                RuntimeOrigin::root(),
                sol_user,
                PassDeviceAttestation::Sol(pass_solana::SolRegistration {
                    pubkey: pass_solana::SolPubkey(pubkey_bytes),
                    message: sol_msg,
                    signature: sol_sig,
                })
            ));

            // Attempt to register SAME DeviceId as SSH for different user
            // pallet-pass enforces DeviceId uniqueness via DeviceIds storage
            let ssh_msg = pass_ssh::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &ssh_addr.encode()),
                authority_id: PassAuthority::get(),
            };
            let ssh_sig = ssh_msg.sign(&shared_key);

            assert_noop!(
                PassPallet::register(
                    RuntimeOrigin::root(),
                    ssh_user,
                    PassDeviceAttestation::Ssh(pass_ssh::SshRegistration {
                        pubkey: pass_ssh::SshPubkey(pubkey_bytes),
                        message: ssh_msg,
                        signature: ssh_sig,
                    })
                ),
                pallet_pass::Error::<Test>::DeviceAlreadyExists
            );
        })
    }
}

// ---------- Authority mismatch ----------

mod authority {
    use super::*;

    #[test]
    fn wrong_authority_id_rejects_registration() {
        new_test_ext().execute_with(|| {
            let pair = EthKey::get();
            let address = eth_address_of(&pair);

            let context = System::block_number();
            let bad_authority = [0xFFu8; 32];
            let message = pass_ethereum::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &EthUserAddress::get().encode()),
                authority_id: bad_authority,
            };
            let signature = message.sign(&pair);

            assert_noop!(
                PassPallet::register(
                    RuntimeOrigin::root(),
                    ETH_USER,
                    PassDeviceAttestation::Eth(pass_ethereum::EthRegistration {
                        address,
                        message,
                        signature,
                    })
                ),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }
}

// ---------- Payload domain separation ----------

mod domain_separation {
    use super::*;

    #[test]
    fn different_authenticators_produce_different_payloads_for_same_inputs() {
        new_test_ext().execute_with(|| {
            let context: u64 = 1;
            let challenge = [42u8; 32];
            let authority = [1u8; 32];

            let eth_msg = pass_ethereum::SignedMessage {
                context,
                challenge,
                authority_id: authority,
            };
            let sol_msg = pass_solana::SignedMessage {
                context,
                challenge,
                authority_id: authority,
            };
            let ssh_msg = pass_ssh::SignedMessage {
                context,
                challenge,
                authority_id: authority,
            };
            let btc_msg = pass_bitcoin::SignedMessage {
                context,
                challenge,
                authority_id: authority,
            };
            let nostr_msg = pass_nostr::SignedMessage {
                context,
                challenge,
                authority_id: authority,
            };

            let eth_payload = eth_msg.payload();
            let sol_payload = sol_msg.payload();
            let ssh_payload = ssh_msg.payload();
            let btc_payload = btc_msg.payload();
            let nostr_payload = nostr_msg.payload();

            // All payloads must be distinct due to domain separators
            let payloads = [
                &eth_payload,
                &sol_payload,
                &ssh_payload,
                &btc_payload,
                &nostr_payload,
            ];
            for i in 0..payloads.len() {
                for j in (i + 1)..payloads.len() {
                    assert_ne!(
                        payloads[i], payloads[j],
                        "Payload collision between authenticators {} and {}",
                        i, j
                    );
                }
            }
        })
    }

    #[test]
    fn domain_prefixes_are_correct() {
        new_test_ext().execute_with(|| {
            let msg = pass_ethereum::SignedMessage {
                context: 1u64,
                challenge: [0u8; 32],
                authority_id: [0u8; 32],
            };
            assert!(msg.payload().starts_with(b"ETH"));

            let msg = pass_bitcoin::SignedMessage {
                context: 1u64,
                challenge: [0u8; 32],
                authority_id: [0u8; 32],
            };
            assert!(msg.payload().starts_with(b"BTC"));

            let msg = pass_solana::SignedMessage {
                context: 1u64,
                challenge: [0u8; 32],
                authority_id: [0u8; 32],
            };
            assert!(msg.payload().starts_with(b"SOL"));

            let msg = pass_nostr::SignedMessage {
                context: 1u64,
                challenge: [0u8; 32],
                authority_id: [0u8; 32],
            };
            assert!(msg.payload().starts_with(b"NOSTR"));

            let msg = pass_ssh::SignedMessage {
                context: 1u64,
                challenge: [0u8; 32],
                authority_id: [0u8; 32],
            };
            assert!(msg.payload().starts_with(b"SSH"));
        })
    }

    #[test]
    fn payload_is_unique_for_different_contexts() {
        // Verify no SCALE length-extension ambiguity:
        // different (context, challenge) pairs must produce different payloads.
        new_test_ext().execute_with(|| {
            let authority = [0u8; 32];

            let msg1 = pass_ethereum::SignedMessage {
                context: 256u64, // SCALE encodes as [0, 1, 0, 0, 0, 0, 0, 0]
                challenge: [0u8; 32],
                authority_id: authority,
            };
            let msg2 = pass_ethereum::SignedMessage {
                context: 1u64, // SCALE encodes as [1, 0, 0, 0, 0, 0, 0, 0]
                challenge: [0u8; 32],
                authority_id: authority,
            };

            assert_ne!(msg1.payload(), msg2.payload());

            // Also verify that context bytes don't bleed into challenge
            let mut challenge_with_prefix = [0u8; 32];
            challenge_with_prefix[0] = 1;
            let msg3 = pass_ethereum::SignedMessage {
                context: 0u64,
                challenge: challenge_with_prefix,
                authority_id: authority,
            };
            let msg4 = pass_ethereum::SignedMessage {
                context: 0u64,
                challenge: [0u8; 32],
                authority_id: authority,
            };
            assert_ne!(msg3.payload(), msg4.payload());
        })
    }
}
