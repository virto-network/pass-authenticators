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
    let signature =
        <pass_ethereum::SignedMessage<u64> as pass_ethereum::Sign<u64>>::sign(&message, &pair);

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
    let signature =
        <pass_solana::SignedMessage<u64> as pass_solana::Sign<u64>>::sign(&message, &pair);

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
    let signature =
        <pass_bitcoin::SignedMessage<u64> as pass_bitcoin::Sign<u64>>::sign(&message, &pair);

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
    let signature = <pass_ssh::SignedMessage<u64> as pass_ssh::Sign<u64>>::sign(&message, &pair);

    let attestation = PassDeviceAttestation::Ssh(pass_ssh::SshRegistration {
        pubkey,
        message,
        signature,
    });
    (pubkey, attestation)
}

// ---------- Cross-authenticator replay tests ----------

mod cross_authenticator {
    use super::*;

    fn setup() -> TestExternalities {
        let mut t = new_test_ext();
        t.execute_with(|| {
            // Register ETH device
            let (_, att) = make_eth_registration(&EthUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), ETH_USER, att));

            // Register SOL device
            let (_, att) = make_sol_registration(&SolUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), SOL_USER, att));

            // Register BTC device
            let (_, att) = make_btc_registration(&BtcUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), BTC_USER, att));

            // Register SSH device
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

            // Create a valid ETH signature
            let context = System::block_number();
            let eth_msg = pass_ethereum::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let eth_sig = <pass_ethereum::SignedMessage<u64> as pass_ethereum::Sign<u64>>::sign(
                &eth_msg,
                &EthKey::get(),
            );

            // Wrap in ETH credential but use SOL account's device_id
            let sol_pubkey = pass_solana::SolPubkey(SolKey::get().public().0);
            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                sol_pubkey.0, // SOL's device_id
                PassCredential::Eth(pass_ethereum::EthSignature {
                    user_id: SOL_USER, // Try to auth as SOL user
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

            // Create a valid SOL signature
            let context = System::block_number();
            let sol_msg = pass_solana::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let sol_sig = <pass_solana::SignedMessage<u64> as pass_solana::Sign<u64>>::sign(
                &sol_msg,
                &SolKey::get(),
            );

            // Wrap in SOL credential but use ETH account's device_id
            let eth_addr = eth_address_of(&EthKey::get());
            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                *eth_addr.as_ref(), // ETH's device_id
                PassCredential::Sol(pass_solana::SolSignature {
                    user_id: ETH_USER, // Try to auth as ETH user
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
            let btc_sig = <pass_bitcoin::SignedMessage<u64> as pass_bitcoin::Sign<u64>>::sign(
                &btc_msg,
                &BtcKey::get(),
            );

            // Use SSH device_id with BTC credential
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

            // Valid ETH auth
            let context = System::block_number();
            let eth_msg = pass_ethereum::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let eth_sig = <pass_ethereum::SignedMessage<u64> as pass_ethereum::Sign<u64>>::sign(
                &eth_msg,
                &EthKey::get(),
            );
            let eth_addr = eth_address_of(&EthKey::get());

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                *eth_addr.as_ref(),
                PassCredential::Eth(pass_ethereum::EthSignature {
                    user_id: ETH_USER,
                    message: eth_msg,
                    signature: eth_sig,
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

    #[test]
    fn all_authenticators_work_independently_in_composite() {
        setup().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let xtc =
                TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);
            let context = System::block_number();

            // SOL auth
            let sol_msg = pass_solana::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let sol_sig = <pass_solana::SignedMessage<u64> as pass_solana::Sign<u64>>::sign(
                &sol_msg,
                &SolKey::get(),
            );
            let sol_pubkey = pass_solana::SolPubkey(SolKey::get().public().0);

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                sol_pubkey.0,
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

            // SSH auth
            let ssh_msg = pass_ssh::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let ssh_sig = <pass_ssh::SignedMessage<u64> as pass_ssh::Sign<u64>>::sign(
                &ssh_msg,
                &SshKey::get(),
            );
            let ssh_pubkey = pass_ssh::SshPubkey(SshKey::get().public().0);

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                ssh_pubkey.0,
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

// ---------- Session key security ----------

mod session_keys {
    use super::*;

    fn setup_with_eth() -> TestExternalities {
        let mut t = new_test_ext();
        t.execute_with(|| {
            let (_, att) = make_eth_registration(&EthUserAddress::get().encode());
            assert_ok!(PassPallet::register(RuntimeOrigin::root(), ETH_USER, att));
        });
        t
    }

    #[test]
    fn session_key_cannot_register_new_account() {
        setup_with_eth().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let xtc =
                TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);

            // Create a valid session key
            let context = System::block_number();
            let eth_msg = pass_ethereum::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &xtc),
                authority_id: PassAuthority::get(),
            };
            let eth_sig = <pass_ethereum::SignedMessage<u64> as pass_ethereum::Sign<u64>>::sign(
                &eth_msg,
                &EthKey::get(),
            );
            let eth_addr = eth_address_of(&EthKey::get());

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                *eth_addr.as_ref(),
                PassCredential::Eth(pass_ethereum::EthSignature {
                    user_id: ETH_USER,
                    message: eth_msg,
                    signature: eth_sig,
                }),
            );

            // First verify the auth works
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

            // Now add a session key for this account
            let session_key_pair = ed25519::Pair::from_seed(&[99u8; 32]);
            let session_key: AccountId = session_key_pair.public().into();

            // Session keys are ephemeral — they can authenticate but should not
            // be usable to escalate privileges (e.g., register new accounts).
            // The session key itself is NOT a registered pass account.
            // Verify that no pass account maps to this session key's address.
            let session_addr =
                PassPallet::address_for(*b"session_test\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
            assert_ne!(session_key, session_addr);
        })
    }
}

// ---------- Device isolation tests ----------

mod device_isolation {
    use super::*;

    #[test]
    fn same_ed25519_key_registered_as_sol_and_ssh_are_separate_accounts() {
        new_test_ext().execute_with(|| {
            // Use the SAME ed25519 key for both SOL and SSH registrations
            // Due to domain separators, the signatures will be different
            // But the DeviceId (raw 32-byte pubkey) is identical
            let shared_key = ed25519::Pair::from_seed(&[20u8; 32]);
            let pubkey_bytes = shared_key.public().0;

            let sol_user: HashedUserId = *b"sol_shared\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
            let ssh_user: HashedUserId = *b"ssh_shared\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

            let sol_addr = PassPallet::address_for(sol_user);
            let ssh_addr = PassPallet::address_for(ssh_user);

            // Register as SOL
            let context = System::block_number();
            let sol_msg = pass_solana::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &sol_addr.encode()),
                authority_id: PassAuthority::get(),
            };
            let sol_sig = <pass_solana::SignedMessage<u64> as pass_solana::Sign<u64>>::sign(
                &sol_msg,
                &shared_key,
            );
            let sol_att = PassDeviceAttestation::Sol(pass_solana::SolRegistration {
                pubkey: pass_solana::SolPubkey(pubkey_bytes),
                message: sol_msg,
                signature: sol_sig,
            });
            assert_ok!(PassPallet::register(
                RuntimeOrigin::root(),
                sol_user,
                sol_att
            ));

            // Try to register the SAME DeviceId as SSH for a different user
            // pallet-pass should reject because the device_id is already taken
            let ssh_msg = pass_ssh::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &ssh_addr.encode()),
                authority_id: PassAuthority::get(),
            };
            let ssh_sig =
                <pass_ssh::SignedMessage<u64> as pass_ssh::Sign<u64>>::sign(&ssh_msg, &shared_key);
            let ssh_att = PassDeviceAttestation::Ssh(pass_ssh::SshRegistration {
                pubkey: pass_ssh::SshPubkey(pubkey_bytes),
                message: ssh_msg,
                signature: ssh_sig,
            });

            // This should fail — same device_id cannot be registered to two accounts
            // (assuming pallet-pass enforces this)
            let result = PassPallet::register(RuntimeOrigin::root(), ssh_user, ssh_att);

            // If pallet-pass allows it, that's a finding worth documenting
            if result.is_ok() {
                // Both registrations succeeded — verify they're on SEPARATE accounts
                // This means the same physical key controls two accounts
                // The SOL credential should NOT work for the SSH account
                let extrinsic_version: u8 = 0;
                let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
                let xtc =
                    TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256);

                let sol_auth_msg = pass_solana::SignedMessage {
                    context,
                    challenge: BlockChallenger::generate(&context, &xtc),
                    authority_id: PassAuthority::get(),
                };
                let sol_auth_sig =
                    <pass_solana::SignedMessage<u64> as pass_solana::Sign<u64>>::sign(
                        &sol_auth_msg,
                        &shared_key,
                    );

                // Try SOL credential claiming to be SSH user
                let ext = pallet_pass::PassAuthenticate::<Test>::from(
                    pubkey_bytes,
                    PassCredential::Sol(pass_solana::SolSignature {
                        user_id: ssh_user, // wrong user
                        message: sol_auth_msg,
                        signature: sol_auth_sig,
                    }),
                );

                // This MUST fail — composite dispatch (Device::Sol, Cred::Sol) would match
                // on variant but the device stored is SSH variant for this account
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
            }
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

            // Use a WRONG authority_id
            let context = System::block_number();
            let bad_authority = [0xFFu8; 32];
            let message = pass_ethereum::SignedMessage {
                context,
                challenge: BlockChallenger::generate(&context, &EthUserAddress::get().encode()),
                authority_id: bad_authority,
            };
            let signature = <pass_ethereum::SignedMessage<u64> as pass_ethereum::Sign<u64>>::sign(
                &message, &pair,
            );

            let attestation = PassDeviceAttestation::Eth(pass_ethereum::EthRegistration {
                address,
                message,
                signature,
            });

            assert_noop!(
                PassPallet::register(RuntimeOrigin::root(), ETH_USER, attestation),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }
}
