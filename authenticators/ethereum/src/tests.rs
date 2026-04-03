use crate::mock::*;
use crate::{
    eth::recover_eth_address, EthAddress, EthRegistration, EthSignature, Sign, SignedMessage,
};
use frame::{
    deps::sp_core::{ecdsa, Pair},
    testing_prelude::*,
    traits::TxBaseImplication,
};
use sp_io::hashing::keccak_256;
use traits_authn::{Challenger, ExtrinsicContext, HashedUserId};

const USER: HashedUserId = *b"alice\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
parameter_types! {
    pub EthKey: ecdsa::Pair = ecdsa::Pair::from_seed(&[1u8; 32]);
    pub UserAddress: AccountId = Pass::address_for(USER);
}

fn eth_address_of(pair: &ecdsa::Pair) -> EthAddress {
    let dummy_msg = [0u8; 32];
    let sig = pair.sign_prehashed(&dummy_msg);
    let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig.0, &dummy_msg)
        .ok()
        .expect("recovery works");
    let hash = keccak_256(&pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    EthAddress::from_raw(addr)
}

fn make_signature(xtc: &impl ExtrinsicContext) -> (SignedMessage<u64>, EthAddress, [u8; 65]) {
    let context = System::block_number();
    let message = SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: AuthorityId::get(),
    };
    let pair = EthKey::get();
    let address = eth_address_of(&pair);
    let signature = message.sign(&pair);

    (message, address, signature)
}

mod registration {
    use super::*;

    #[test]
    fn registration_fails_if_attestation_is_invalid() {
        new_test_ext().execute_with(|| {
            let (mut message, address, signature) = make_signature(&[]);

            // Alter challenge to invalidate
            message.challenge = [0u8; 32];

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    EthRegistration {
                        address,
                        message,
                        signature,
                    }
                ),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }

    #[test]
    fn registration_fails_with_wrong_address() {
        new_test_ext().execute_with(|| {
            let (message, _address, signature) = make_signature(&UserAddress::get().encode());

            // Use a different address
            let wrong_address = EthAddress::from_raw([0xAB; 20]);

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    EthRegistration {
                        address: wrong_address,
                        message,
                        signature,
                    }
                ),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }

    #[test]
    fn registration_works_if_attestation_is_valid() {
        new_test_ext().execute_with(|| {
            let (message, address, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                EthRegistration {
                    address,
                    message,
                    signature,
                }
            ));
        })
    }
}

mod authentication {
    use super::*;

    fn new_test_ext() -> TestExternalities {
        let mut t = super::new_test_ext();
        t.execute_with(|| {
            let (message, address, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                EthRegistration {
                    address,
                    message,
                    signature,
                }
            ));
        });
        t
    }

    #[test]
    fn authentication_fails_if_credentials_are_invalid() {
        new_test_ext().execute_with(|| {
            let (message, address, signature) = make_signature(&[]);

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                address.as_ref().clone(),
                EthSignature {
                    user_id: USER,
                    message,
                    signature,
                },
            );

            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();

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
    fn authentication_works_if_credentials_are_valid() {
        new_test_ext().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();

            let (message, address, signature) = make_signature(
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
            );

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                address.as_ref().clone(),
                EthSignature {
                    user_id: USER,
                    message,
                    signature,
                },
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

mod eth_address {
    use super::*;

    #[test]
    fn recover_works_with_normalized_v() {
        new_test_ext().execute_with(|| {
            let pair = EthKey::get();
            let message = b"hello ethereum";
            let hash = crate::eth::personal_sign_hash(message);
            let sig = pair.sign_prehashed(&hash);

            let recovered = recover_eth_address(&hash, &sig.0).expect("should recover");
            let expected = eth_address_of(&pair);
            assert_eq!(recovered, expected);
        })
    }

    #[test]
    fn recover_works_with_legacy_v() {
        new_test_ext().execute_with(|| {
            let pair = EthKey::get();
            let message = b"hello ethereum";
            let hash = crate::eth::personal_sign_hash(message);
            let mut sig = pair.sign_prehashed(&hash).0;

            // Convert v from 0/1 to legacy 27/28
            sig[64] += 27;

            let recovered = recover_eth_address(&hash, &sig).expect("should recover");
            let expected = eth_address_of(&pair);
            assert_eq!(recovered, expected);
        })
    }

    #[test]
    fn recover_fails_with_invalid_v() {
        new_test_ext().execute_with(|| {
            let pair = EthKey::get();
            let hash = crate::eth::personal_sign_hash(b"test");
            let mut sig = pair.sign_prehashed(&hash).0;
            sig[64] = 99; // Invalid v

            assert!(recover_eth_address(&hash, &sig).is_none());
        })
    }

    #[test]
    fn recover_fails_with_zero_signature() {
        new_test_ext().execute_with(|| {
            let hash = crate::eth::personal_sign_hash(b"test");
            let sig = [0u8; 65];
            assert!(recover_eth_address(&hash, &sig).is_none());
        })
    }

    #[test]
    fn malformed_padding_rejects_registration() {
        new_test_ext().execute_with(|| {
            let (message, _address, signature) = make_signature(&UserAddress::get().encode());

            // Construct an EthAddress with non-zero padding
            let mut malformed = EthAddress::from_raw([0xAA; 20]);
            // Directly set a padding byte to non-zero via encode/decode round-trip
            let mut bytes = [0u8; 32];
            bytes[0] = 0xFF; // non-zero in padding area
            bytes[12..].copy_from_slice(&[0xAA; 20]);
            let malformed = EthAddress::decode(&mut &bytes[..]).unwrap();

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    EthRegistration {
                        address: malformed,
                        message,
                        signature,
                    }
                ),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }
}
