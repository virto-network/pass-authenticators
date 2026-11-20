use super::*;

/// What browser wallet extensions put around a message they sign as raw bytes (`signRaw`, i.e.
/// polkadot-js' `u8aWrapBytes`), so that it can't be mistaken for an extrinsic.
const WRAP_PREFIX: &[u8] = b"<Bytes>";
const WRAP_POSTFIX: &[u8] = b"</Bytes>";

impl<Cx: Encode> SignedMessage<Cx> {
    pub fn message(&self) -> impl AsRef<[u8]> {
        [
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }

    /// The [message][Self::message] wrapped in `<Bytes>…</Bytes>`: what a browser wallet
    /// extension signs when it's asked to sign the message as raw bytes.
    pub fn wrapped_message(&self) -> impl AsRef<[u8]> {
        [WRAP_PREFIX, self.message().as_ref(), WRAP_POSTFIX].concat()
    }
}

#[cfg(feature = "runtime")]
impl<Cx: Encode> SignedMessage<Cx> {
    /// Whether `signature` is `signer`'s signature of the [message][Self::message], either as
    /// it is or [wrapped][Self::wrapped_message] in `<Bytes>…</Bytes>`.
    pub(crate) fn is_signed_by(&self, signature: &MultiSignature, signer: &AccountId32) -> bool {
        use sp_runtime::traits::Verify;

        signature.verify(self.message().as_ref(), signer)
            || signature.verify(self.wrapped_message().as_ref(), signer)
    }
}

#[cfg(feature = "full-crypto")]
mod signing {
    use super::*;
    use sp_core::{ecdsa, ed25519, sr25519, Pair};

    impl<Cx: Encode> Sign<sr25519::Pair, Cx> for SignedMessage<Cx> {
        fn sign(&self, signer: sr25519::Pair) -> MultiSignature {
            MultiSignature::from(signer.sign(self.message().as_ref()))
        }
    }

    impl<Cx: Encode> Sign<ed25519::Pair, Cx> for SignedMessage<Cx> {
        fn sign(&self, signer: ed25519::Pair) -> MultiSignature {
            MultiSignature::from(signer.sign(self.message().as_ref()))
        }
    }

    impl<Cx: Encode> Sign<ecdsa::Pair, Cx> for SignedMessage<Cx> {
        fn sign(&self, signer: ecdsa::Pair) -> MultiSignature {
            MultiSignature::from(signer.sign(self.message().as_ref()))
        }
    }
}
