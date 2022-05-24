use crypto::{
    aes::KeySize::KeySize128, aesni::AesNiEncryptor, aessafe, symmetriccipher::BlockEncryptor,
};
use rand::Rng;

pub struct Aes128SafeEncryptor;
pub struct Aes128NiEncryptor;

impl super::Commitment for Aes128SafeEncryptor {
    type Element = [u8; 16];

    fn generate(&self) -> Self::Element {
        rand::thread_rng().gen()
    }

    fn commit(&self, el: &Self::Element) -> Self::Element {
        let zeroes = [0; 16];
        let mut out = [0; 16];
        let cipher = aessafe::AesSafe128Encryptor::new(el);
        cipher.encrypt_block(&zeroes, &mut out);
        out
    }

    fn verify(&self, commitment: &Self::Element, reveal: &Self::Element) -> bool {
        let c = self.commit(reveal);
        crypto::util::fixed_time_eq(&c, commitment)
    }
}

impl super::Commitment for Aes128NiEncryptor {
    type Element = [u8; 16];

    fn generate(&self) -> Self::Element {
        rand::thread_rng().gen()
    }

    fn commit(&self, el: &Self::Element) -> Self::Element {
        let zeroes = [0; 16];
        let mut out = [0; 16];
        let cipher = AesNiEncryptor::new(KeySize128, el);
        cipher.encrypt_block(&zeroes, &mut out);
        out
    }

    fn verify(&self, commitment: &Self::Element, reveal: &Self::Element) -> bool {
        let c = self.commit(reveal);
        crypto::util::fixed_time_eq(&c, commitment)
    }
}

#[cfg(test)]
mod tests {
    use crate::commitment::{PrivateKey, PublicKey};

    use super::*;

    #[test]
    fn test_safe_auth() {
        let mut private = PrivateKey::new(Aes128SafeEncryptor);
        let mut public = PublicKey::new(Aes128SafeEncryptor, private.public());

        for _ in 0..10 {
            let reveal = private.private();
            assert!(public.verify(&reveal));

            private.advance();
            public.advance(private.public());
        }
    }

    #[test]
    fn test_ni_auth() {
        let mut private = PrivateKey::new(Aes128NiEncryptor);
        let mut public = PublicKey::new(Aes128NiEncryptor, private.public());

        for _ in 0..10 {
            let reveal = private.private();
            assert!(public.verify(&reveal));

            private.advance();
            public.advance(private.public());
        }
    }
}
