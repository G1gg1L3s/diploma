use crypto::{digest::Digest, sha2};
use rand::Rng;

pub struct Sha256;

impl super::Commitment for Sha256 {
    type PublicElement = [u8; 32];
    type PrivateElement = [u8; 32];

    fn generate(&self) -> Self::PrivateElement {
        rand::thread_rng().gen()
    }

    fn commit(&self, el: &Self::PrivateElement) -> Self::PublicElement {
        let mut digest = sha2::Sha256::new();
        digest.input(el);
        let mut out = [0; 32];
        digest.result(&mut out);
        out
    }

    fn verify(&self, commitment: &Self::PublicElement, reveal: &Self::PrivateElement) -> bool {
        let c = self.commit(reveal);
        crypto::util::fixed_time_eq(&c, commitment)
    }
}

#[cfg(test)]
mod tests {
    use crate::commitment::{PrivateKey, PublicKey};

    use super::*;

    #[test]
    fn test_sha256_auth() {
        let mut private = PrivateKey::new(Sha256);
        let mut public = PublicKey::new(Sha256, private.public());

        for _ in 0..10 {
            let reveal = private.private();
            assert!(public.verify(&reveal));

            private.advance();
            public.advance(private.public());
        }
    }
}
