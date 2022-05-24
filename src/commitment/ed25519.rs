use ed25519_dalek::{PublicKey, SecretKey};

pub struct CloneableSecretKey(pub SecretKey);

impl Clone for CloneableSecretKey {
    fn clone(&self) -> Self {
        Self(SecretKey::from_bytes(self.0.as_bytes()).expect("should be valid"))
    }
}

pub struct Ed25519;

impl super::Commitment for Ed25519 {
    type PublicElement = PublicKey;

    type PrivateElement = CloneableSecretKey;

    fn generate(&self) -> Self::PrivateElement {
        let mut rng = rand::thread_rng();
        CloneableSecretKey(SecretKey::generate(&mut rng))
    }

    fn commit(&self, el: &Self::PrivateElement) -> Self::PublicElement {
        PublicKey::from(&el.0)
    }

    fn verify(&self, commitment: &Self::PublicElement, reveal: &Self::PrivateElement) -> bool {
        let c = self.commit(reveal);
        c.eq(commitment)
    }
}

#[cfg(test)]
mod tests {
    use crate::commitment::{PrivateKey, PublicKey};

    use super::*;

    #[test]
    fn test_auth() {
        let mut private = PrivateKey::new(Ed25519);
        let mut public = PublicKey::new(Ed25519, private.public());

        for _ in 0..10 {
            let reveal = private.private();
            assert!(public.verify(&reveal));

            private.advance();
            public.advance(private.public());
        }
    }
}
