pub mod aes;
pub mod ed25519;
pub mod hash;

pub trait Commitment {
    type PublicElement;
    type PrivateElement: Clone;

    fn generate(&self) -> Self::PrivateElement;

    fn commit(&self, el: &Self::PrivateElement) -> Self::PublicElement;

    fn verify(&self, commitment: &Self::PublicElement, reveal: &Self::PrivateElement) -> bool;
}

pub struct PrivateKey<C: Commitment> {
    commit: C,
    private: C::PrivateElement,
}

pub struct PublicKey<C: Commitment> {
    commit: C,
    public: C::PublicElement,
}

impl<C: Commitment> PrivateKey<C> {
    pub fn new(commit: C) -> Self {
        let private = commit.generate();
        Self { commit, private }
    }

    pub fn public(&self) -> C::PublicElement {
        self.commit.commit(&self.private)
    }

    pub fn private(&self) -> C::PrivateElement {
        self.private.clone()
    }

    pub fn advance(&mut self) {
        let private = self.commit.generate();
        self.private = private;
    }
}

impl<C: Commitment> PublicKey<C> {
    pub fn new(commit: C, public: C::PublicElement) -> Self {
        Self { commit, public }
    }

    pub fn verify(&self, private: &C::PrivateElement) -> bool {
        self.commit.verify(&self.public, private)
    }

    pub fn advance(&mut self, new_public: C::PublicElement) {
        self.public = new_public;
    }
}
