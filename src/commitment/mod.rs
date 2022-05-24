pub mod aes;
pub mod hash;

pub trait Commitment {
    type Element: Clone;

    fn generate(&self) -> Self::Element;

    fn commit(&self, el: &Self::Element) -> Self::Element;

    fn verify(&self, commitment: &Self::Element, reveal: &Self::Element) -> bool;
}

pub struct PrivateKey<C: Commitment> {
    commit: C,
    private: C::Element,
}

pub struct PublicKey<C: Commitment> {
    commit: C,
    public: C::Element,
}

impl<C: Commitment> PrivateKey<C> {
    pub fn new(commit: C) -> Self {
        let private = commit.generate();
        Self { commit, private }
    }

    pub fn public(&self) -> C::Element {
        self.commit.commit(&self.private)
    }

    pub fn private(&self) -> C::Element {
        self.private.clone()
    }

    pub fn advance(&mut self) {
        let private = self.commit.generate();
        self.private = private;
    }
}

impl<C: Commitment> PublicKey<C> {
    pub fn new(commit: C, public: C::Element) -> Self {
        Self { commit, public }
    }

    pub fn verify(&self, private: &C::Element) -> bool {
        self.commit.verify(&self.public, private)
    }

    pub fn advance(&mut self, new_public: C::Element) {
        self.public = new_public;
    }
}
