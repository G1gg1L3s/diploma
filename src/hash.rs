use std::marker::PhantomData;

use crypto::{digest::Digest, sha2::Sha256};

use crate::base::{OneWay, PrivateKey, PublicKey};

pub trait Hash: Digest {
    fn new() -> Self;
}

impl Hash for Sha256 {
    fn new() -> Self {
        Sha256::new()
    }
}

impl<T> OneWay for T
where
    T: Hash,
{
    fn compute(&self, i: usize, input: &[u8], output: &mut [u8]) {
        let ctr = u64::try_from(i)
            .expect("sorry, architecture is not supported")
            .to_be_bytes();
        let mut d = T::new();
        d.input(&ctr);
        d.input(input);
        d.result(output);
    }
}

pub struct HashBuilder<H: Hash, const SIZE: usize>(PhantomData<H>);

impl<H: Hash, const SIZE: usize> HashBuilder<H, SIZE> {
    pub fn new_private(rounds: usize) -> PrivateKey<H, SIZE> {
        PrivateKey::new(H::new(), rounds)
    }

    pub fn private_from_password(rounds: usize, pass: [u8; SIZE]) -> PrivateKey<H, SIZE> {
        PrivateKey::from_password(H::new(), rounds, pass)
    }

    pub fn new_public(password: [u8; SIZE]) -> PublicKey<H, SIZE> {
        PublicKey::new(H::new(), password)
    }
}

pub type Sha256Builder = HashBuilder<Sha256, 32>;

#[cfg(test)]
mod tests {
    use crate::{base::State, hash::Sha256Builder};

    #[test]
    fn normal_protocol() {
        let mut private = Sha256Builder::new_private(5);

        let p0 = private.get_password().unwrap();
        assert_eq!(private.pop_password(), State::Ok);

        let mut public = Sha256Builder::new_public(p0);

        let p1 = private.get_password().unwrap();
        assert!(public.verify(&p1).is_ok());
        assert_eq!(private.pop_password(), State::Ok);

        let p2 = private.get_password().unwrap();
        assert!(public.verify(&p2).is_ok());
        assert_eq!(private.pop_password(), State::Ok);

        let p3 = private.get_password().unwrap();
        assert!(public.verify(&p3).is_ok());
        assert_eq!(private.pop_password(), State::Ok);

        let p4 = private.get_password().unwrap();
        assert!(public.verify(&p4).is_ok());
        assert_eq!(private.pop_password(), State::Ok);

        let p5 = private.get_password().unwrap();
        assert!(public.verify(&p5).is_ok());
        assert_eq!(private.pop_password(), State::Empty);
    }
}
