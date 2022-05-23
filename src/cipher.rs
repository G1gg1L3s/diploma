use std::marker::PhantomData;

use crypto::{
    aes::KeySize::KeySize128, aesni::AesNiEncryptor, aessafe::AesSafe128Encryptor,
    symmetriccipher::BlockEncryptor,
};

use crate::base::{OneWay, PrivateKey, PublicKey};

pub trait BlockCipher: BlockEncryptor + Sized {
    fn new(key: &[u8]) -> Self;

    fn encrypt(key: &[u8], block: &[u8], out: &mut [u8]) {
        let cipher = Self::new(key);
        cipher.encrypt_block(block, out);
    }
}

impl BlockCipher for AesSafe128Encryptor {
    fn new(key: &[u8]) -> Self {
        AesSafe128Encryptor::new(key)
    }
}

impl BlockCipher for AesNiEncryptor {
    fn new(key: &[u8]) -> Self {
        AesNiEncryptor::new(KeySize128, key)
    }
}

pub struct BlockOneWay<B: BlockCipher, const N: usize> {
    secret: [u8; N],
    _cipher: PhantomData<B>,
}

impl<B: BlockCipher, const N: usize> BlockOneWay<B, N> {
    pub fn new(secret: [u8; N]) -> Self {
        Self {
            secret,
            _cipher: PhantomData {},
        }
    }
}

impl<B: BlockCipher, const N: usize> OneWay for BlockOneWay<B, N> {
    fn compute(&self, i: usize, input: &[u8], output: &mut [u8]) {
        let ctr = u64::try_from(i)
            .expect("sorry, architecture is not supported")
            .to_be_bytes();
        let mut block = [0; N];
        block[N - ctr.len()..].copy_from_slice(&ctr);
        let mut key = self.secret;
        key.iter_mut().zip(input).for_each(|(a, b)| *a ^= *b);
        B::encrypt(&key, &block, output);
    }
}

pub struct BlockBuilder<B: BlockCipher, const N: usize>(PhantomData<B>);

impl<B: BlockCipher, const N: usize> BlockBuilder<B, N> {
    pub fn new_private(rounds: usize, secret: [u8; N]) -> PrivateKey<BlockOneWay<B, N>, N> {
        PrivateKey::new(BlockOneWay::new(secret), rounds)
    }

    pub fn private_from_password(
        rounds: usize,
        secret: [u8; N],
        pass: [u8; N],
    ) -> PrivateKey<BlockOneWay<B, N>, N> {
        PrivateKey::from_password(BlockOneWay::new(secret), rounds, pass)
    }

    pub fn new_public(secret: [u8; N], password: [u8; N]) -> PublicKey<BlockOneWay<B, N>, N> {
        PublicKey::new(BlockOneWay::new(secret), password)
    }
}

pub type Aes128SafeBuilder = BlockBuilder<AesSafe128Encryptor, 16>;
pub type Aes128NiBuilder = BlockBuilder<AesNiEncryptor, 16>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::State;

    #[test]
    fn normal_protocol() {
        let secret = b"YELLOW SUBMARINE";
        let mut private = Aes128SafeBuilder::new_private(5, *secret);

        let p0 = private.get_password().unwrap();
        assert_eq!(private.pop_password(), State::Ok);

        let mut public = Aes128SafeBuilder::new_public(*secret, p0);

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
