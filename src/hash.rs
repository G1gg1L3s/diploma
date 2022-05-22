use std::{fmt, marker::PhantomData};

use crypto::{digest::Digest, sha2::Sha256};
use rand::RngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Ok,
    Empty,
}

#[derive(Debug, Clone, Copy)]
pub struct AuthError;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication error")
    }
}

pub trait Hash: Digest {
    fn new() -> Self;
}

impl Hash for Sha256 {
    fn new() -> Self {
        Sha256::new()
    }
}

pub type PrivateKeySha256 = PrivateKey<Sha256, 32>;
pub type PublicKeySha256 = PublicKey<Sha256, 32>;

pub struct PrivateKey<H: Hash, const SIZE: usize> {
    round: usize,
    passwords: Vec<[u8; SIZE]>,
    _digest: PhantomData<H>,
}

impl<H: Hash, const SIZE: usize> PrivateKey<H, SIZE> {
    pub fn new(rounds: usize) -> Self {
        let mut pass = [0; SIZE];
        rand::thread_rng().fill_bytes(&mut pass);
        Self::new_from_password(rounds, pass)
    }

    pub fn new_from_password(rounds: usize, pass: [u8; SIZE]) -> Self {
        let mut counter = rounds;
        let passwords = std::iter::successors(Some(pass), |pass| {
            let ctr = u64::to_be_bytes(counter as u64);
            let mut digest = H::new();
            digest.input(&ctr);
            digest.input(pass);
            let mut result = [0; SIZE];
            digest.result(&mut result);
            counter = counter.checked_sub(1)?;
            Some(result)
        })
        // One additional round for the registation
        .take(rounds + 1)
        .collect::<Vec<_>>();
        Self {
            round: rounds,
            passwords,
            _digest: PhantomData {},
        }
    }

    pub fn get_password(&self) -> Option<[u8; SIZE]> {
        let p = self.passwords.get(self.round).copied();
        p
    }

    #[must_use]
    pub fn pop_password(&mut self) -> State {
        self.passwords.pop();
        if let Some(round) = self.round.checked_sub(1) {
            self.round = round;
            State::Ok
        } else {
            State::Empty
        }
    }

    #[must_use]
    pub fn round(&self) -> usize {
        self.round
    }
}

pub struct PublicKey<H: Hash, const SIZE: usize> {
    round: usize,
    password: [u8; SIZE],
    _digest: PhantomData<H>,
}

impl<H: Hash, const SIZE: usize> PublicKey<H, SIZE> {
    pub fn new(password: [u8; SIZE]) -> Self {
        Self {
            // we already have 0th password, so start with a one
            round: 1,
            password,
            _digest: PhantomData {},
        }
    }

    pub fn verify_dry(&self, password: &[u8; SIZE]) -> Result<(), AuthError> {
        let hash = {
            let ctr = u64::to_be_bytes(self.round as u64);
            let mut d = H::new();
            d.input(&ctr);
            d.input(password);
            let mut out = [0; SIZE];
            d.result(&mut out);
            out
        };

        if crypto::util::fixed_time_eq(&hash, &self.password) {
            Ok(())
        } else {
            Err(AuthError)
        }
    }

    pub fn verify(&mut self, password: &[u8; SIZE]) -> Result<(), AuthError> {
        match self.verify_dry(password) {
            Ok(_) => {
                self.password = *password;
                self.round += 1;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[test]
fn normal_protocol() {
    let mut private = PrivateKey::<Sha256, 32>::new(5);

    let p0 = private.get_password().unwrap();
    assert_eq!(private.pop_password(), State::Ok);

    let mut public = PublicKey::<Sha256, 32>::new(p0);

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
