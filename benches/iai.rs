use diploma::commitment::{
    aes::{Aes128NiEncryptor, Aes128SafeEncryptor},
    ed25519::Ed25519,
    hash::Sha256,
    PrivateKey, PublicKey,
};
use iai::black_box;

fn commitment_register_ed25519() {
    let private = PrivateKey::new(Ed25519);
    let public = PublicKey::new(Ed25519, private.public());
    black_box(public);
}

fn commitment_register_aes128safe() {
    let private = PrivateKey::new(Aes128SafeEncryptor);
    let public = PublicKey::new(Aes128SafeEncryptor, private.public());
    black_box(public);
}

fn commitment_register_aes128ni() {
    let private = PrivateKey::new(Aes128NiEncryptor);
    let public = PublicKey::new(Aes128NiEncryptor, private.public());
    black_box(public);
}

fn commitment_register_sha256() {
    let private = PrivateKey::new(Sha256);
    let public = PublicKey::new(Sha256, private.public());
    black_box(public);
}
iai::main!(
    commitment_register_ed25519,
    commitment_register_aes128safe,
    commitment_register_aes128ni,
    commitment_register_sha256
);
