use criterion::{black_box, criterion_group, criterion_main, Criterion};
use diploma::{
    cipher::{Aes128NiBuilder, Aes128SafeBuilder},
    commitment::{
        aes::{Aes128NiEncryptor, Aes128SafeEncryptor},
        ed25519::Ed25519,
        hash::Sha256,
        PrivateKey, PublicKey,
    },
    hash::Sha256Builder,
};

fn register(c: &mut Criterion) {
    let mut group = c.benchmark_group("register");
    let password = [0xde; 32];
    group.bench_function("sha256-10000", |b| {
        b.iter(|| Sha256Builder::private_from_password(10000, password))
    });

    let password = [0xde; 16];
    let secret = [0xad; 16];

    group.bench_function("aes128-software-10000", |b| {
        b.iter(|| Aes128SafeBuilder::private_from_password(10000, secret, password))
    });
    group.bench_function("aes128-hardware-10000", |b| {
        b.iter(|| Aes128NiBuilder::private_from_password(10000, secret, password))
    });
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    let private = Sha256Builder::new_private(5);
    let p0 = private.get_password().unwrap();
    let public = Sha256Builder::new_public(p0);
    let p1 = private.get_password().unwrap();

    group.bench_function("sha256", |b| b.iter(|| public.verify_dry(&p1)));

    let secret = [0xad; 16];

    let private = Aes128SafeBuilder::new_private(5, secret);

    let p0 = private.get_password().unwrap();
    let public = Aes128SafeBuilder::new_public(secret, p0);

    let p1 = private.get_password().unwrap();

    group.bench_function("aes128-software", |b| b.iter(|| public.verify_dry(&p1)));

    let private = Aes128NiBuilder::new_private(5, secret);

    let p0 = private.get_password().unwrap();
    let public = Aes128NiBuilder::new_public(secret, p0);

    let p1 = private.get_password().unwrap();

    group.bench_function("aes128-hardware", |b| b.iter(|| public.verify_dry(&p1)));
}

fn commitment_register(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment/register");

    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let private = PrivateKey::new(Ed25519);
            let public = PublicKey::new(Ed25519, private.public());
            black_box(public);
        })
    });

    group.bench_function("aes128safe", |b| {
        b.iter(|| {
            let private = PrivateKey::new(Aes128SafeEncryptor);
            let public = PublicKey::new(Aes128SafeEncryptor, private.public());
            black_box(public);
        })
    });

    group.bench_function("aes128ni", |b| {
        b.iter(|| {
            let private = PrivateKey::new(Aes128NiEncryptor);
            let public = PublicKey::new(Aes128NiEncryptor, private.public());
            black_box(public);
        })
    });

    group.bench_function("sha256", |b| {
        b.iter(|| {
            let private = PrivateKey::new(Sha256);
            let public = PublicKey::new(Sha256, private.public());
            black_box(public);
        })
    });
}

fn commitment_login(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment/login");

    let mut private = PrivateKey::new(Ed25519);
    let mut public = PublicKey::new(Ed25519, private.public());
    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let reveal = private.private();
            public.verify(&reveal);

            private.advance();
            public.advance(private.public());
        })
    });

    let mut private = PrivateKey::new(Aes128SafeEncryptor);
    let mut public = PublicKey::new(Aes128SafeEncryptor, private.public());

    group.bench_function("aes128safe", |b| {
        b.iter(|| {
            let reveal = private.private();
            public.verify(&reveal);

            private.advance();
            public.advance(private.public());
        })
    });

    let mut private = PrivateKey::new(Aes128NiEncryptor);
    let mut public = PublicKey::new(Aes128NiEncryptor, private.public());

    group.bench_function("aes128ni", |b| {
        b.iter(|| {
            let reveal = private.private();
            public.verify(&reveal);

            private.advance();
            public.advance(private.public());
        })
    });

    let mut private = PrivateKey::new(Sha256);
    let mut public = PublicKey::new(Sha256, private.public());

    group.bench_function("sha256", |b| {
        b.iter(|| {
            let reveal = private.private();
            public.verify(&reveal);

            private.advance();
            public.advance(private.public());
        })
    });
}

criterion_group!(
    benches,
    register,
    verify,
    commitment_register,
    commitment_login
);
criterion_main!(benches);
