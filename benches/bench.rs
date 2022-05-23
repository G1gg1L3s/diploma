use criterion::{criterion_group, criterion_main, Criterion};
use diploma::{
    cipher::{Aes128NiBuilder, Aes128SafeBuilder},
    hash::Sha256Builder,
};

fn sha256(c: &mut Criterion) {
    let password = [0xde; 32];
    c.bench_function("sha256-hash-login-10000", |b| {
        b.iter(|| Sha256Builder::private_from_password(10000, password))
    });

    let private = Sha256Builder::new_private(5);

    let p0 = private.get_password().unwrap();
    let public = Sha256Builder::new_public(p0);

    let p1 = private.get_password().unwrap();

    c.bench_function("sha256-hash-verify", |b| b.iter(|| public.verify_dry(&p1)));
}

fn aes128_safe(c: &mut Criterion) {
    let password = [0xde; 16];
    let secret = [0xad; 16];
    c.bench_function("aes128-software-hash-login-10000", |b| {
        b.iter(|| Aes128SafeBuilder::private_from_password(10000, secret, password))
    });

    let private = Aes128SafeBuilder::new_private(5, secret);

    let p0 = private.get_password().unwrap();
    let public = Aes128SafeBuilder::new_public(secret, p0);

    let p1 = private.get_password().unwrap();

    c.bench_function("aes128-software-hash-verify", |b| {
        b.iter(|| public.verify_dry(&p1))
    });
}

fn aes128_ni(c: &mut Criterion) {
    let password = [0xde; 16];
    let secret = [0xad; 16];
    c.bench_function("aes128-hardware-hash-login-10000", |b| {
        b.iter(|| Aes128NiBuilder::private_from_password(10000, secret, password))
    });

    let private = Aes128NiBuilder::new_private(5, secret);

    let p0 = private.get_password().unwrap();
    let public = Aes128NiBuilder::new_public(secret, p0);

    let p1 = private.get_password().unwrap();

    c.bench_function("aes128-hardware-hash-verify", |b| {
        b.iter(|| public.verify_dry(&p1))
    });
}

criterion_group!(benches, sha256, aes128_safe, aes128_ni);
criterion_main!(benches);
