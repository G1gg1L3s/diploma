use criterion::{criterion_group, criterion_main, Criterion};
use diploma::{
    cipher::{Aes128NiBuilder, Aes128SafeBuilder},
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

criterion_group!(benches, register, verify);
criterion_main!(benches);
