use criterion::{criterion_group, criterion_main, Criterion};
use diploma::hash::{PrivateKeySha256, PublicKeySha256};

fn criterion_benchmark(c: &mut Criterion) {
    let password = [0xde; 32];
    c.bench_function("sha256-hash-login-10000", |b| {
        b.iter(|| PrivateKeySha256::new_from_password(10000, password))
    });

    let private = PrivateKeySha256::new(5);

    let p0 = private.get_password().unwrap();
    let public = PublicKeySha256::new(p0);

    let p1 = private.get_password().unwrap();

    c.bench_function("sha256-hash-verify", |b| b.iter(|| public.verify_dry(&p1)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
