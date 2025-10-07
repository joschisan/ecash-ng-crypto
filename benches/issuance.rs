use bitcoin_hashes::{sha256, Hash};
use bls12_381::Scalar;
use ecash_ng_crypto::IssuanceRequest;
use ff::Field;
use rand::thread_rng;

fn main() {
    divan::main();
}

#[divan::bench]
fn issuance_prepare(bencher: divan::Bencher) {
    bencher.bench(|| {
        IssuanceRequest::new(
            1000,
            sha256::Hash::hash(&[0; 32]),
            Scalar::random(&mut thread_rng()),
        )
        .prepare_issuance()
    });
}

#[divan::bench]
fn issuance_verify(bencher: divan::Bencher) {
    let request = IssuanceRequest::new(
        1000,
        sha256::Hash::hash(&[0; 32]),
        Scalar::random(&mut thread_rng()),
    )
    .prepare_issuance();

    bencher.bench(|| request.verify());
}
