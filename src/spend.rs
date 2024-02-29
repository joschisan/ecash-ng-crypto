use bitcoin_hashes::{sha256, Hash};
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::thread_rng;
use std::array;
use std::io::Write;

fn spend_homomorphism(
    [m_1, m_2, r_p]: [Scalar; 3],
    pk: [G2Projective; 4],
) -> (G1Projective, G2Projective) {
    let p = crate::compute_pc(m_1, r_p);
    let k = compute_k(m_1, m_2, pk);

    (p, k)
}

pub fn compute_k(m_1: Scalar, m_2: Scalar, pk: [G2Projective; 4]) -> G2Projective {
    (m_1 * pk[1]) + (m_2 * pk[2])
}

pub fn prove_spend(
    y: (G1Projective, G2Projective),
    x: [Scalar; 3],
    pk: [G2Projective; 4],
) -> ((G1Projective, G2Projective), [Scalar; 3]) {
    let r = array::from_fn(|_| Scalar::random(&mut thread_rng()));

    let r_proof = spend_homomorphism(r, pk);

    let challenge = get_challenge_spend(y, r_proof);

    let s_proof = array::from_fn(|i| r[i] + challenge * x[i]);

    assert!(verify_spend(y, r_proof, s_proof, pk));

    (r_proof, s_proof)
}

pub fn verify_spend(
    y: (G1Projective, G2Projective),
    r: (G1Projective, G2Projective),
    s: [Scalar; 3],
    pk: [G2Projective; 4],
) -> bool {
    let challenge = get_challenge_spend(y, r);

    spend_homomorphism(s, pk) == ((challenge * y.0 + r.0), (challenge * y.1 + r.1))
}

fn get_challenge_spend(
    (y_p, y_k): (G1Projective, G2Projective),
    (r_p, r_k): (G1Projective, G2Projective),
) -> Scalar {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all("FEDIMINT_ECASH_CHALLENGE_SPEND".as_bytes())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&y_p.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&y_k.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&r_p.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    engine
        .write_all(&r_k.to_affine().to_compressed())
        .expect("Writing to hash engine can't fail");

    let hash = sha256::Hash::from_engine(engine);

    crate::hash::map_to_scalar(&hash)
}

pub fn prepare_spend(
    m_1: Scalar,
    m_2: Scalar,
    r_p: Scalar,
    pk: [G2Projective; 4],
) -> (
    (G1Projective, G2Projective),
    (G1Projective, G2Projective),
    [Scalar; 3],
) {
    let y = spend_homomorphism([m_1, m_2, r_p], pk);

    let (r, s) = prove_spend(y, [m_1, m_2, r_p], pk);

    (y, r, s)
}
