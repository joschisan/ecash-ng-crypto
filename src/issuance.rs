use bitcoin_hashes::{sha256, Hash};
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::thread_rng;
use std::array;
use std::io::Write;

pub fn issuance_homomorphism(
    [m_1, m_2, m_3, r_p, r_m, r_1, r_2, r_3]: [Scalar; 8],
    h: G1Projective,
) -> [G1Projective; 5] {
    let pc = crate::compute_pc(m_1, r_p);
    let c_m = compute_c_m(m_1, m_2, m_3, r_m);
    let c_1 = compute_c_k(m_1, r_1, h);
    let c_2 = compute_c_k(m_2, r_2, h);
    let c_3 = compute_c_k(m_3, r_3, h);

    [pc, c_m, c_1, c_2, c_3]
}

pub fn compute_c_m(m_1: Scalar, m_2: Scalar, m_3: Scalar, r_m: Scalar) -> G1Projective {
    m_1 * crate::generators::gen_ecash_h_1()
        + m_2 * crate::generators::gen_ecash_h_2()
        + m_3 * crate::generators::gen_ecash_h_3()
        + r_m * crate::generators::gen_ecash_g_1()
}

pub fn compute_c_k(m: Scalar, r: Scalar, h: G1Projective) -> G1Projective {
    m * h + r * crate::generators::gen_ecash_g_1()
}

pub fn prove_issuance(
    y: [G1Projective; 5],
    x: [Scalar; 8],
    h: G1Projective,
) -> ([G1Projective; 5], [Scalar; 8]) {
    let r = array::from_fn(|_| Scalar::random(&mut thread_rng()));

    let r_proof = issuance_homomorphism(r, h);

    let challenge = get_challenge_issuance(y, r_proof);

    let s_proof = array::from_fn(|i| r[i] + challenge * x[i]);

    assert!(verify_issuance(y, r_proof, s_proof));

    (r_proof, s_proof)
}

pub fn verify_issuance(y: [G1Projective; 5], r: [G1Projective; 5], s: [Scalar; 8]) -> bool {
    let h = crate::hash::hash_g1_to_g1(y[1]);
    let challenge = get_challenge_issuance(y, r);

    issuance_homomorphism(s, h) == array::from_fn(|i| (challenge * y[i] + r[i]))
}

fn get_challenge_issuance(y: [G1Projective; 5], r: [G1Projective; 5]) -> Scalar {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all("FEDIMINT_ECASH_CHALLENGE_ISSUANCE".as_bytes())
        .expect("Writing to hash engine can't fail");

    for point in y {
        engine
            .write_all(&point.to_affine().to_compressed())
            .expect("Writing to hash engine can't fail");
    }

    for point in r {
        engine
            .write_all(&point.to_affine().to_compressed())
            .expect("Writing to hash engine can't fail");
    }

    let hash = sha256::Hash::from_engine(engine);

    crate::hash::map_to_scalar(&hash)
}

pub fn prepare_issuance(
    m_1: Scalar,
    m_2: Scalar,
    m_3: Scalar,
    r_p: Scalar,
    r_m: Scalar,
    r_1: Scalar,
    r_2: Scalar,
    r_3: Scalar,
) -> ([G1Projective; 5], [G1Projective; 5], [Scalar; 8]) {
    let pc = crate::compute_pc(m_1, r_p);
    let c_m = compute_c_m(m_1, m_2, m_3, r_m);

    let h = crate::hash::hash_g1_to_g1(compute_c_m(m_1, m_2, m_3, r_m));

    let c_1 = compute_c_k(m_1, r_1, h);
    let c_2 = compute_c_k(m_2, r_2, h);
    let c_3 = compute_c_k(m_3, r_3, h);

    let y = [pc, c_m, c_1, c_2, c_3];

    let (r, s) = prove_issuance(y, [m_1, m_2, m_3, r_p, r_m, r_1, r_2, r_3], h);

    (y, r, s)
}
