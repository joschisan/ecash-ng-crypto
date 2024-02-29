use bls12_381::{G1Projective, G2Projective};

pub fn gen_pedersen_g() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_PEDERSEN_G".as_bytes())
}

pub fn gen_pedersen_h() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_PEDERSEN_H".as_bytes())
}

pub fn gen_ecash_g_1() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_G1".as_bytes())
}

pub fn gen_ecash_g_2() -> G2Projective {
    crate::hash::hash_to_g2("FEDIMINT_GENERATOR_ECASH_G2".as_bytes())
}

pub fn gen_ecash_h_1() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_H1".as_bytes())
}

pub fn gen_ecash_h_2() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_H2".as_bytes())
}

pub fn gen_ecash_h_3() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_H3".as_bytes())
}
