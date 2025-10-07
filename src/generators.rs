use std::sync::LazyLock;

use bls12_381::{G1Projective, G2Projective};

static PEDERSEN_G: LazyLock<G1Projective> = LazyLock::new(|| gen_pedersen_g());

static PEDERSEN_H: LazyLock<G1Projective> = LazyLock::new(|| gen_pedersen_h());

static ECASH_G1: LazyLock<G1Projective> = LazyLock::new(|| gen_ecash_g1());

static ECASH_G2: LazyLock<G2Projective> = LazyLock::new(|| gen_ecash_g2());

static ECASH_H1: LazyLock<G1Projective> = LazyLock::new(|| gen_ecash_h1());

static ECASH_H2: LazyLock<G1Projective> = LazyLock::new(|| gen_ecash_h2());

static ECASH_H3: LazyLock<G1Projective> = LazyLock::new(|| gen_ecash_h3());

fn gen_pedersen_g() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_PEDERSEN_G".as_bytes())
}

fn gen_pedersen_h() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_PEDERSEN_H".as_bytes())
}

fn gen_ecash_g1() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_G1".as_bytes())
}

fn gen_ecash_g2() -> G2Projective {
    crate::hash::hash_to_g2("FEDIMINT_GENERATOR_ECASH_G2".as_bytes())
}

fn gen_ecash_h1() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_H1".as_bytes())
}

fn gen_ecash_h2() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_H2".as_bytes())
}

fn gen_ecash_h3() -> G1Projective {
    crate::hash::hash_to_g1("FEDIMINT_GENERATOR_ECASH_H3".as_bytes())
}

pub fn pedersen_g() -> G1Projective {
    *PEDERSEN_G
}

pub fn pedersen_h() -> G1Projective {
    *PEDERSEN_H
}

pub fn ecash_g1() -> G1Projective {
    *ECASH_G1
}

pub fn ecash_g2() -> G2Projective {
    *ECASH_G2
}

pub fn ecash_h1() -> G1Projective {
    *ECASH_H1
}

pub fn ecash_h2() -> G1Projective {
    *ECASH_H2
}

pub fn ecash_h3() -> G1Projective {
    *ECASH_H3
}
