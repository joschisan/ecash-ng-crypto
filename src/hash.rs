use bitcoin_hashes::{sha256, Hash};
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    map_to_scalar(&sha256::Hash::hash(bytes))
}

pub fn hash_to_g1(bytes: &[u8]) -> G1Projective {
    map_to_g1(&sha256::Hash::hash(bytes))
}

pub fn hash_to_g2(bytes: &[u8]) -> G2Projective {
    map_to_g2(&sha256::Hash::hash(bytes))
}

pub fn map_to_scalar(hash: &sha256::Hash) -> Scalar {
    Scalar::random(&mut ChaChaRng::from_seed(hash.into_inner()))
}

fn map_to_g1(hash: &sha256::Hash) -> G1Projective {
    G1Projective::random(&mut ChaChaRng::from_seed(hash.into_inner()))
}

fn map_to_g2(hash: &sha256::Hash) -> G2Projective {
    G2Projective::random(&mut ChaChaRng::from_seed(hash.into_inner()))
}

pub fn hash_g1_to_g1(c_m: G1Projective) -> G1Projective {
    hash_to_g1(c_m.to_affine().to_compressed().as_slice())
}
