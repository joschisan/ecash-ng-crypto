#![allow(dead_code)]
mod generators;
mod hash;
mod issuance;
mod spend;

use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::thread_rng;
use std::collections::BTreeMap;

use crate::hash::hash_g1_to_g1;
use crate::hash::map_to_scalar;
use crate::issuance::compute_c_m;
use crate::issuance::prepare_issuance;
use crate::issuance::verify_issuance;
use crate::spend::compute_k;
use crate::spend::prepare_spend;
use crate::spend::verify_spend;

use bitcoin_hashes::sha256;

pub struct AggregatePublicKey {
    g1: [G1Projective; 4],
    g2: [G2Projective; 4],
}

pub struct PublicKeyShare {
    g1: [G1Projective; 4],
    g2: [G2Projective; 4],
}

pub struct SecretKeyShare([Scalar; 4]);

pub struct SignatureShare(G1Projective);

pub struct Signature(G1Projective);

pub struct IssuanceRequest {
    m_1: Scalar,
    m_2: Scalar,
    m_3: Scalar,
    r_p: Scalar,
    r_m: Scalar,
    r_1: Scalar,
    r_2: Scalar,
    r_3: Scalar,
}

impl IssuanceRequest {
    pub fn new(amount: u64, authentication: sha256::Hash, r_p: Scalar) -> Self {
        let m_1 = Scalar::from(amount);
        let m_2 = Scalar::random(&mut thread_rng());
        let m_3 = map_to_scalar(&authentication);

        let r_m = Scalar::random(&mut thread_rng());
        let r_1 = Scalar::random(&mut thread_rng());
        let r_2 = Scalar::random(&mut thread_rng());
        let r_3 = Scalar::random(&mut thread_rng());

        IssuanceRequest {
            m_1,
            m_2,
            m_3,
            r_p,
            r_m,
            r_1,
            r_2,
            r_3,
        }
    }

    fn compute_h(&self) -> G1Projective {
        hash_g1_to_g1(compute_c_m(self.m_1, self.m_2, self.m_3, self.r_m))
    }

    pub fn prepare_issuance(&self) -> Issuance {
        let (y, r, s) = prepare_issuance(
            self.m_1, self.m_2, self.m_3, self.r_p, self.r_m, self.r_1, self.r_2, self.r_3,
        );

        assert_eq!(hash_g1_to_g1(y[1]), self.compute_h());

        Issuance { y, r, s }
    }

    pub fn verify_blind_signature_share(
        &self,
        pk: &PublicKeyShare,
        signature: &SignatureShare,
    ) -> bool {
        self.verify_signature(&pk.g2, &self.unblind_signature(&pk.g1, &signature.0))
    }

    pub fn verify_blind_signature(&self, pk: &AggregatePublicKey, signature: &Signature) -> bool {
        self.verify_signature(&pk.g2, &self.unblind_signature(&pk.g1, &signature.0))
    }

    fn unblind_signature(&self, g1: &[G1Projective; 4], signature: &G1Projective) -> G1Projective {
        signature - blinding_factor(g1, self.r_1, self.r_2, self.r_3)
    }

    fn verify_signature(&self, g2: &[G2Projective; 4], signature: &G1Projective) -> bool {
        let message = compute_message(g2, self.m_1, self.m_2, self.m_3);

        verify(message, self.compute_h(), *signature)
    }

    pub fn finalize_issuance(
        &self,
        pk: &AggregatePublicKey,
        signature: &Signature,
    ) -> SpendRequest {
        let signature = self.unblind_signature(&pk.g1, &signature.0);

        assert!(self.verify_signature(&pk.g2, &signature));

        let r = Scalar::random(&mut thread_rng());

        let h = r * self.compute_h();
        let signature = r * signature;

        SpendRequest {
            m_2: self.m_2,
            h,
            signature,
        }
    }
}

pub struct Issuance {
    y: [G1Projective; 5],
    r: [G1Projective; 5],
    s: [Scalar; 8],
}

impl Issuance {
    pub fn verify(&self) -> bool {
        verify_issuance(self.y, self.r, self.s)
    }

    pub fn amount_commitment(&self) -> G1Projective {
        self.y[0]
    }

    pub fn sign(&self, secret_key: &SecretKeyShare) -> SignatureShare {
        let h = hash_g1_to_g1(self.y[1]);

        SignatureShare(sign_blinded_message(
            secret_key.0,
            h,
            self.y[2],
            self.y[3],
            self.y[4],
        ))
    }
}

pub struct SpendRequest {
    m_2: Scalar,
    h: G1Projective,
    signature: G1Projective,
}

impl SpendRequest {
    pub fn verify(&self, pk: &AggregatePublicKey, amount: u64, auth: sha256::Hash) -> bool {
        let m_1 = Scalar::from(amount);
        let m_3 = map_to_scalar(&auth);

        let message = pk.g2[0] + compute_k(m_1, self.m_2, pk.g2) + m_3 * pk.g2[3];

        verify(message, self.h, self.signature)
    }

    pub fn prepare_spend(&self, pk: &AggregatePublicKey, amount: u64, r_p: Scalar) -> Spend {
        let m_1 = Scalar::from(amount);

        let (y, r, s) = prepare_spend(m_1, self.m_2, r_p, pk.g2);

        Spend {
            y,
            r,
            s,
            h: self.h,
            signature: self.signature,
        }
    }
}

pub struct Spend {
    y: (G1Projective, G2Projective),
    r: (G1Projective, G2Projective),
    s: [Scalar; 3],
    h: G1Projective,
    signature: G1Projective,
}

impl Spend {
    fn verify(&self, pk: AggregatePublicKey, authentication: sha256::Hash) -> bool {
        let message = pk.g2[0] + self.y.1 + map_to_scalar(&authentication) * pk.g2[3];

        verify_spend(self.y, self.r, self.s, pk.g2) && verify(message, self.h, self.signature)
    }

    fn amount_commitment(&self) -> G1Projective {
        self.y.0
    }
}

fn compute_pc(m: Scalar, r: Scalar) -> G1Projective {
    m * generators::pedersen_g() + r * generators::pedersen_h()
}

fn compute_blinding_factor(
    pk: [G1Projective; 4],
    r_1: Scalar,
    r_2: Scalar,
    r_3: Scalar,
) -> G1Projective {
    (r_1 * pk[1]) + (r_2 * pk[2]) + (r_3 * pk[3])
}

fn sign_blinded_message(
    sk: [Scalar; 4],
    h: G1Projective,
    c_1: G1Projective,
    c_2: G1Projective,
    c_3: G1Projective,
) -> G1Projective {
    sk[0] * h + sk[1] * c_1 + sk[2] * c_2 + sk[3] * c_3
}

fn blinding_factor(pk: &[G1Projective; 4], r_1: Scalar, r_2: Scalar, r_3: Scalar) -> G1Projective {
    r_1 * pk[1] + r_2 * pk[2] + r_3 * pk[3]
}

fn compute_message(pk: &[G2Projective; 4], m_1: Scalar, m_2: Scalar, m_3: Scalar) -> G2Projective {
    pk[0] + m_1 * pk[1] + m_2 * pk[2] + m_3 * pk[3]
}

fn verify(message: G2Projective, h: G1Projective, s: G1Projective) -> bool {
    let p_m = pairing(&h.to_affine(), &message.to_affine());
    let p_s = pairing(&s.to_affine(), &generators::ecash_g2().to_affine());

    p_m == p_s
}

pub fn aggregate_signature_shares(shares: &BTreeMap<u64, SignatureShare>) -> Signature {
    Signature(
        lagrange_multipliers(shares.keys().cloned().map(Scalar::from).collect())
            .into_iter()
            .zip(shares.values())
            .map(|(lagrange_multiplier, share)| lagrange_multiplier * share.0)
            .reduce(|a, b| a + b)
            .expect("We have at least one share"),
    )
}

fn lagrange_multipliers(scalars: Vec<Scalar>) -> Vec<Scalar> {
    scalars
        .iter()
        .map(|i| {
            scalars
                .iter()
                .filter(|j| *j != i)
                .map(|j| j * (j - i).invert().expect("We filtered the case j == i"))
                .reduce(|a, b| a * b)
                .expect("We have at least one share")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::aggregate_signature_shares;
    use crate::generators::{ecash_g1, ecash_g2};
    use bitcoin_hashes::sha256;
    use bitcoin_hashes::Hash;
    use bls12_381::Scalar;
    use ff::Field;
    use rand::thread_rng;
    use std::array;
    use std::collections::BTreeMap;

    use crate::AggregatePublicKey;
    use crate::IssuanceRequest;
    use crate::PublicKeyShare;
    use crate::SecretKeyShare;
    use crate::SignatureShare;

    fn dealer_keygen(
        threshold: usize,
        keys: usize,
    ) -> (AggregatePublicKey, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
        let polys: [Vec<Scalar>; 4] = array::from_fn(|_| random_polynomial(threshold));

        let g1 = polys
            .clone()
            .map(|p| ecash_g1() * evaluate(&p, &Scalar::zero()));

        let g2 = polys
            .clone()
            .map(|p| ecash_g2() * evaluate(&p, &Scalar::zero()));

        let apk = AggregatePublicKey { g1, g2 };

        let sks = (0..keys)
            .map(|idx| {
                SecretKeyShare(
                    polys
                        .clone()
                        .map(|p| evaluate(&p, &Scalar::from(idx as u64 + 1))),
                )
            })
            .collect::<Vec<SecretKeyShare>>();

        let pks = sks
            .iter()
            .map(|sk| PublicKeyShare {
                g1: sk.0.map(|s| (ecash_g1() * s)),
                g2: sk.0.map(|s| (ecash_g2() * s)),
            })
            .collect::<Vec<PublicKeyShare>>();

        (apk, pks, sks)
    }

    fn random_polynomial(degree: usize) -> Vec<Scalar> {
        (0..degree)
            .map(|_| Scalar::random(&mut thread_rng()))
            .collect()
    }

    fn evaluate(coefficients: &[Scalar], x: &Scalar) -> Scalar {
        coefficients
            .iter()
            .cloned()
            .rev()
            .reduce(|acc, coefficient| acc * x + coefficient)
            .expect("We have at least one coefficient")
    }

    #[test]
    fn test_roundtrip() {
        let amount = 1000;
        let auth = sha256::Hash::hash("authentication".as_bytes());

        let issuance_request =
            IssuanceRequest::new(amount, auth, Scalar::random(&mut thread_rng()));

        let issuance = issuance_request.prepare_issuance();

        assert!(issuance.verify());

        let (apk, pks, sks) = dealer_keygen(5, 7);

        let signature_shares = sks
            .iter()
            .map(|sk| issuance.sign(sk))
            .collect::<Vec<SignatureShare>>();

        for (pk, share) in pks.iter().zip(signature_shares.iter()) {
            assert!(issuance_request.verify_blind_signature_share(pk, &share));
        }

        let signature_shares = (1_u64..)
            .zip(signature_shares)
            .take(5)
            .collect::<BTreeMap<u64, SignatureShare>>();

        let signature = aggregate_signature_shares(&signature_shares);

        assert!(issuance_request.verify_blind_signature(&apk, &signature));

        let spend_request = issuance_request.finalize_issuance(&apk, &signature);

        assert!(spend_request.verify(&apk, amount, auth));

        let r_p = Scalar::random(&mut thread_rng());

        let spend = spend_request.prepare_spend(&apk, amount, r_p);

        assert!(spend.verify(apk, auth));
    }

    #[test]
    fn test_issuance_timing() {
        use std::time::Instant;

        let amount = 1000;
        let auth = sha256::Hash::hash("authentication".as_bytes());

        let issuance_request =
            IssuanceRequest::new(amount, auth, Scalar::random(&mut thread_rng()));

        let issuance = issuance_request.prepare_issuance();

        // Time issuance verify
        let start = Instant::now();
        let verify_result = issuance.verify();
        let verify_duration = start.elapsed();
        assert!(verify_result);
        println!("Issuance verify took: {:?}", verify_duration);

        // Generate keys for signing
        let (_, _, sks) = dealer_keygen(5, 7);
        let sk = &sks[0];

        // Time issuance sign
        let start = Instant::now();
        let signature = issuance.sign(sk);
        let sign_duration = start.elapsed();
        println!("Issuance sign took: {:?}", sign_duration);

        // Verify the signature was created
        assert_ne!(signature.0, bls12_381::G1Projective::identity());
    }
}
