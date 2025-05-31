use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use peochain_validator_bond::{
    utils::threshold_crypto::{ThresholdCrypto, ThresholdParams, KeyShare, SignatureShare},
    models::subnet::ValidatorSet,
};
use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use rand::thread_rng;
use std::time::Duration;

fn generate_key_shares(threshold: usize, total: usize) -> Vec<KeyShare> {
    let params = ThresholdParams { threshold, total_participants: total };
    let mut rng = thread_rng();
    
    // Generate a random polynomial
    let mut polynomial = vec![Fr::rand(&mut rng); threshold];
    
    // Generate verification vector
    let verification_vector: Vec<_> = polynomial.iter()
        .map(|coeff| (ark_bls12_381::G1Affine::generator() * coeff).into_affine())
        .collect();
    
    // Generate key shares
    (0..total).map(|i| {
        let x = Fr::from((i + 1) as u64);
        let mut share = Fr::zero();
        let mut x_pow = Fr::one();
        
        for coeff in &polynomial {
            share += *coeff * x_pow;
            x_pow *= x;
        }
        
        KeyShare {
            index: i + 1,
            secret_share: share,
            public_share: (ark_bls12_381::G1Affine::generator() * share).into_affine(),
            verification_vector: verification_vector.clone(),
        }
    }).collect()
}

fn generate_signature_shares(
    message: &[u8],
    key_shares: &[KeyShare],
    count: usize,
) -> Vec<SignatureShare> {
    key_shares[..count].iter()
        .map(|key_share| {
            let hash = ThresholdCrypto::hash_to_g2(message);
            let signature_share = hash * key_share.secret_share;
            
            SignatureShare {
                index: key_share.index,
                share: signature_share.into_affine(),
                cached_bytes: None,
            }
        })
        .collect()
}

fn benchmark_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate_signature_shares");
    
    // Test with different threshold sizes
    for &threshold in [5, 10, 20, 50, 100].iter() {
        let total = threshold * 2; // 2x threshold for safety margin
        let key_shares = generate_key_shares(threshold, total);
        let message = b"benchmark_message";
        
        // Generate signature shares for the minimum required threshold
        let signature_shares = generate_signature_shares(message, &key_shares, threshold);
        
        group.throughput(Throughput::Elements(threshold as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("threshold_{}", threshold)),
            &(signature_shares, message),
            |b, (shares, msg)| {
                b.iter(|| {
                    ThresholdCrypto::aggregate_signature_shares(
                        &ThresholdParams { threshold, total_participants: total },
                        msg,
                        shares,
                    ).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(2));
    targets = benchmark_aggregation
}

criterion_main!(benches);
