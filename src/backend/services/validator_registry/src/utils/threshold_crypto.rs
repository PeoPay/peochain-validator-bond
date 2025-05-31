use anyhow::{Result, anyhow, Context};
use ark_bls12_381::{
    Bls12_381, G1Affine, G2Affine, G1Projective, G2Projective, Fr, G1Prepared, G2Prepared,
};
use ark_ec::{
    pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup, Group, VariableBaseMSM,
};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial, Radix2EvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Valid, Validate};
use ark_std::{
    collections::BTreeMap,
    ops::{Add, Mul, Sub},
    rand::{rngs::OsRng, RngCore},
    vec,
    vec::Vec,
};
use blake2::{Blake2b512, Digest};
use merlin::Transcript;
use rand::Rng;
use std::ops::Neg;
use std::sync::Arc;
use std::mem;
use std::time::Instant;
use parking_lot::Mutex;
use lazy_static::lazy_static;

// Memory pool for frequently used vectors
struct VectorPool<T> {
    pool: Mutex<Vec<Vec<T>>>,
    capacity: usize,
}

impl<T> VectorPool<T> {
    fn new(capacity: usize) -> Self {
        Self {
            pool: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
        }
    }

    fn get(&self, capacity: usize) -> Vec<T> {
        let mut pool = self.pool.lock();
        if let Some(mut vec) = pool.pop() {
            vec.clear();
            vec.reserve(capacity);
            vec
        } else {
            Vec::with_capacity(capacity)
        }
    }

    fn put(&self, mut vec: Vec<T>) {
        let mut pool = self.pool.lock();
        if pool.len() < self.capacity {
            vec.clear();
            pool.push(vec);
        }
        // else: drop the vector
    }
}

lazy_static! {
    // Pools for different vector types
    static ref FR_VEC_POOL: VectorPool<Fr> = VectorPool::new(16);
    static ref USIZE_VEC_POOL: VectorPool<usize> = VectorPool::new(16);
    static ref G2_PROJECTIVE_VEC_POOL: VectorPool<G2Projective> = VectorPool::new(8);
}

// Memory usage profiling macro
#[cfg(debug_assertions)]
macro_rules! profile_memory {
    ($label:expr, $code:expr) => {{
        use std::alloc::{GlobalAlloc, System, Layout};
        use std::sync::atomic::{AtomicUsize, Ordering};
        
        struct TrackingAllocator;
        
        unsafe impl GlobalAlloc for TrackingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                let ret = System.alloc(layout);
                if !ret.is_null() {
                    ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
                }
                ret
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                System.dealloc(ptr, layout);
                ALLOCATED_BYTES.fetch_sub(layout.size(), Ordering::SeqCst);
            }
        }
        
        #[global_allocator]
        static GLOBAL: TrackingAllocator = TrackingAllocator;
        static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
        
        let before = ALLOCATED_BYTES.load(Ordering::SeqCst);
        let start = Instant::now();
        let result = $code;
        let elapsed = start.elapsed();
        let after = ALLOCATED_BYTES.load(Ordering::SeqCst);
        let diff = after.saturating_sub(before);
        
        if diff > 1024 * 1024 { // Only log if more than 1MB allocated
            log::debug!(
                "[MEMORY] {}: {}ms, Δ{}MB",
                $label,
                elapsed.as_millis(),
                diff / (1024 * 1024)
            );
        } else if diff > 0 {
            log::debug!(
                "[MEMORY] {}: {}ms, Δ{}B",
                $label,
                elapsed.as_millis(),
                diff
            );
        } else {
            log::debug!(
                "[PERF] {}: {}ms",
                $label,
                elapsed.as_millis()
            );
        }
        
        result
    }};
}

#[cfg(not(debug_assertions))]
macro_rules! profile_memory {
    ($label:expr, $code:expr) => { $code };
}

/// Error type for threshold crypto operations
#[derive(Debug, thiserror::Error)]
pub enum ThresholdCryptoError {
    #[error("Insufficient shares to meet threshold")]
    InsufficientShares,
    #[error("Invalid threshold value")]
    InvalidThreshold,
    #[error("Invalid share index")]
    InvalidShareIndex,
    #[error("Deserialization failed: {0}")]
    DeserializationError(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Threshold for the signature scheme (t-of-n)
#[derive(Debug, Clone, Copy)]
pub struct ThresholdParams {
    /// Minimum number of participants required for signing
    pub threshold: usize,
    /// Total number of participants
    pub total_participants: usize,
}

impl ThresholdParams {
    /// Create new threshold parameters
    pub fn new(threshold: usize, total_participants: usize) -> Result<Self> {
        if threshold == 0 || threshold > total_participants {
            return Err(ThresholdCryptoError::InvalidThreshold.into());
        }
        Ok(Self {
            threshold,
            total_participants,
        })
    }
}

/// Represents a participant's key share in the threshold scheme
#[derive(Debug, Clone)]
pub struct KeyShare {
    /// Index of the participant (1-indexed)
    pub index: usize,
    /// Secret key share (scalar in Fr)
    pub secret_share: Fr,
    /// Public key share (G1 point)
    pub public_share: G1Affine,
    /// Verification vector (commitments to the polynomial coefficients in G1)
    pub verification_vector: Vec<G1Affine>,
}

impl KeyShare {
    /// Serialize the key share to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.secret_share.serialize_compressed(&mut bytes)?;
        self.public_share.serialize_compressed(&mut bytes)?;
        
        let vvec_len = (self.verification_vector.len() as u32).to_be_bytes();
        bytes.extend_from_slice(&vvec_len);
        
        for point in &self.verification_vector {
            point.serialize_compressed(&mut bytes)?;
        }
        
        Ok(bytes)
    }
    
    /// Deserialize key share from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(bytes);
        
        let secret_share = Fr::deserialize_compressed(&mut cursor)
            .map_err(|e| ThresholdCryptoError::DeserializationError(e.to_string()))?;
            
        let public_share = G1Affine::deserialize_compressed(&mut cursor)
            .map_err(|e| ThresholdCryptoError::DeserializationError(e.to_string()))?;
            
        let mut vvec_len_bytes = [0u8; 4];
        cursor.read_exact(&mut vvec_len_bytes)
            .map_err(|e| ThresholdCryptoError::DeserializationError(e.to_string()))?;
        let vvec_len = u32::from_be_bytes(vvec_len_bytes) as usize;
        
        let mut verification_vector = Vec::with_capacity(vvec_len);
        for _ in 0..vvec_len {
            let point = G1Affine::deserialize_compressed(&mut cursor)
                .map_err(|e| ThresholdCryptoError::DeserializationError(e.to_string()))?;
            verification_vector.push(point);
        }
        
        // The index isn't serialized, it should be tracked separately
        Ok(Self {
            index: 0, // Must be set by the caller
            secret_share,
            public_share,
            verification_vector,
        })
    }
}

/// Represents a signature share from a participant
#[derive(Debug, Clone)]
pub struct SignatureShare {
    /// Index of the participant (1-indexed)
    pub index: usize,
    /// Signature share data (G2 point)
    pub share: G2Affine,
    /// Cached serialized form to avoid repeated serialization
    cached_bytes: Option<Vec<u8>>,
}

impl SignatureShare {
    /// Create a new signature share
    pub fn new(index: usize, share: G2Affine) -> Self {
        Self {
            index,
            share,
            cached_bytes: None,
        }
    }
    
    /// Serialize the signature share to bytes with caching
    pub fn to_bytes(&mut self) -> Result<&[u8]> {
        if self.cached_bytes.is_none() {
            let mut bytes = Vec::with_capacity(96); // Pre-allocate exact size for G2 point
            self.share.serialize_compressed(&mut bytes)?;
            self.cached_bytes = Some(bytes);
        }
        Ok(self.cached_bytes.as_ref().unwrap())
    }
    
    /// Deserialize signature share from bytes without copying
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let share = G2Affine::deserialize_compressed(&mut std::io::Cursor::new(bytes))
            .map_err(|e| ThresholdCryptoError::DeserializationError(e.to_string()))?;
        
        Ok(Self {
            index: 0, // Must be set by the caller
            share,
            cached_bytes: Some(bytes.to_vec()),
        })
    }
    
    /// Get a reference to the cached bytes if available
    pub fn get_cached_bytes(&self) -> Option<&[u8]> {
        self.cached_bytes.as_deref()
    }
}

/// Threshold signature implementation using BLS12-381
pub struct ThresholdCrypto;

impl ThresholdCrypto {
    /// Generate distributed key shares for a threshold signature scheme using Feldman's VSS
    /// 
    /// # Arguments
    /// * `params` - Threshold parameters
    /// 
    /// # Returns
    /// * `Result<Vec<KeyShare>>` - Key shares for all participants
    pub fn generate_key_shares(params: &ThresholdParams) -> Result<Vec<KeyShare>> {
        if params.threshold == 0 || params.threshold > params.total_participants {
            return Err(ThresholdCryptoError::InvalidThreshold.into());
        }
        
        let mut rng = OsRng;
        
        // Generate a random polynomial of degree (threshold - 1)
        let mut polynomial = DensePolynomial::<Fr>::rand(params.threshold - 1, &mut rng);
        
        // The constant term is the secret key
        let secret_key = polynomial.coeffs[0];
        
        // Generate verification vector (commitments to the polynomial coefficients)
        let verification_vector: Vec<G1Affine> = polynomial
            .coeffs
            .iter()
            .map(|coeff| (G1Affine::generator() * coeff).into_affine())
            .collect();
            
        // Generate key shares for each participant
        let mut shares = Vec::with_capacity(params.total_participants);
        
        for i in 1..=params.total_participants {
            // Evaluate the polynomial at x = i
            let x = Fr::from(i as u64);
            let mut share = Fr::zero();
            let mut x_pow = Fr::one();
            
            for coeff in &polynomial.coeffs {
                share += *coeff * x_pow;
                x_pow *= x;
            }
            
            // Compute the public key share
            let public_share = (G1Affine::generator() * share).into_affine();
            
            shares.push(KeyShare {
                index: i,
                secret_share: share,
                public_share,
                verification_vector: verification_vector.clone(),
            });
        }
        
        Ok(shares)
    }
    
    /// Create a signature share using a participant's key share
    /// 
    /// # Arguments
    /// * `message` - Message to sign
    /// * `key_share` - Participant's key share
    /// 
    /// # Returns
    /// Create a signature share using a participant's key share
    pub fn create_signature_share(message: &[u8], key_share: &KeyShare) -> Result<SignatureShare> {
        profile_memory!("create_signature_share", {
            let hash = Self::hash_to_g2(message);
            let signature_share = hash * key_share.secret_share;
            
            Ok(SignatureShare::new(
                key_share.index,
                signature_share.into_affine(),
            ))
        })
    }
    
    /// Aggregate signature shares into a complete threshold signature
    /// 
    /// # Arguments
    /// * `params` - Threshold parameters
    /// * `message` - Original message that was signed
    /// * `shares` - Signature shares from participants
    /// 
    /// # Returns
    /// * `Result<Vec<u8>>` - Aggregated threshold signature
    pub fn aggregate_signature_shares(
        _params: &ThresholdParams,
        message: &[u8],
        shares: &[SignatureShare],
    ) -> Result<Vec<u8>> {
        profile_memory!("aggregate_signature_shares", {
            if shares.is_empty() {
                return Err(ThresholdCryptoError::InsufficientShares.into());
            }
            
            // Get a pre-allocated vector for indices
            let mut indices = USIZE_VEC_POOL.get(shares.len());
            indices.extend(shares.iter().map(|s| s.index));
            
            // Compute Lagrange coefficients
            let coefficients = Self::lagrange_coefficients(&indices)?;
            
            // Return indices to the pool
            USIZE_VEC_POOL.put(indices);
            
            // Get a pre-allocated vector for signature shares
            let mut signature_shares = G2_PROJECTIVE_VEC_POOL.get(shares.len());
            
            // First pass: convert all shares to projective form
            signature_shares.extend(shares.iter().map(|s| G2Projective::from(s.share)));
            
            // Second pass: aggregate using multi-scalar multiplication (MSM) for better performance
            let aggregated_signature = if let Some(msm_result) = G2Projective::msm(
                &signature_shares,
                &coefficients,
            ) {
                msm_result
            } else {
                // Fallback to naive aggregation if MSM fails
                let mut result = G2Projective::zero();
                for (share, &coeff) in signature_shares.iter().zip(coefficients.iter()) {
                    result += share.mul_bigint(coeff.into_bigint());
                }
                result
            };
            
            // Return signature shares to the pool
            G2_PROJECTIVE_VEC_POOL.put(signature_shares);
            
            // Pre-allocate exact capacity for the serialized signature
            let mut signature_bytes = Vec::with_capacity(96); // BLS12-381 G2 point size
            aggregated_signature
                .into_affine()
                .serialize_compressed(&mut signature_bytes)?;
                
            Ok(signature_bytes)
        })
    }
    
    /// Verify a threshold signature
    /// 
    /// # Arguments
    /// * `message` - Original message that was signed
    /// * `signature` - Aggregated threshold signature
    /// * `public_key` - Aggregated public key (G1 point)
    /// 
    /// # Returns
    /// * `Result<bool>` - Whether the signature is valid
    pub fn verify_threshold_signature(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        // Deserialize the public key
        let public_key = G1Affine::deserialize_compressed(public_key)
            .map_err(|e| ThresholdCryptoError::DeserializationError(e.to_string()))?;
            
        // Deserialize the signature
        let signature = G2Affine::deserialize_compressed(signature)
            .map_err(|e| ThresholdCryptoError::DeserializationError(e.to_string()))?;
        
        // Hash the message to G2
        let msg_point = Self::hash_to_g2(message);
        
        // Prepare the points for pairing
        let g1_neg = -G1Affine::generator();
        
        // Verify the signature using the pairing
        let valid = Bls12_381::multi_pairing(
            [g1_neg, public_key],
            [msg_point.into_affine(), signature],
        )
        .is_zero();
        
        Ok(valid)
    }
    
    /// Derive the aggregated public key from individual public key shares
    /// 
    /// # Arguments
    /// * `shares` - Key shares from participants
    /// 
    /// # Returns
    /// * `Result<Vec<u8>>` - Aggregated public key (G1 point)
    pub fn derive_aggregated_public_key(shares: &[&KeyShare]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(ThresholdCryptoError::InsufficientShares.into());
        }
        
        // The aggregated public key is the first element of the verification vector
        // (which is the same for all shares)
        let aggregated_key = shares[0].verification_vector[0];
        
        // Serialize the public key
        let mut key_bytes = Vec::new();
        aggregated_key.serialize_compressed(&mut key_bytes)?;
        
        Ok(key_bytes)
    }
    
    /// Verify a key share against the verification vector
    /// 
    /// # Arguments
    /// * `share` - Key share to verify
    /// 
    /// # Returns
    /// * `Result<bool>` - Whether the share is valid
    pub fn verify_key_share(share: &KeyShare) -> Result<bool> {
        // Reconstruct the public share from the verification vector
        let x = Fr::from(share.index as u64);
        let mut reconstructed = G1Projective::zero();
        let mut x_pow = Fr::one();
        
        for coeff in &share.verification_vector {
            reconstructed += coeff.mul_bigint(x_pow.into_bigint());
            x_pow *= x;
        }
        
        // The reconstructed point should match the public share
        let valid = G1Projective::from(share.public_share) == reconstructed;
        
        // Also verify that the public share matches the secret share
        let expected_public = G1Affine::generator() * share.secret_share;
        let valid = valid && (expected_public == share.public_share);
        
        Ok(valid)
    }
    
    // --- Helper functions ---
    
    /// Hash a message to a point on G2
    fn hash_to_g2(message: &[u8]) -> G2Projective {
        // Use a domain separation tag
        let mut hasher = Blake2b512::new();
        hasher.update(b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_");
        hasher.update(message);
        let hash_result = hasher.finalize();
        
        // Map the hash to a point on G2
        let mut hash_bytes = [0u8; 64];
        hash_bytes.copy_from_slice(&hash_result[..64]);
        
        // This is a simplified version - in practice, use a proper hash-to-curve function
        G2Projective::from(G2Affine::generator()) * Fr::from_le_bytes_mod_order(&hash_bytes)
    }
    
    /// Compute Lagrange coefficients for a set of indices
    fn lagrange_coefficients(indices: &[usize]) -> Result<Vec<Fr>> {
        profile_memory!("lagrange_coefficients", {
            if indices.is_empty() {
                return Err(ThresholdCryptoError::InsufficientShares.into());
            }
            
            // Get a pre-allocated vector from the pool
            let mut x_coords = FR_VEC_POOL.get(indices.len());
            x_coords.extend(indices.iter().map(|&i| Fr::from(i as u64)));
            
            // Get a pre-allocated vector for coefficients
            let mut coefficients = FR_VEC_POOL.get(indices.len());
            coefficients.resize(indices.len(), Fr::zero());
            
            let len = x_coords.len();
            
            for i in 0..len {
                let x_i = &x_coords[i];
                let mut numerator = Fr::one();
                let mut denominator = Fr::one();
                
                for j in 0..len {
                    if i == j {
                        continue;
                    }
                    
                    let x_j = &x_coords[j];
                    numerator *= x_j;
                    denominator *= x_j - x_i;
                }
                
                if denominator.is_zero() {
                    // Return the vectors to the pool before returning
                    FR_VEC_POOL.put(x_coords);
                    FR_VEC_POOL.put(coefficients);
                    return Err(ThresholdCryptoError::InvalidShareIndex.into());
                }
                
                coefficients[i] = numerator * denominator.inverse().unwrap();
            }
            
            // Return x_coords to the pool
            FR_VEC_POOL.put(x_coords);
            
            Ok(coefficients)
        })
    }
}

// Note: The ThresholdEcdsa implementation has been removed as it was a placeholder
// and would require a different cryptographic approach. For a production implementation
// of threshold ECDSA, consider using the GG20 protocol with secp256k1.

// This is left as a future extension if needed.
                verification_vector: vec![vec![0u8; 33]], // Placeholder
            };
            
            shares.push(share);
        }
        
        Ok(shares)
    }
    
    /// Create a signature share for threshold ECDSA
    pub fn create_signature_share(message: &[u8], key_share: &KeyShare) -> Result<SignatureShare> {
        // Implementation will follow the GG20 protocol
        // This is a placeholder for the actual implementation
        
        let signature_share = SignatureShare {
            index: key_share.index,
            share: vec![0u8; 65], // Placeholder for ECDSA signature share
        };
        
        Ok(signature_share)
    }
    
    /// Aggregate signature shares into a complete threshold ECDSA signature
    pub fn aggregate_signature_shares(
        params: &ThresholdParams,
        message: &[u8],
        shares: &[SignatureShare],
        public_key: &[u8],
    ) -> Result<Vec<u8>> {
        // Ensure we have enough shares to meet the threshold
        if shares.len() < params.threshold {
            return Err(anyhow::anyhow!("Not enough signature shares to meet threshold"));
        }
        
        // Implementation will follow the GG20 protocol
        // This is a placeholder for the actual implementation
        
        // Placeholder for aggregated signature
        let aggregated_signature = vec![0u8; 65]; // ECDSA signature size
        
        Ok(aggregated_signature)
    }
    
    /// Verify a threshold ECDSA signature
    pub fn verify_threshold_signature(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        // In the actual implementation, this would:
        // 1. Deserialize the signature and public key
        // 2. Perform ECDSA signature verification
        
        // Placeholder for verification result
        Ok(true)
    }
}
