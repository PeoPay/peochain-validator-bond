use actix_web::{web, HttpResponse, Scope};
use serde::{Deserialize, Serialize};
use sp_core::H256;

use crate::services::validator_service::ValidatorService;

pub fn validator_routes() -> Scope {
    web::scope("/validators")
        .route("/register", web::post().to(register_validator))
        .route("/performance", web::post().to(submit_performance_proof))
        .route("/slash", web::post().to(submit_slashing_evidence))
}

#[derive(Debug, Deserialize)]
struct RegisterValidatorRequest {
    public_key: Vec<u8>,
    proof_of_escrow: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct RegisterValidatorResponse {
    validator_id: H256,
}

async fn register_validator(
    service: web::Data<ValidatorService>,
    req: web::Json<RegisterValidatorRequest>,
) -> HttpResponse {
    match service.register_validator(req.public_key.clone(), req.proof_of_escrow.clone()).await {
        Ok(validator_id) => HttpResponse::Ok().json(RegisterValidatorResponse { validator_id }),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct PerformanceProofRequest {
    proof: Vec<u8>,
}

async fn submit_performance_proof(
    service: web::Data<ValidatorService>,
    req: web::Json<PerformanceProofRequest>,
) -> HttpResponse {
    // Implement performance proof submission
    HttpResponse::NotImplemented().finish()
}

#[derive(Debug, Deserialize)]
struct SlashingEvidenceRequest {
    validator_id: H256,
    evidence: Vec<u8>,
}

async fn submit_slashing_evidence(
    service: web::Data<ValidatorService>,
    req: web::Json<SlashingEvidenceRequest>,
) -> HttpResponse {
    // Implement slashing evidence submission
    HttpResponse::NotImplemented().finish()
}
