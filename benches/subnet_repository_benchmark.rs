use criterion::{criterion_group, criterion_main, Criterion};
use peochain_validator_bond::{
    models::subnet::{SubnetAssignment, ValidatorSet},
    repositories::postgres::PostgresSubnetRepository,
};
use sp_core::H256;
use std::time::Duration;

async fn setup_repository() -> PostgresSubnetRepository {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PostgresSubnetRepository::new(&database_url, 5).await.unwrap()
}

fn generate_test_assignments(count: usize) -> Vec<SubnetAssignment> {
    (0..count)
        .map(|i| SubnetAssignment {
            subnet_id: (i % 10) as u32,
            epoch: 1,
            validator_set: ValidatorSet::new(vec![H256::random()]),
        })
        .collect()
}

fn benchmark_store_assignments(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let repo = rt.block_on(setup_repository());
    
    let mut group = c.benchmark_group("store_assignments");
    group.measurement_time(Duration::from_secs(10));
    
    for count in [10, 100, 1000].iter() {
        let assignments = generate_test_assignments(*count);
        
        group.bench_with_input(
            format!("store_{}_assignments", count),
            count,
            |b, _| {
                b.to_async(&rt).iter(|| {
                    let repo = &repo;
                    async move {
                        repo.store_subnet_assignments(assignments.clone())
                            .await
                            .unwrap();
                    }
                })
            },
        );
    }
    
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_store_assignments
}
criterion_main!(benches);
