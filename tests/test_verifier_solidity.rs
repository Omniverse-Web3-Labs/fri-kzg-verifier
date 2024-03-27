
use fri_kzg_verifier::exec::fri_2_kzg_solidity::{generate_kzg_verifier, load_fri_proof};
use log::LevelFilter;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};

#[test]
#[ignore]
fn test_verifier_solidity() {
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    const D: usize = 2;
    type INNERC = PoseidonGoldilocksConfig;
    type F = <INNERC as GenericConfig<D>>::F;

    let degree: u32 = 20;

    let mut rng = rand::thread_rng();
    let param = ParamsKZG::<Bn256>::setup(degree, &mut rng);

    let proof_id = "8-4";
    let high_rate_proof = load_fri_proof::<F, INNERC, D>(proof_id).unwrap();
    generate_kzg_verifier(high_rate_proof, degree, &param, Some(proof_id.to_string())).unwrap();

    let proof_id = "8-4s";
    let high_rate_proof = load_fri_proof::<F, INNERC, D>(proof_id).unwrap();
    generate_kzg_verifier(high_rate_proof, degree, &param, Some(proof_id.to_string())).unwrap();
}