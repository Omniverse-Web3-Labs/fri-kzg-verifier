
use colored::Colorize;
use fri_kzg_verifier::exec::{fri_2_kzg_solidity::{generate_kzg_proof, generate_kzg_verifier, load_fri_proof}, kzg_setup::load_kzg_params};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_solidity_verifier::{compile_solidity, encode_calldata, Evm};
use itertools::Itertools;
use log::{info, LevelFilter};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use semaphore_aggregation::plonky2_verifier::verifier_api::std_ops;

// use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};

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

    // let mut rng = rand::thread_rng();
    // let param = ParamsKZG::<Bn256>::setup(degree, &mut rng);
    let param = load_kzg_params(degree, true);

    let proof_id = "8-4";
    let high_rate_proof = load_fri_proof::<F, INNERC, D>(proof_id).unwrap();
    generate_kzg_verifier(high_rate_proof, degree, &param, Some(proof_id.to_string())).unwrap();

    let proof_id = "16-4";
    let high_rate_proof = load_fri_proof::<F, INNERC, D>(proof_id).unwrap();
    generate_kzg_verifier(high_rate_proof, degree, &param, Some(proof_id.to_string())).unwrap();
}

#[test]
#[ignore]
fn test_v_s_with_kzg_loaded() {
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    let degree: u32 = 20;

    let kzg_param = load_kzg_params(degree, true);

    const D: usize = 2;
    type INNERC = PoseidonGoldilocksConfig;
    type F = <INNERC as GenericConfig<D>>::F;

    let proof_id = "16-4";
    let high_rate_proof = load_fri_proof::<F, INNERC, D>(proof_id).unwrap();

    generate_kzg_verifier(high_rate_proof, degree, &kzg_param, Some(proof_id.to_string())).unwrap();
}

#[test]
#[ignore]
fn test_generate_proof_to_local() {
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    let degree: u32 = 20;

    let kzg_param = load_kzg_params(degree, true);

    const D: usize = 2;
    type INNERC = PoseidonGoldilocksConfig;
    type F = <INNERC as GenericConfig<D>>::F;

    let proof_id = "16-4";
    let high_rate_proof = load_fri_proof::<F, INNERC, D>(proof_id).unwrap();

    // load and compile solidity
    let verifier_solidity = std_ops::load_solidity(format!("{proof_id}_verifier.sol")).expect(&format!("load `{proof_id}_verifier.sol` error"));
    let vk_solidity = std_ops::load_solidity(format!("{proof_id}_vk.sol")).expect(&format!("load `{proof_id}_vk.sol` error"));
    let mut evm = Evm::default();
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_address = evm.create(verifier_creation_code);
    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);

    // the `instances` are the public inputs
    let (proof, instances) = generate_kzg_proof(high_rate_proof, &kzg_param, Some(proof_id.to_string())).unwrap();
    
    let calldata = encode_calldata(Some(vk_address.into()), &proof, &instances);
    let (gas_cost, _output) = evm.call(verifier_address, calldata);
    info!("{}", format!("Gas cost: {}", gas_cost).yellow().bold());
}

#[test]
fn test_verify_proof_by_solidity_verifier() {
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    let proof_id = "16-4";

    // load and compile solidity
    let verifier_solidity = std_ops::load_solidity(format!("{proof_id}_verifier.sol")).expect(&format!("load `{proof_id}_verifier.sol` error"));
    let vk_solidity = std_ops::load_solidity(format!("{proof_id}_vk.sol")).expect(&format!("load `{proof_id}_vk.sol` error"));
    let mut evm = Evm::default();
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_address = evm.create(verifier_creation_code);
    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);

    // the `instances` are the public inputs
    // let (proof, instances) = generate_kzg_proof(high_rate_proof, &kzg_param, Some(proof_id.to_string())).unwrap();
    let proof = std_ops::load_snark_proof(format!("{proof_id}_snark_proof.json")).expect(&format!("load proof: {} error", proof_id));
    let instances = std_ops::load_snark_instances(format!("{proof_id}_snark_instances.json")).expect(&format!("load instances: {} error", proof_id));
    let instances = instances.iter().map(|ins| {
        Fr::from(u64::from_str_radix(ins, 10).unwrap())
    }).collect_vec();
    
    let calldata = encode_calldata(Some(vk_address.into()), &proof, &instances);
    let (gas_cost, _output) = evm.call(verifier_address, calldata);
    info!("{}", format!("Gas cost: {}", gas_cost).yellow().bold());
}

/////////////////////////////////////////////////////////////////
/// test fake
#[test]
#[ignore]
#[should_panic]
fn test_fake_proof() {
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    let degree: u32 = 20;

    let kzg_param = load_kzg_params(degree, true);

    const D: usize = 2;
    type INNERC = PoseidonGoldilocksConfig;
    type F = <INNERC as GenericConfig<D>>::F;

    let proof_id = "fake";
    let high_rate_proof = load_fri_proof::<F, INNERC, D>(proof_id).unwrap();

    // load and compile solidity
    let verifier_solidity = std_ops::load_solidity(format!("8-4_verifier.sol")).expect(&format!("load `8-4_verifier.sol` error"));
    let vk_solidity = std_ops::load_solidity(format!("8-4_vk.sol")).expect(&format!("load `8-4_vk.sol` error"));
    let mut evm = Evm::default();
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_address = evm.create(verifier_creation_code);
    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);

    // the `instances` are the public inputs
    let (proof, instances) = generate_kzg_proof(high_rate_proof, &kzg_param, Some(proof_id.to_string())).unwrap();
    
    let calldata = encode_calldata(Some(vk_address.into()), &proof, &instances);
    let (gas_cost, _output) = evm.call(verifier_address, calldata);
    info!("{}", format!("Gas cost: {}", gas_cost).yellow().bold());
}

#[test]
#[should_panic]
fn test_verify_fake_proof_by_solidity_verifier() {
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    let proof_id = "fake";

    // load and compile solidity
    let verifier_solidity = std_ops::load_solidity(format!("8-4_verifier.sol")).expect(&format!("load `8-4_verifier.sol` error"));
    let vk_solidity = std_ops::load_solidity(format!("8-4_vk.sol")).expect(&format!("load `8-4_vk.sol` error"));
    let mut evm = Evm::default();
    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_address = evm.create(verifier_creation_code);
    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);

    // the `instances` are the public inputs
    // let (proof, instances) = generate_kzg_proof(high_rate_proof, &kzg_param, Some(proof_id.to_string())).unwrap();
    let proof = std_ops::load_snark_proof(format!("{proof_id}_snark_proof.json")).expect(&format!("load proof: {} error", proof_id));
    let instances = std_ops::load_snark_instances(format!("{proof_id}_snark_instances.json")).expect(&format!("load instances: {} error", proof_id));
    let instances = instances.iter().map(|ins| {
        Fr::from(u64::from_str_radix(ins, 10).unwrap())
    }).collect_vec();
    
    let calldata = encode_calldata(Some(vk_address.into()), &proof, &instances);
    let (gas_cost, _output) = evm.call(verifier_address, calldata);
    info!("{}", format!("Gas cost: {}", gas_cost).yellow().bold());
}