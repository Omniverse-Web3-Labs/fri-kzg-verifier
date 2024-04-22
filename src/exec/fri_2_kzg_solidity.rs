
use std::fs;

use colored::Colorize;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr}, 
    poly::kzg::commitment::ParamsKZG, 
};

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::{circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData}, config::{GenericConfig, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs}, util::serialization::DefaultGateSerializer
};

use plonky2_ecdsa::gadgets::recursive_proof::{recursive_proof_2, ProofTuple};

use semaphore_aggregation::plonky2_verifier::{bn245_poseidon::plonky2_config::{standard_stark_verifier_config, Bn254PoseidonGoldilocksConfig}, verifier_api::{make_checked_fri2kzg_snark_proof, verify_inside_snark_solidity}};

use log::info;
use anyhow::Result;

const FRI_PROOF_DIR: &str = "./data-circuit";

pub fn load_fri_proof
<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
(hrr_proof_id: &str) -> Result<ProofTuple<F, C, D>> 
{

    let vod_path = format!("{}/{}_vod", FRI_PROOF_DIR, hrr_proof_id);
    let ccd_path = format!("{}/{}_ccd", FRI_PROOF_DIR, hrr_proof_id);
    let ppis_path = format!("{}/{}_ppis.json", FRI_PROOF_DIR, hrr_proof_id);

    let vod = fs::read(vod_path).unwrap();
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(vod).unwrap();

    let gate_serializer = DefaultGateSerializer;
    let ccd = fs::read(ccd_path).unwrap();
    let common = CommonCircuitData::<F, D>::from_bytes(ccd, &gate_serializer).unwrap();

    let ppis = fs::read(ppis_path).unwrap();
    let ppis: ProofWithPublicInputs<F, C, D> = serde_json::from_slice(&ppis).unwrap();
    let vd = VerifierCircuitData {
        verifier_only,
        common,
    };
    vd.verify(ppis.clone()).unwrap();

    Ok((ppis, vd.verifier_only, vd.common))
}

pub fn generate_kzg_verifier
(high_rate_proof: ProofTuple<plonky2::field::goldilocks_field::GoldilocksField, PoseidonGoldilocksConfig, 2>, degree: u32, kzg_param: &ParamsKZG<Bn256>, save: Option<String>) -> Result<()>
{
    type F = plonky2::field::goldilocks_field::GoldilocksField;
    type INNERC = PoseidonGoldilocksConfig;
    type STRKC = Bn254PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    let starky_config = standard_stark_verifier_config();

    let final_proof = recursive_proof_2::<F, STRKC, INNERC, D>(&vec![high_rate_proof], &starky_config, None)?;

    info!("{}", "start verify in snark".cyan().bold());
    verify_inside_snark_solidity(degree, final_proof, kzg_param, save);
    
    Ok(())
}

pub fn generate_kzg_proof
(high_rate_proof: ProofTuple<plonky2::field::goldilocks_field::GoldilocksField, PoseidonGoldilocksConfig, 2>, kzg_param: &ParamsKZG<Bn256>, save: Option<String>) -> Result<(Vec<u8>, Vec<Fr>)>
{
    type F = plonky2::field::goldilocks_field::GoldilocksField;
    type INNERC = PoseidonGoldilocksConfig;
    type STRKC = Bn254PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    let starky_config = standard_stark_verifier_config();

    let final_proof = recursive_proof_2::<F, STRKC, INNERC, D>(&vec![high_rate_proof], &starky_config, None)?;

    info!("{}", "start verify in snark".cyan().bold());
    make_checked_fri2kzg_snark_proof(final_proof, kzg_param, save)
}
