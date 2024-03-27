use circuit_local_storage::circuit::p_v_io::{read_ppis_from_local, PVDataPath};
use client_verifier::circuit::verify_from_file::PureVerifier;

use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::{circuit_data::VerifierCircuitData, config::{GenericConfig, PoseidonGoldilocksConfig}}
};

use plonky2_ecdsa::gadgets::recursive_proof::{recursive_proof_2, ProofTuple};

use semaphore_aggregation::plonky2_verifier::{bn245_poseidon::plonky2_config::{standard_stark_verifier_config, Bn254PoseidonGoldilocksConfig}, verifier_api::verify_inside_snark_solidity};

use log::info;
use anyhow::Result;

pub fn load_fri_proof
<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
(hrr_proof_id: &str) -> Result<ProofTuple<F, C, D>> 
{
    let pv_path = PVDataPath::new(hrr_proof_id);

    let vd = VerifierCircuitData::<F, C, D>::load_from_file(&pv_path.verifier_only_path, &pv_path.common_path);

    let ppis = read_ppis_from_local::<F, C, D>(&pv_path.ppis_path);
    // vd.verify(ppis).unwrap();

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

    info!("start verify in snark");
    verify_inside_snark_solidity(degree, final_proof, kzg_param, save);
    
    Ok(())
}
