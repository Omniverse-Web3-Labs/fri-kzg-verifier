use std::fs;

use circuit_local_storage::circuit::p_v_io::{read_ppis_from_local, PVDataPath};
use client_verifier::circuit::verify_from_file::PureVerifier;

use halo2_proofs::{
    arithmetic::{parallelize, Field}, 
    halo2curves::{bn256::Bn256, group::{Group, Curve, prime::PrimeCurveAffine}, pairing::Engine}, 
    poly::{commitment::{Params, ParamsProver}, kzg::commitment::ParamsKZG}, 
    SerdeFormat
};

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::{circuit_data::VerifierCircuitData, config::{GenericConfig, PoseidonGoldilocksConfig}}
};

use plonky2_ecdsa::gadgets::recursive_proof::{recursive_proof_2, ProofTuple};

use semaphore_aggregation::plonky2_verifier::{bn245_poseidon::plonky2_config::{standard_stark_verifier_config, Bn254PoseidonGoldilocksConfig}, verifier_api::verify_inside_snark_solidity};

use log::info;
use anyhow::Result;

pub const KZG_SETUP_DIR: &str = "/Users/monkey/Downloads";

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

pub fn load_kzg_params(filename: &str, equip: bool) -> ParamsKZG<Bn256>
{
    let kzg_params_buffer = fs::read(filename).expect("read kzg params file failed");
    let mut kzg_params = ParamsKZG::<Bn256>::read_custom(&mut &kzg_params_buffer[..], SerdeFormat::RawBytes).expect("`read_custom` bytes error");

    if equip {
        kzg_params.equip_kzg_params();
    }

    kzg_params
}

/////////////////////////////////////////////////////////////////////////
/// trait: Equip the KZG params
pub trait KZGEquipment<E: Engine> {
    fn equip_kzg_params(&mut self);
}

impl KZGEquipment<Bn256> for ParamsKZG<Bn256>
{
    fn equip_kzg_params(&mut self) {
        let rng = rand::thread_rng();

        let n: u64 = self.n();

        // Calculate g = [G1, [s] G1, [s^2] G1, ..., [s^(n-1)] G1] in parallel.
        // let g1 = <Bn256 as Engine>::G1Affine::generator();
        let s = <<Bn256 as Engine>::Fr>::random(rng);

        let g_projective_affine = self.get_g();
        let mut g_projective = vec![<Bn256 as Engine>::G1::identity(); n as usize];
        parallelize(&mut g_projective, |g, start| {
            let mut s_pow = s.pow_vartime([start as u64]);
            for (idx, g) in g.iter_mut().enumerate() {
                *g = Into::<<Bn256 as Engine>::G1>::into(g_projective_affine[start + idx]) * s_pow;
                s_pow *= s;
            }
        });

        let g = {
            let mut g = vec![<Bn256 as Engine>::G1Affine::identity(); n as usize];
            parallelize(&mut g, |g, starts| {
                <Bn256 as Engine>::G1::batch_normalize(&g_projective[starts..(starts + g.len())], g);
            });
            g
        };

        let g2 = self.g2();
        let s_g2 = (self.s_g2() * s).into();

        *self = self.from_parts(
            self.k(),
            g,
            None,
            g2,
            s_g2,
        );
    }
}
