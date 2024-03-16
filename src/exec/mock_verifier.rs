
#[cfg(test)]
pub mod tests {
    use anyhow::{Ok, Result};
    use circuit_local_storage::circuit::{p_v_io::proof_tuple_to_local, vd_local::write_circuit_p_v_data_to_local};
    use itertools::Itertools;

    use log::{info, LevelFilter};
    use plonky2::{field::extension::Extendable, hash::{hash_types::{HashOut, RichField}, merkle_tree::MerkleTree, poseidon::PoseidonHash}, iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig}}};
    use plonky2_ecdsa::gadgets::recursive_proof::{self, recursive_proof_2};
    use semaphore_aggregation::plonky2_verifier::{bn245_poseidon::plonky2_config::{standard_inner_stark_verifier_config, standard_stark_verifier_config, Bn254PoseidonGoldilocksConfig}, verifier_api::verify_inside_snark};
    use zk_6358_prover::circuit::signature_prover::build_merkle_root_chip;


    fn a_simple_circuit<F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,>() -> Result<recursive_proof::ProofTuple<F, C, D>> {

        let config = standard_inner_stark_verifier_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut witness = PartialWitness::new();

        let hash_t_v_pairs = (0..8).map(|i: u8| {
            let hash_v = HashOut::from_bytes(&[i; 32]);

            let hash_t = builder.add_virtual_hash();
            witness.set_hash_target(hash_t, hash_v);

            // builder.register_public_inputs(&hash_t.elements);
            (hash_t, hash_v)
        }).collect_vec();

        let leaves_t_vec = hash_t_v_pairs.iter().map(|h| {
            h.0.clone()
        }).collect_vec();

        let leaves_v_vec = hash_t_v_pairs.iter().map(|h| {
            h.1.elements.to_vec()
        }).collect_vec();

        let tree = MerkleTree::<F, PoseidonHash>::new(leaves_v_vec, 0);
        build_merkle_root_chip(&mut builder, &mut witness, &leaves_t_vec, tree.cap.0[0]);

        let data = builder.build::<C>();
        let proof = data.prove(witness).unwrap();

        data.verify(proof.clone()).expect("verify error");

        info!("The public hash inputs are: {:?}", proof.public_inputs);

        Ok((proof, data.verifier_only, data.common))
    }

    #[test]
    fn test_sc_fir_kzg_verifier_evm() {
        let mut log_builder = env_logger::Builder::from_default_env();
        log_builder.format_timestamp(None);
        log_builder.filter_level(LevelFilter::Info);
        log_builder.try_init().unwrap();

        const D: usize = 2;
        type INNERC = PoseidonGoldilocksConfig;
        type STRKC = Bn254PoseidonGoldilocksConfig;
        // type STRKC = PoseidonGoldilocksConfig;
        type F = <INNERC as GenericConfig<D>>::F;
        // type H = <INNERC as GenericConfig<D>>::Hasher;
        // type EC = Secp256K1;

        let inner_proof = a_simple_circuit::<F, INNERC, D>().unwrap();

        // let config = standard_inner_stark_verifier_config();
        // let middle_proof = recursive_proof_2::<F, INNERC, INNERC, D>(&vec![inner_proof], &config, None).unwrap();

        let starky_config = standard_stark_verifier_config();
        let final_proof = recursive_proof_2::<F, STRKC, INNERC, D>(&vec![inner_proof], &starky_config, None).unwrap();

        proof_tuple_to_local("s_smt_sv", &final_proof, false).unwrap();
        proof_tuple_to_local("s_smt_sv", &final_proof, true).unwrap();

        write_circuit_p_v_data_to_local("s_smt_sv", &final_proof).unwrap();

        info!("start verify in snark");
        verify_inside_snark(19, final_proof);
    }
}
