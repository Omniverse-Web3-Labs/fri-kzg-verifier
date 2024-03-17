
#[cfg(test)]
pub mod tests {
    use anyhow::{Ok, Result};
    use circuit_local_storage::circuit::{p_v_io::{proof_tuple_to_local, read_compressed_ppis_from_local, read_ppis_from_local, PVDataPath}, vd_local::write_circuit_p_v_data_to_local};
    use client_verifier::circuit::verify_from_file::PureVerifier;
    use itertools::Itertools;

    use log::{info, LevelFilter};
    use plonky2::{field::extension::Extendable, fri::FriConfig, hash::{hash_types::{HashOut, RichField}, merkle_tree::MerkleTree, poseidon::PoseidonHash}, iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, VerifierCircuitData}, config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig}}};
    use plonky2_ecdsa::gadgets::recursive_proof::{self, recursive_proof_2};
    use semaphore_aggregation::plonky2_verifier::{bn245_poseidon::plonky2_config::{standard_inner_stark_verifier_config, standard_stark_verifier_config, Bn254PoseidonGoldilocksConfig}, verifier_api::verify_inside_snark};
    use zk_6358_prover::circuit::signature_prover::build_merkle_root_chip;


    fn a_simple_circuit<F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,>() -> Result<recursive_proof::ProofTuple<F, C, D>> {

        // let config = standard_inner_stark_verifier_config();
        let config = CircuitConfig::standard_ecc_config();
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
    #[ignore]
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

        // let st_config = standard_inner_stark_verifier_config();
        let st_config = CircuitConfig::standard_recursion_config();
        let st_config = CircuitConfig {
            fri_config: FriConfig {
                rate_bits: 7,
                proof_of_work_bits: 16,
                num_query_rounds: 12,
                ..st_config.fri_config.clone()
            },
            ..st_config
        };
        let middle_proof = recursive_proof_2::<F, INNERC, INNERC, D>(&vec![inner_proof], &st_config, None).unwrap();

        let starky_config = standard_stark_verifier_config();

        let final_proof = recursive_proof_2::<F, STRKC, INNERC, D>(&vec![middle_proof], &starky_config, None).unwrap();

        proof_tuple_to_local("s_smt_sv", &final_proof, false).unwrap();
        proof_tuple_to_local("s_smt_sv", &final_proof, true).unwrap();

        write_circuit_p_v_data_to_local("s_smt_sv", &final_proof).unwrap();

        info!("start verify in snark");
        verify_inside_snark(21, final_proof);
    }

    #[test]
    #[ignore]
    fn test_evm_verifier_from_local() {
        let mut log_builder = env_logger::Builder::from_default_env();
        log_builder.format_timestamp(None);
        log_builder.filter_level(LevelFilter::Info);
        log_builder.try_init().unwrap();

        const D: usize = 2;
        type INNERC = PoseidonGoldilocksConfig;
        type STRKC = Bn254PoseidonGoldilocksConfig;
        type F = <INNERC as GenericConfig<D>>::F;

        let pv_path = PVDataPath::new("st_parallel_utxo_high_rate");

        let vd = VerifierCircuitData::<F, INNERC, D>::load_from_file(&pv_path.verifier_only_path, &pv_path.common_path);

        let ppis = read_ppis_from_local::<F, INNERC, D>(&pv_path.ppis_path);
        // let c_ppis = read_compressed_ppis_from_local::<F, INNERC, D>(&pv_path.compressed_ppis_path);

        // vd.verify(ppis).unwrap();
        // vd.verify_compressed(c_ppis).unwrap();

        let high_rate_proof = (ppis, vd.verifier_only, vd.common);

        let starky_config = standard_stark_verifier_config();

        let final_proof = recursive_proof_2::<F, STRKC, INNERC, D>(&vec![high_rate_proof], &starky_config, None).unwrap();

        info!("start verify in snark");
        verify_inside_snark(21, final_proof);
    }
}
