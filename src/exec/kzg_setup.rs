use std::{fs, path::PathBuf};

use halo2_proofs::{
    arithmetic::{parallelize, Field}, 
    halo2curves::{bn256::Bn256, group::{Group, Curve, prime::PrimeCurveAffine}, pairing::Engine}, 
    poly::{commitment::{Params, ParamsProver}, kzg::commitment::ParamsKZG}, 
    SerdeFormat
};

use log::info;
use colored::Colorize;

pub const KZG_SETUP_DIR_DEFAULT: &str = ".kzg-setup";
pub const KZG_SETUP_FIL_DEFUALT: &str = "kzg_bn254";
pub const KZG_SETUP_EQP_DEFAULT: &str = "equip";

pub fn default_kzg_setup_file(degree: u32) -> PathBuf {
    let mut full_path = dirs::home_dir().unwrap();
    // format!("{home_dir}/{KZG_SETUP_DIR_DEFAULT}/{KZG_SETUP_FIL_DEFUALT}_{degree}.srs")
    full_path.extend(&[KZG_SETUP_DIR_DEFAULT, &format!("{KZG_SETUP_FIL_DEFUALT}_{degree}.srs")]);
    full_path
}

pub fn equiped_kzg_setup_file(degree: u32) -> PathBuf {
    let mut full_path = dirs::home_dir().unwrap();
    // format!("{home_dir}/{KZG_SETUP_DIR_DEFAULT}/{KZG_SETUP_EQP_DEFAULT}_{KZG_SETUP_FIL_DEFUALT}_{degree}.srs")
    full_path.extend(&[KZG_SETUP_DIR_DEFAULT, &format!("{KZG_SETUP_EQP_DEFAULT}_{KZG_SETUP_FIL_DEFUALT}_{degree}.srs")]);
    full_path
}

pub fn load_kzg_params(degree: u32, equip: bool) -> ParamsKZG<Bn256>
{
    if equip {
        if let Ok(kzg_params_buffer) = fs::read(equiped_kzg_setup_file(degree)) {
            info!("{}", "directly load equipped kzg params".white());
            return ParamsKZG::<Bn256>::read_custom(&mut &kzg_params_buffer[..], SerdeFormat::RawBytes).expect("`read_custom` bytes error");
        } else {
            let kzg_params_buffer = fs::read(default_kzg_setup_file(degree)).expect("read default kzg params file failed");
            let mut kzg_params = ParamsKZG::<Bn256>::read_custom(&mut &kzg_params_buffer[..], SerdeFormat::RawBytes).expect("`read_custom` bytes error");
            info!("{}", "equipping kzg params".white());
            kzg_params.equip_kzg_params();

            info!("{}", "write equipped kzg params to local".white());
            let mut data = vec![];
            kzg_params.write_custom(&mut data, SerdeFormat::RawBytes).unwrap();
            fs::write(equiped_kzg_setup_file(degree), data).expect("write equiped kzg params error");

            return kzg_params;
        }
    } else {
        let kzg_params_buffer = fs::read(default_kzg_setup_file(degree)).expect("read default kzg params file failed");
        return ParamsKZG::<Bn256>::read_custom(&mut &kzg_params_buffer[..], SerdeFormat::RawBytes).expect("`read_custom` bytes error");
    }
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

        // random tau
        let s = <<Bn256 as Engine>::Fr>::random(rng);

        // generate g = [G1, [s * r] G1, [s^2 * r^2] G1, ..., [s^(n-1) * r^(n-1)] G1] in parallel.
        // `r` is the accumulated `tau` from public kzg trusted setup params
        // here we use [kzg_bn254_{self.k()}](https://docs.axiom.xyz/docs/transparency-and-security/kzg-trusted-setup)
        // info!("{}", "equip `g_projective`".white());
        let g_projective_affine = self.get_g();
        let mut g_projective = vec![<Bn256 as Engine>::G1::identity(); n as usize];
        parallelize(&mut g_projective, |g, start| {
            let mut s_pow = s.pow_vartime([start as u64]);
            for (idx, g) in g.iter_mut().enumerate() {
                *g = Into::<<Bn256 as Engine>::G1>::into(g_projective_affine[start + idx]) * s_pow;
                s_pow *= s;
            }
        });

        // info!("{}", "equip `g`".white());
        let g = {
            let mut g = vec![<Bn256 as Engine>::G1Affine::identity(); n as usize];
            parallelize(&mut g, |g, starts| {
                <Bn256 as Engine>::G1::batch_normalize(&g_projective[starts..(starts + g.len())], g);
            });
            g
        };

        // info!("{}", "equip `g2`".white());
        let g2 = self.g2();
        let s_g2 = (self.s_g2() * s).into();

        info!("{}", "equip `g_lagrange` and build equipped kzg params".white());
        *self = self.from_parts(
            self.k(),
            g,
            None,
            g2,
            s_g2,
        );
    }
}
