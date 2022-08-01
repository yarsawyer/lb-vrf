use lb_vrf::lbvrf::LBVRF;
use lb_vrf::param::Param;
use lb_vrf::VRF;
use rand::RngCore;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::{Digest, Sha512};
//use lb_vrf::poly256::Poly256;
use lb_vrf::serde::Serdes;
use std::convert::TryInto;

fn main() {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];

    rng.fill_bytes(&mut seed);

    let param: Param = <LBVRF as VRF>::paramgen(seed).unwrap();

    println!("Param1: {:?}", param);

    let param2: Param = <LBVRF as VRF>::paramgen(seed).unwrap();
    println!();
    println!();
    println!();
    println!("Param2: {:?}", param2);

    rng.fill_bytes(&mut seed);
    let (pk, sk) = <LBVRF as VRF>::keygen(seed, param).unwrap();
    let message = "hashblock";



    println!();
    println!();
    println!();


    rng.fill_bytes(&mut seed);
    let proof = <LBVRF as VRF>::prove(message, param, pk, sk, seed).unwrap();
    println!("proof: {:?}", proof);

    
    
    let message2 = "hashblock";
    
    let res = <LBVRF as VRF>::verify(message2, param, pk, proof).unwrap();
    println!("{:?}", res);
    
    println!();
    println!();
    println!();

    let mut hash_input: Vec<u8> = vec![];
    let mut seedx = [0u8; 32];

    for e in res.iter() {
        assert!((*e).serialize(&mut hash_input).is_ok());
    }

    rng.fill_bytes(&mut seedx);
    let mut hasher = Sha512::new();
    
    hasher.update(hash_input);
    let digest = hasher.finalize();
    let seed: [u8; 32] = digest.as_slice()[0..32].try_into().expect("Wrong length");
    let mut xrng = ChaCha20Rng::from_seed(seed);

    println!("RAND1: {:?}", xrng.next_u32());
    println!("RAND2: {:?}", xrng.next_u32());
    println!("RAND3: {:?}", xrng.next_u32());

    let mut xrng1 = ChaCha20Rng::from_seed(seed);

    println!("RAND11: {:?}", xrng1.next_u32());
    println!("RAND12: {:?}", xrng1.next_u32());
    println!("RAND13: {:?}", xrng1.next_u32());





}
