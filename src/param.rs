use crate::poly::PolyArith;
use crate::poly256::Poly256;
use rand::{CryptoRng, RngCore};

/// P is the modulus for `B part`
pub const P: i64 = 2_097_169;

/// Q is the modulus for `A part`
pub const Q: i64 = 100_679_681;

/// R is a root s.t. (x^32+R) divides (x^256+1) mod P
pub const R: i64 = 852_368;

/// Q_RS_RANGE: rejection sampling range for Q
/// Q_RS_RANGE = 2^32//Q * Q
/// if a random 32 bits integer is smaller than Q_RS_RANGE
/// then it produces a uniform value within [0,Q)
pub const Q_RS_RANGE: u32 = 4_228_546_602;

/// Q_RS_RANGE: rejection sampling range for P
/// Q_RS_RANGE = 2^32//P * P
/// if a random 32 bits integer is smaller than P_RS_RANGE
/// then it produces a uniform value within [0,P)
pub const P_RS_RANGE: u32 = 4_292_904_943;

/// range for Y
pub const BETA: i64 = 89_856;
pub const BETA_M2_P1: u32 = 179_703;
pub const BETA_M_KAPPA: i64 = 89817;

/// BETA_RS_RANGE: rejection sampling range for beta
/// BETA_RS_RANGE = 2^32//BETA_M2_P1 * BETA_M2_P1
/// if a random 32 bits integer is smaller than BETA_RS_RANGE
/// then it produces a uniform value within [-beta,beta]
pub const BETA_RS_RANGE: u32 = 4_294_901_700;

/// number of non-zero coefficients in challenge
pub const KAPPA: usize = 39;

/// the param is a 4*9 matrix of polynomials
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Param {
    pub matrix: [[Poly256; 9]; 4],
}

impl Param {
    pub fn init<R: RngCore + CryptoRng + ?Sized>(mut rng: &mut R) -> Self {
        let mut res = Self {
            matrix: [[Poly256::zero(); 9]; 4],
        };
        for e in res.matrix.iter_mut() {
            for f in e.iter_mut() {
                *f = Poly256::uniform_random(&mut rng);
            }
        }
        res
    }
}
