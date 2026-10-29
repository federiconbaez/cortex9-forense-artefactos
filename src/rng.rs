//! Generador pseudoaleatorio determinista (xorshift64*).
//!
//! Todo corpus de prueba se deriva de una semilla fijada **antes** de medir
//! (ver `docs/PREREGISTRO.md`). Mismo binario + misma semilla = misma
//! secuencia, en la caja y en el runner de CI. No es criptográfico: solo
//! sirve para generar casos de prueba reproducibles.

#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Crea un generador a partir de una semilla. La semilla 0 se remapea
    /// porque xorshift con estado 0 queda fijo en 0.
    pub fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Rng { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Entero uniforme en `[0, n)`. `n` debe ser > 0.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "below(0) no está definido");
        self.next_u64() % n
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misma_semilla_misma_secuencia() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn semilla_cero_no_queda_fija() {
        let mut r = Rng::new(0);
        assert_ne!(r.next_u64(), 0);
    }

    #[test]
    fn below_respeta_cota() {
        let mut r = Rng::new(7);
        for _ in 0..10_000 {
            assert!(r.below(13) < 13);
        }
    }
}
