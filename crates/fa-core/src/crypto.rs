//! SHA-256 y HMAC-SHA256 en std puro.
//!
//! El Gatekeeper y el RPMB autenticados usan HMAC sobre mensajes de protocolo.
//! Traemos la implementación propia (sin crates externos) para que el binario
//! compile sin red y para poder citar vectores de prueba FIPS/RFC en el README.
//! Validado contra:
//! - FIPS 180-4 / NIST CAVP SHA-256 ("abc", cadena vacía, "abcdbc...")
//! - RFC 4231 HMAC-SHA256 casos 1, 2 y 3.

/// Digest SHA-256 de `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finalize()
}

/// HMAC-SHA256(key, message) según RFC 2104 / RFC 4231.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finalize()
}

/// Comparación en tiempo constante (bitwise OR de diferencias). Evita
/// early-return sobre MACs de protocolo; no sustituye una implementación
/// hardened de producción.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    bitlen: u64,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            buflen: 0,
            bitlen: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.buflen] = b;
            self.buflen += 1;
            if self.buflen == 64 {
                self.compress();
                self.bitlen = self.bitlen.wrapping_add(512);
                self.buflen = 0;
            }
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let total_bits = self
            .bitlen
            .wrapping_add((self.buflen as u64).wrapping_mul(8));
        // padding 0x80 + ceros + longitud big-endian de 64 bits
        self.buf[self.buflen] = 0x80;
        self.buflen += 1;
        if self.buflen > 56 {
            while self.buflen < 64 {
                self.buf[self.buflen] = 0;
                self.buflen += 1;
            }
            self.compress();
            self.buflen = 0;
        }
        while self.buflen < 56 {
            self.buf[self.buflen] = 0;
            self.buflen += 1;
        }
        for i in 0..8 {
            self.buf[56 + i] = ((total_bits >> (56 - 8 * i)) & 0xFF) as u8;
        }
        self.compress();
        let mut out = [0u8; 32];
        for (i, &w) in self.h.iter().enumerate() {
            out[4 * i] = (w >> 24) as u8;
            out[4 * i + 1] = (w >> 16) as u8;
            out[4 * i + 2] = (w >> 8) as u8;
            out[4 * i + 3] = w as u8;
        }
        out
    }

    fn compress(&mut self) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *wi = u32::from_be_bytes([
                self.buf[j],
                self.buf[j + 1],
                self.buf[j + 2],
                self.buf[j + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        let d = sha256(b"");
        assert_eq!(
            hex::encode_like(&d),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        let d = sha256(b"abc");
        assert_eq!(
            hex::encode_like(&d),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_long() {
        let d = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex::encode_like(&d),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn hmac_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        assert_eq!(
            hex::encode_like(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        assert_eq!(
            hex::encode_like(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_rfc4231_case3() {
        let key = [0xaau8; 20];
        let data = [0xdd; 50];
        let mac = hmac_sha256(&key, &data);
        assert_eq!(
            hex::encode_like(&mac),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn ct_eq_iguales_y_distintos() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    }

    /// Mini helper local para no depender de `hex`.
    mod hex {
        pub fn encode_like(b: &[u8]) -> String {
            b.iter().map(|x| format!("{:02x}", x)).collect()
        }
    }
}
