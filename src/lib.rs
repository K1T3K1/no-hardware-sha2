pub struct SHA256 {
    digest: Vec<u8>,
    length: usize,
}

impl SHA256 {
    pub fn new(starting_digest: Option<&[u8]>) -> SHA256 {
        let mut length = 0;
        let mut digest = match starting_digest {
            Some(input) => {
                let mut digest = vec![0u8; SHA256::required_capacity(input.len())];
                length = input.len();
                digest.copy_from_slice(input);
                digest
            }
            None => {
                let digest = vec![0u8; 64];
                digest
            }
        };
        digest[length] = 128;
        SHA256 { digest, length }
    }

    #[inline(always)]
    fn required_capacity(len: usize) -> usize {
        ((len + 9) / 64) * 64
    }

    pub fn update(&mut self, new_data: &[u8]) {
        let new_len = self.length + new_data.len();
        let required = SHA256::required_capacity(new_len);
        if required > self.digest.capacity() {
            self.digest.resize(required, 0);
        }
        self.digest[self.length..new_len].copy_from_slice(new_data);
        self.digest[new_len] = 128;
        self.length = new_len;
    }

    pub fn produce(&mut self) -> [u8; 32] {
        let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) =
            SHA256::init_working_vars();
        let digest_len = self.digest.len();
        self.digest[digest_len - 8..].copy_from_slice(((self.length * 8) as u64).to_be_bytes().as_ref());

        for i in 0..digest_len.div_ceil(64) {
            let digest_slice = self.digest[(i * 64)..((i + 1) * 64)].as_ref();
            println!("{:?}", digest_slice);
            let mut schedule = [0u32; 64];
            for index in 0..16 {
                let lower = 4 * index;
                let upper = 4 * (index + 1);
                schedule[index] =
                    u32::from_be_bytes(digest_slice[lower..upper].try_into().unwrap());
            }

            for index in 0..48 {
                let left1 = schedule[index + 1];
                let (left2, left3) = (left1.clone(), left1.clone());
                let right1 = schedule[index + 14];
                let (right2, right3) = (right1.clone(), right1.clone());

                let left_fin = left1.rotate_right(7) ^ left2.rotate_right(18) ^ (left3 >> 3);
                let right_fin = right1.rotate_right(17) ^ right2.rotate_right(19) ^ (right3 >> 10);

                schedule[index + 16] = schedule[index]
                    .wrapping_add(left_fin)
                    .wrapping_add(schedule[index + 9])
                    .wrapping_add(right_fin);
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
                SHA256::init_working_vars();
            let k_consts = SHA256::init_k_consts();

            for index in 0..64 {
                let (a1, a2, a3) = (a.clone(), a.clone(), a.clone());
                let (e1, e2, e3) = (e.clone(), e.clone(), e.clone());
                let sigma0 = a1.rotate_right(2) ^ a2.rotate_right(13) ^ a3.rotate_right(22);
                let sigma1 = e1.rotate_right(6) ^ e2.rotate_right(11) ^ e3.rotate_right(25);
                let choice = (e & f) ^ ((!e) & g);
                let majority = (a & b) ^ (a & c) ^ (b & c);
                let temp1 = h
                    .wrapping_add(sigma1)
                    .wrapping_add(choice)
                    .wrapping_add(k_consts[index])
                    .wrapping_add(schedule[index]);
                let temp2 = sigma0.wrapping_add(majority);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
            h5 = h5.wrapping_add(f);
            h6 = h6.wrapping_add(g);
            h7 = h7.wrapping_add(h);
        }

        let mut result = [0u8; 32];

        for (i, &h) in [h0, h1, h2, h3, h4, h5, h6, h7].iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&h.to_be_bytes());
        }

        result
    }

    const fn init_working_vars() -> (u32, u32, u32, u32, u32, u32, u32, u32) {
        (
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        )
    }

    const fn init_k_consts() -> [u32; 64] {
        [
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
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn it_works() {
        let mut hasher = SHA256::new(None);
        hasher.update(&[1]);
        let mut test_hasher = sha2::Sha256::new();
        test_hasher.update(&[1]);
        println!("my: {:?}", hasher.digest);
        assert_eq!(
            hasher.produce().as_slice(),
            test_hasher.finalize().as_slice()
        );
    }
}
