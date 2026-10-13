//! SHA-256 implementation translated from Python
//! Original from: https://gist.github.com/prokls/41e82472bd4968720d1482f81235e0ac
//! Base: https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py
//! Author: Lukas Prokop
//! License: MIT
//! SHA-256 implementation translated from Python
//! Original from: https://gist.github.com/prokls/41e82472bd4968720d1482f81235e0ac
//! Base: https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py
//! Author: Lukas Prokop
//! License: MIT

use std::vec::Vec;
use std::format;
use std::string::String;
use alloc::vec;
const F32: u32 = 0xFFFFFFFF;


const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Get the SHA-256 hash state as a hex string
pub fn get_h_state(input: &str) -> Result<String, hex::FromHexError> {
    let byte_object = hex::decode(input)?;
    let mut sha_object = Sha256::new();
    sha_object.update(&byte_object);
    
    let h_string = sha_object.h
        .iter()
        .map(|&i| format!("{:08x}", i))
        .collect::<String>();
    
    Ok(h_string)
}

fn pad(msglen: usize) -> Vec<u8> {
    let mdi = msglen & 0x3F;
    let length = (msglen as u64 * 8).to_be_bytes();
    
    let padlen = if mdi < 56 {
        55 - mdi
    } else {
        119 - mdi
    };
    
    let mut padding = vec![0x80];
    padding.extend(vec![0x00; padlen]);
    padding.extend_from_slice(&length);
    padding
}

fn rotr(x: u32, y: u32) -> u32 {
    ((x >> y) | (x << (32 - y))) & F32
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

pub struct Sha256 {
    output_size: usize,
    blocksize: usize,
    block_size: usize,
    digest_size: usize,
    counter: usize,
    cache: Vec<u8>,
    k: [u32; 64],
    h: [u32; 8],
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        let mut sha = Sha256 {
            output_size: 8,
            blocksize: 1,
            block_size: 64,
            digest_size: 32,
            counter: 0,
            cache: Vec::new(),
            k: K,
            h: INITIAL_H,
        };
        sha
    }
    
    pub(crate) fn with_data(data: &[u8]) -> Self {
        let mut sha = Self::new();
        sha.update(data);
        sha
    }

    fn compress(&mut self, chunk: &[u8]) {
        let mut w = [0u32; 64];
        
        // First 16 words from the chunk
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1], 
                chunk[i * 4 + 2],
                chunk[i * 4 + 3]
            ]);
        }
        
        // Extend the first 16 words into the remaining 48 words
        for i in 16..64 {
            let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = (w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1)) & F32;
        }
        
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        
        // Main loop
        for i in 0..64 {
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            let t2 = s0.wrapping_add(maj(a, b, c));
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            let t1 = h.wrapping_add(s1).wrapping_add(ch(e, f, g)).wrapping_add(self.k[i]).wrapping_add(w[i]);
            
            h = g;
            g = f;
            f = e;
            e = (d.wrapping_add(t1)) & F32;
            d = c;
            c = b;
            b = a;
            a = (t1.wrapping_add(t2)) & F32;
        }
        
        // Add this chunk's hash to result so far
        self.h[0] = (self.h[0].wrapping_add(a)) & F32;
        self.h[1] = (self.h[1].wrapping_add(b)) & F32;
        self.h[2] = (self.h[2].wrapping_add(c)) & F32;
        self.h[3] = (self.h[3].wrapping_add(d)) & F32;
        self.h[4] = (self.h[4].wrapping_add(e)) & F32;
        self.h[5] = (self.h[5].wrapping_add(f)) & F32;
        self.h[6] = (self.h[6].wrapping_add(g)) & F32;
        self.h[7] = (self.h[7].wrapping_add(h)) & F32;
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        
        self.cache.extend_from_slice(data);
        self.counter += data.len();
        
        while self.cache.len() >= 64 {
            let chunk = &self.cache[..64].to_vec();
            self.compress(chunk);
            self.cache = self.cache[64..].to_vec();
        }
    }

    pub(crate) fn digest(&self) -> Vec<u8> {
        let mut clone = Sha256 {
            output_size: self.output_size,
            blocksize: self.blocksize,
            block_size: self.block_size,
            digest_size: self.digest_size,
            counter: self.counter,
            cache: self.cache.clone(),
            k: self.k,
            h: self.h,
        };
        
        let padding = pad(clone.counter);
        clone.update(&padding);
        
        let mut result = Vec::new();
        for i in 0..clone.output_size {
            result.extend_from_slice(&clone.h[i].to_be_bytes());
        }
        result
    }

    pub(crate) fn hexdigest(&self) -> String {
        hex::encode(self.digest())
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(msg: &str, expected: &str) -> bool {
        let mut m = Sha256::new();
        m.update(msg.as_bytes());
        m.hexdigest() == expected
    }

    #[test]
    fn test_sha256() {
        let tests = [
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("message digest", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"),
            ("abcdefghijklmnopqrstuvwxyz", "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"),
        ];

        for (input, expected) in tests.iter() {
            assert!(check(input, expected), "Test failed for input: '{}'", input);
        }
    }
}