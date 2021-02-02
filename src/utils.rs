use crypto::ripemd160::Ripemd160;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

pub fn double_sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let mut hash = vec![0; hasher.output_bytes()];
    hasher.input(&bytes);
    hasher.result(&mut hash);
    hasher.reset();
    hasher.input(&hash);
    hasher.result(&mut hash);
    return hash;
}

pub fn hash160(bytes: &[u8]) -> Vec<u8> {
    let mut res = sha256(&bytes);
    res = ripemd160(&res);
    return res;
}

fn ripemd160(bytes: &[u8]) -> Vec<u8> {
    let mut ripemder = Ripemd160::new();
    let mut hash = vec![0; ripemder.output_bytes()];
    ripemder.input(&bytes);
    ripemder.result(&mut hash);
    return hash;
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let mut hash = vec![0; hasher.output_bytes()];
    hasher.input(&bytes);
    hasher.result(&mut hash);
    return hash;
}

#[cfg(test)]
mod tests {
    use crate::utils::hash160;
    use faster_hex::{hex_encode, hex_string};

    #[test]
    fn hash160_test() {
        let data: Vec<u8> = vec![1,2,3,4];
        let hash = hash160(&data);
        assert_eq!(hash, [236, 210, 203, 216, 38, 45, 44, 54, 27, 147, 191, 137, 196, 240, 167, 141, 118, 161, 110, 112]);
        let hex = hex_string(&[236, 210, 203, 216, 38, 45, 44, 54, 27, 147, 191, 137, 196, 240, 167, 141, 118, 161, 110, 112]);
        println!("{}", hex.unwrap());
    }
}
