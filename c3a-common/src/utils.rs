pub fn generate_dilithium_keypair() -> pqc_dilithium::Keypair {
  pqc_dilithium::Keypair::generate()
}

pub fn sign(data: &[u8], keypair: &pqc_dilithium::Keypair) -> Vec<u8> {
  keypair.sign(data).to_vec()
}

pub fn verify(data: &[u8], sign: &[u8], keypair: &pqc_dilithium::Keypair) -> bool {
  pqc_dilithium::verify(sign, data, &keypair.public).is_ok()
}
