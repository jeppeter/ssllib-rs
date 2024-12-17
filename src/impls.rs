
use std::error::Error;

pub trait Asn1DigestOp {
	fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>>;
	fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1SignOp {
	fn sign_update(&mut self,data :&[u8],digop :Box<dyn Asn1DigestOp>) -> Result<(),Box<dyn Error>>;
	fn sign_final(&mut self,digop:Box<dyn Asn1DigestOp>) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1VerifyOp {
	fn verify_update(&mut self, origdata :&[u8], digop :Box<dyn Asn1DigestOp>) -> Result<(),Box<dyn Error>>;
	fn verify_final(&mut self,signdata :&[u8], digop :Box<dyn Asn1DigestOp>) -> Result<bool,Box<dyn Error>>;
}

pub trait Asn1EncryptOp {
	fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
	fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1DecryptOp {
	fn decrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
	fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}