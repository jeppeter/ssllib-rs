
use std::error::Error;

pub trait Asn1DigestOp {
	fn digest(&self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1SignOp {
	fn sign(&self,data :&[u8],digop :Box<dyn Asn1DigestOp>) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1VerifyOp {
	fn verify(&self, origdata :&[u8],signdata :&[u8], digop :Box<dyn Asn1DigestOp>) -> Result<bool,Box<dyn Error>>;
}

pub trait Asn1EncryptOp {
	fn encrypt(&self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1DecryptOp {
	fn encrypt(&self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
}