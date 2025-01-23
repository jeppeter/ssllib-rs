
use std::error::Error;
//use std::cell::RefCell;
//use std::sync::Arc;

pub trait Asn1DigestOp {
	fn init_digest(&mut self,times :u32,initv :&[u8]) -> Result<(),Box<dyn Error>>;
	fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>>;
	fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1SignOp {
	fn sing_init(&mut self,key :&[u8],initv :&[u8]) -> Result<(),Box<dyn Error>>;
	fn sign_exec(&mut self,data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1VerifyOp {
	fn verify_init(&mut self,key :&[u8],initv :&[u8]) -> Result<(),Box<dyn Error>>;
	fn verify_exec(&mut self, origdata :&[u8], signdata :&[u8]) -> Result<bool,Box<dyn Error>>;
}

pub trait Asn1EncryptOp   {
	fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>>;
	fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
	fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}

pub trait Asn1DecryptOp   {
	fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>>;
	fn decrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>>;
	fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>>;
}

// pub trait Asn1EncryptOpClone : Asn1EncryptOp + Clone + Sized + Sync {	
// }

// pub trait Asn1DecryptOpClone : Asn1DecryptOp + Clone + Sized + Sync {	
// }