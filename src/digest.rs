
use crate::impls::*;
use std::error::Error;
use sha2::{Sha256,Digest};

pub struct Sha256Digest {	
}

impl Sha256Digest {
	pub fn calc(data :&[u8]) -> Vec<u8> {
	    let mut hasher = Sha256::new();
	    hasher.update(&data);
	    let res = hasher.finalize();
	    return res.to_vec();    
	}	

	pub fn new() -> Self {
		Sha256Digest{}
	}
}

impl Asn1DigestOp for Sha256Digest {
	fn digest(&self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv = Sha256Digest::calc(data);
		Ok(retv)
	}
}

