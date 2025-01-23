
use crate::impls::*;
use std::error::Error;
use sha2::{Sha256,Digest};
use hmac::{Hmac,Mac};
use crate::*;
use std::sync::{Arc};
use std::cell::RefCell;
use crate::consts::*;
//use crate::logger::*;


ssllib_error_class!{SslDigestError}

pub struct Sha256Digest {
	hasher :Vec<Sha256>,
	inited : bool,
}

impl Sha256Digest {
	pub fn calc(data :&[u8]) -> Vec<u8> {
		let mut hasher = Sha256::new();
		hasher.update(&data);
		let res = hasher.finalize();
		return res.to_vec();    
	}	

	pub fn new() -> Result<Self,Box<dyn Error>> {
		Ok(Self{ 
			hasher :vec![],
			inited : false,
		})
	}
}

impl Asn1DigestOp for Sha256Digest {
	fn init_digest(&mut self,_times :u32,_initv :&[u8]) -> Result<(),Box<dyn Error>> {
		if self.hasher.len() > 0 {
			self.hasher[0] = Sha256::new();
		} else {
			self.hasher.push(Sha256::new());
		}
		self.inited = true;
		Ok(())
	}
	fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslDigestError,"not inited"}
		}
		self.hasher[0].update(&data);
		//self.innerdata = Sha256Digest::calc(data);
		Ok(())
	}
	fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslDigestError,"not inited"}
		}
		let res = self.hasher[0].clone().finalize();
		self.inited = false;
		let _ = self.hasher.remove(0);
		return Ok(res.to_vec());
	}
}

pub type HmacSha256 = Hmac<Sha256>;

pub struct HmacSha256Digest {
	times :u32,
	initv8 :Vec<u8>,
	inited :bool,
	hasher :Vec<HmacSha256>,
}

impl HmacSha256Digest {
	pub fn new() -> Result<Self,Box<dyn Error>> {
		Ok(Self {
			//times :times,
			times :0,
			//initv8 : initv.to_vec().clone(),
			initv8 :vec![],
			inited : false,
			hasher : vec![],
		})
	}
}

impl Asn1DigestOp for HmacSha256Digest {
	fn init_digest(&mut self,times :u32,initv :&[u8]) -> Result<(),Box<dyn Error>> {
		self.inited = true;
		self.times = times;
		self.initv8 = initv.to_vec().clone();
		if self.hasher.len() > 0 {
			self.hasher[0] = HmacSha256::new_from_slice(initv)?;
		} else {
			self.hasher.push(HmacSha256::new_from_slice(initv)?);
		}
		Ok(())
	}
	fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslDigestError,"not inited"}
		}

		//self.origdata.extend(data.iter().collect::<Vec<_>>().clone());
		self.hasher[0].update(data);
		return Ok(());
	}

	fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslDigestError,"not inited"}
		}
		let cplen :usize = 32;
		let mut p :Vec<u8> = Vec::new();
		let plen :usize = 0;
		let mut curv:u8;
		let i :usize=1;
		let mut itmp :Vec<u8> = vec![];
		curv = ((i >> 24) & 0xff) as u8;
		itmp.push(curv);
		curv = ((i >> 16) & 0xff) as u8;
		itmp.push(curv);
		curv = ((i >> 8) & 0xff) as u8;
		itmp.push(curv);
		curv = ((i >> 0) & 0xff) as u8;
		itmp.push(curv);
		let mut nmac = self.hasher[0].clone();
		nmac.update(&itmp);

		let mut resdigtmp = nmac.finalize();
		let mut digtmp = resdigtmp.into_bytes();
		for i in 0..digtmp.len() {
			if (p.len()-plen) <= i {
				p.push(digtmp[i]);
			} else {
				p[i+plen] = digtmp[i];
			}
		}

		for _j in 1..self.times {
			let mut nmac = HmacSha256::new_from_slice(&self.initv8)?;
			nmac.update(&digtmp);
			resdigtmp = nmac.finalize();
			digtmp = resdigtmp.into_bytes();
			for k in 0..cplen {
				p[k+plen] ^= digtmp[k];
			}
		}


		return Ok(p);
	}
}


pub struct HmacSha256DigestSimple {
	initv8 :Vec<u8>,
	origdata :Vec<u8>,
	inited :bool,
}

impl HmacSha256DigestSimple {
	pub fn new() -> Result<Self,Box<dyn Error>> {
		Ok(HmacSha256DigestSimple {
			//initv8 : initv.to_vec().clone(),
			initv8 : vec![],
			origdata :vec![],
			inited :false,
		})
	}
}

impl Asn1DigestOp for HmacSha256DigestSimple {
	fn init_digest(&mut self,_times :u32, initv :&[u8]) -> Result<(),Box<dyn Error>> {
		self.initv8 = initv.to_vec().clone();
		self.inited = true;
		Ok(())
	}
	fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslDigestError,"not inited"}
		}
		self.origdata.extend(data.iter().collect::<Vec<_>>().clone());
		return Ok(());
	}

	fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslDigestError,"not inited"}
		}
		let mut omac = HmacSha256::new_from_slice(&self.initv8)?;
		omac.update(&self.origdata);
		let res = omac.finalize();
		return Ok(res.into_bytes().to_vec());
	}
}


pub fn calc_hmac_sha256(initkey :&[u8],data :&[u8]) -> Vec<u8> {
	let mut shmac = HmacSha256DigestSimple::new().unwrap();
	shmac.init_digest(0,initkey).unwrap();
	shmac.digest_update(data).unwrap();
	return shmac.digest_final().unwrap();
}



macro_rules! expand_digest_operator {
	($name:expr) => {
		if $name == DIGEST_SHA256 {
			let ores = Sha256Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}        
		} else if $name == DIGEST_HMAC_SHA256 {
			let ores = HmacSha256Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}
		} else if $name == DIGEST_HMAC_SHA256_SIMPLE {
			let ores = HmacSha256DigestSimple::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}
		}

		return None;
	};
}



pub fn ssllib_get_digest_operator(name :&str) -> Option<Arc<RefCell<dyn Asn1DigestOp>>> {
	expand_digest_operator!(name);
}

