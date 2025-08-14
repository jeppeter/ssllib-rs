
use crate::impls::*;
use std::error::Error;
use sha1::{Sha1};
use sha2::{Sha224,Sha256,Sha384,Sha512,Digest};
use md5::{Md5};
use hmac::{Hmac,Mac};
use crate::*;
use std::sync::{Arc};
use std::cell::RefCell;
use crate::consts::*;
use lazy_static::lazy_static;
use std::collections::HashMap;
//use crate::logger::*;


ssllib_error_class!{SslDigestError}

macro_rules! decl_digest_class {
	($name:ident,$innercall:ident,$clsname:expr) => {
		pub struct $name {
			hasher :Vec<$innercall>,
			inited : bool,
		}

		impl $name {
			pub fn calc(data :&[u8]) -> Vec<u8> {
				let mut hasher = $innercall::new();
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

		impl Asn1DigestOp for $name {
			fn init_digest(&mut self,_times :u32,_initv :&[u8]) -> Result<(),Box<dyn Error>> {
				if self.hasher.len() > 0 {
					self.hasher[0] = $innercall::new();
				} else {
					self.hasher.push($innercall::new());
				}
				self.inited = true;
				Ok(())
			}
			fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>> {
				if !self.inited {
					ssllib_new_error!{SslDigestError,"{} not inited",$clsname}
				}
				self.hasher[0].update(&data);
				Ok(())
			}
			fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
				if !self.inited {
					ssllib_new_error!{SslDigestError,"{} not inited",$clsname}
				}
				let res = self.hasher[0].clone().finalize();
				self.inited = false;
				let _ = self.hasher.remove(0);
				return Ok(res.to_vec());
			}
		}

	}
}

decl_digest_class!{MD5Digest,Md5,"MD5Digest"}
decl_digest_class!{SHA1Digest,Sha1,"SHA1Digest"}
decl_digest_class!{SHA224Digest,Sha224,"SHA224Digest"}
decl_digest_class!{SHA256Digest,Sha256,"SHA256Digest"}
decl_digest_class!{SHA384Digest,Sha384,"SHA384Digest"}
decl_digest_class!{SHA512Digest,Sha512,"SHA512Digest"}


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
			let ores = SHA256Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}        
		} else if $name == DIGEST_HMAC_SHA256 {
			let ores = HmacSha256Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}
		} else if $name == DIGEST_SHA1 {
			let ores = SHA1Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}
		} else if $name == DIGEST_SHA224 {
			let ores = SHA224Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}
		} else if $name == DIGEST_SHA384 {
			let ores = SHA384Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}
		} else if $name == DIGEST_SHA512 {
			let ores = SHA512Digest::new();
			if ores.is_ok() {
				return Some(Arc::new(RefCell::new(ores.unwrap())));    
			}
		} else if $name == DIGEST_MD5 {
			let ores = MD5Digest::new();
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

#[allow(unused_mut)]
fn create_digest_oid() -> HashMap<String,String> {
	let mut retv :HashMap<String,String> = HashMap::new();

	retv
}

lazy_static!{
	static ref DIGEST_OID_MAPS :HashMap<String,String> = {
		create_digest_oid()
	};
}

pub fn ssllib_get_digest_by_oid(oid :&str) -> Option<Arc<RefCell<dyn Asn1DigestOp>>> {
	match DIGEST_OID_MAPS.get(oid) {
		None => {
			return None;
		},
		Some(v) => {
			return ssllib_get_digest_operator(v);
		}
	}
}

pub (crate) fn get_hmac_sha256_key(passv8 :&[u8], saltv8 :&[u8], itertimes : usize) -> Vec<u8> {
	let mut omac = HmacSha256Digest::new().unwrap();
	omac.init_digest(itertimes as u32,passv8).unwrap();
	omac.digest_update(saltv8).unwrap();
	return omac.digest_final().unwrap();
}

