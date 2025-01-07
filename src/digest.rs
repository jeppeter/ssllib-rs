
use crate::impls::*;
use std::error::Error;
use sha2::{Sha256,Digest};
use hmac::{Hmac,Mac};

pub struct Sha256Digest {
	innerdata :Vec<u8>,
}

impl Sha256Digest {
	pub fn calc(data :&[u8]) -> Vec<u8> {
		let mut hasher = Sha256::new();
		hasher.update(&data);
		let res = hasher.finalize();
		return res.to_vec();    
	}	

	pub fn new() -> Self {
		Sha256Digest{ innerdata :vec![]}
	}
}

impl Asn1DigestOp for Sha256Digest {
	fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>> {
		self.innerdata = Sha256Digest::calc(data);
		Ok(())
	}
	fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
		return Ok(self.innerdata.clone());
	}
}

pub type HmacSha256 = Hmac<Sha256>;

pub struct HmacSha256Digest {
	times :u32,
	initv8 :Vec<u8>,
	origdata :Vec<u8>,
}

impl HmacSha256Digest {
	pub fn new(times :u32,initv :&[u8]) -> Result<Self,Box<dyn Error>> {
		Ok(HmacSha256Digest {
			times :times,
			initv8 : initv.to_vec().clone(),
			origdata :vec![],
		})
	}
}

impl Asn1DigestOp for HmacSha256Digest {
	fn digest_update(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>> {
		self.origdata.extend(data.iter().collect::<Vec<_>>().clone());
		return Ok(());
	}

	fn digest_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
		let omac = HmacSha256::new_from_slice(&self.initv8)?;
		let mut nmac ;
		let mut tkeylen : usize = 32;
		let cplen :usize = 32;
		let mut i :usize = 1;
		let mut p :Vec<u8> = Vec::new();
		let mut plen :usize = 0;

		while tkeylen > 0 {
			let mut itmp :Vec<u8> = Vec::new();
			let mut curv :u8;
			nmac = omac.clone();
			curv = ((i >> 24) & 0xff) as u8;
			itmp.push(curv);
			curv = ((i >> 16) & 0xff) as u8;
			itmp.push(curv);
			curv = ((i >> 8) & 0xff) as u8;
			itmp.push(curv);
			curv = ((i >> 0) & 0xff) as u8;
			itmp.push(curv);
			nmac.update(&self.origdata);
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


			for _ in 1..self.times {
				nmac = omac.clone();
				nmac.update(&digtmp);
				resdigtmp = nmac.finalize();
				digtmp = resdigtmp.into_bytes();
				for k in 0..cplen {
					p[k+plen] ^= digtmp[k];
				}
			}

			tkeylen -= cplen;
			i += 1;
			plen += cplen;
		}
		return Ok(p);
	}
}

pub fn calc_hmac_sha256(initkey :&[u8],data :&[u8]) -> Vec<u8> {
	let mut hmac = HmacSha256::new_from_slice(initkey).unwrap();
	hmac.update(data);
	let res = hmac.finalize();
	return res.into_bytes().to_vec();
}

