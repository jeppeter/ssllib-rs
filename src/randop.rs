
use rand;
use crate::fileop::*;
use std::error::Error;
use rand_core::CryptoRng;
use rand_core::RngCore;

pub struct RandOps {
	gencore : Option<rand::rngs::ThreadRng>,
	filerand : Option<RandFile>,
	begen : bool,
}

impl RandOps {
	pub fn new(fname :Option<String>) -> Result<Self,Box<dyn Error>> {
		let mut retv = RandOps {
			gencore : None,
			filerand : None,
			begen : true,
		};
		if fname.is_none() {
			retv.gencore = Some(rand::thread_rng());
		} else {
			retv.filerand = Some(RandFile::new(fname.as_ref().unwrap())?);
			retv.begen = false;
		}
		Ok(retv)
	}

	pub fn get_bytes(&mut self, num :usize) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut buf :Vec<u8> = Vec::new();
		for _ in 0..num {
			buf.push(0x0);
		}
		if self.begen {
			self.gencore.as_mut().unwrap().try_fill_bytes(&mut buf)?;
		} else {
			self.filerand.as_mut().unwrap().try_fill_bytes(&mut buf)?;
		}
		Ok(buf)
	}
}