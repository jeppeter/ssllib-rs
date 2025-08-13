
use crate::{ssllib_new_error,ssllib_error_class};
use std::error::Error;
use std::io::{Read};
use std::io::BufReader;


ssllib_error_class!{SslFileOpError}

pub struct RandFile {
	f : std::fs::File,
	fname :String,
}

impl RandFile {
	pub fn new(name :&str) -> Result<RandFile,Box<dyn Error>> {
		let ores = std::fs::File::open(name);
		if ores.is_err() {
			let e = ores.err().unwrap();
			ssllib_new_error!{SslFileOpError,"open {} error {:?}", name,e}
		}
		let f = ores.unwrap();
		Ok(RandFile {
			f : f,
			fname : format!("{}",name),
		})
	}
}

impl rand_core::CryptoRng  for RandFile {
}

impl rand_core::RngCore for RandFile {
	fn next_u32(&mut self) -> u32 {
		let mut buf = [0u8; 4];
		let ores = self.f.read(&mut buf);
		if ores.is_err() {
			let e = ores.err().unwrap();
			panic!("read [{}] error[{:?}]",self.fname,e);
		}
		let cnt = ores.unwrap();
		if cnt != 4 {
			panic!("can not read [{}]", self.fname);
		}
		let mut retv :u32 = 0;
		for i in 0..buf.len() {
			retv |= (buf[i] as u32) << (i * 8);
		}
		retv
	}

	fn next_u64(&mut self) -> u64 {
		let mut buf = [0u8; 8];
		let ores = self.f.read(&mut buf);
		if ores.is_err() {
			let e = ores.err().unwrap();
			panic!("read [{}] error[{:?}]",self.fname,e);
		}
		let cnt = ores.unwrap();
		if cnt != 8 {
			panic!("can not read [{}]", self.fname);
		}
		let mut retv :u64 = 0;
		for i in 0..buf.len() {
			retv |= (buf[i] as u64) << (i * 8);
		}
		retv
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		let ores = self.f.read(dest);
		if ores.is_err() {
			let e = ores.err().unwrap();
			panic!("read [{}] error[{:?}]",self.fname,e);
		}
		let cnt = ores.unwrap();
		if cnt != dest.len() {
			panic!("can not read [{}]", self.fname);	
		}
		return;
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(),rand_core::Error> {
		let ores = self.f.read(dest);
		if ores.is_err() {
			let e = ores.err().unwrap();
			let e2 = SslFileOpError::create(&format!("read {} error {:?}",self.fname,e));
			return Err(rand_core::Error::new(e2));
		}
		let cnt = ores.unwrap();
		if cnt != dest.len() {
			let e2 = SslFileOpError::create(&format!("read {} cnt {} != {}",self.fname,cnt,dest.len()));
			return Err(rand_core::Error::new(e2));
		}
		Ok(())
	}
}


pub (crate) fn read_file_bytes(fname :&str) -> Result<Vec<u8>,Box<dyn Error>> {
	if fname.len() == 0 {
		let f = std::io::stdin();
		let mut reader = BufReader::new(f);
		let mut buf :Vec<u8> = Vec::new();
		let res = reader.read_to_end(&mut buf);
		if res.is_err() {
			let err = res.err().unwrap();
			ssllib_new_error!{SslFileOpError,"read [{}] error [{:?}]", fname,err}
		}
		Ok(buf)
	} else {
		let fo = std::fs::File::open(fname);
		if fo.is_err() {
			let err = fo.err().unwrap();
			ssllib_new_error!{SslFileOpError,"can not open [{}] error[{:?}]", fname, err}
		}
		let f = fo.unwrap();
		let mut reader = BufReader::new(f);
		let mut buf :Vec<u8> = Vec::new();
		let res = reader.read_to_end(&mut buf);
		if res.is_err() {
			let err = res.err().unwrap();
			ssllib_new_error!{SslFileOpError,"read [{}] error [{:?}]", fname,err}
		}

		Ok(buf)		
	}
}

pub fn read_file(fname :&str) -> Result<String,Box<dyn Error>> {
	if fname.len() == 0 {
		let f = std::io::stdin();
		let mut reader = BufReader::new(f);
		let mut retv :String = String::new();
		let res = reader.read_to_string(&mut retv);
		if res.is_err() {
			let err = res.err().unwrap();
			ssllib_new_error!{SslFileOpError,"read [{}] error [{:?}]", fname,err}
		}
		Ok(retv)
	} else {
		let fo = std::fs::File::open(fname);
		if fo.is_err() {
			let err = fo.err().unwrap();
			ssllib_new_error!{SslFileOpError,"can not open [{}] error[{:?}]", fname, err}
		}
		let f = fo.unwrap();
		let mut reader = BufReader::new(f);
		let mut retv :String = String::new();
		let res = reader.read_to_string(&mut retv);
		if res.is_err() {
			let err = res.err().unwrap();
			ssllib_new_error!{SslFileOpError,"read [{}] error [{:?}]", fname,err}
		}

		Ok(retv)		
	}
}
