

use crate::fileop::{read_file,read_file_bytes};
#[allow(unused_imports)]
use regex::Regex;

use crate::*;
use base64;
use std::error::Error;

ssllib_error_class!{SsllibPemError}


fn decode_base64(instr :&str) -> Result<Vec<u8>,Box<dyn Error>> {
	let res = base64::decode(instr);
	if res.is_err() {
		let err = res.err().unwrap();
		ssllib_new_error!{SsllibPemError,"can not parse [{}] for base64 error [{:?}]", instr,err}
	}
	let bv = res.unwrap();
	Ok(bv)
}


fn pem_to_der(ins :&str) -> Result<(Vec<u8>,String),Box<dyn Error>> {
	let retv :Vec<u8>;
	let sarr :Vec<&str> = ins.split("\n").collect();
	let mut bstr :String = "".to_string();
	let regstr = "[\\-]+BEGIN\\s([^\\-]+)[\\-]+".to_string();	
	let mut notice :String = "".to_string();

	let ro = Regex::new(&regstr);
	if ro.is_err() {
		let e = ro.err().unwrap();
		ssllib_new_error!{SsllibPemError,"compile [{}] error[{:?}]", regstr,e}
	}
	let re = ro.unwrap();

	for l in sarr.iter() {
		let mut c :String = format!("{}",l);
		c = c.trim_end_matches("\r").to_string();
		if !c.starts_with("---") {
			bstr.push_str(&format!("{}",c));
		} else {
			let caps = re.captures(&c);
			if caps.is_some() {
				let cp = caps.unwrap();
				notice = format!("{}", cp.get(1).map_or("", |m| m.as_str()));
			}
		}
	}
	retv = decode_base64(&bstr)?;
	Ok((retv,notice))
}

pub (crate) fn read_file_into_der(infile :&str) -> Result<Vec<u8>,Box<dyn Error>> {
	let ores = read_file(infile);
	let retdata :Vec<u8>;
	if ores.is_err() {
		retdata = read_file_bytes(infile)?;
	} else {
		let sv = ores.unwrap();
		let bres = pem_to_der(&sv);
		if bres.is_err() {
			retdata = read_file_bytes(infile)?;
		} else {
			(retdata,_) = bres.unwrap();
		}
	}
	Ok(retdata)
}
