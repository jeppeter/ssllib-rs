
use std::error::Error;
use num_bigint::{BigInt};
use num_traits::{zero};
use crate::*;

ssllib_error_class!{SslSerdeObjError}


#[allow(dead_code)]
pub struct StringVisitor(pub String);

impl<'de> serde::de::Visitor<'de> for StringVisitor {
	type Value = String;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "an string")
	}

	fn visit_str<E>(self, v :&str) -> Result<Self::Value,E>
	where E :Error
	{
		Ok(format!("{}",v))
	}
}

pub fn parse_to_bigint(instr :&str) -> Result<BigInt,Box<dyn Error>> {
	let mut _cparse = format!("{}",instr);
	let mut base :u32 = 10;
	let mut retv :BigInt = zero();
	let mut curv :BigInt ;
	let mut curvi :i32;
	let mut addi :i32 = 0;
	let mut bbchar :String;
	let mut negv :bool = false;
	let cparse :Vec<u8>;
	if _cparse.starts_with("0x") || _cparse.starts_with("0X") {
		_cparse = _cparse[2..].to_string();
		base = 16;
		addi += 2;
	} else if _cparse.starts_with("x") || _cparse.starts_with("X") {
		_cparse = _cparse[1..].to_string();
		base = 16;
		addi += 1;
	}

	if _cparse.starts_with("-") {
		_cparse = _cparse[1..].to_string();
		negv = true;
		addi += 1;
	}

	cparse = _cparse.as_bytes().to_vec();

	if cparse.len() == 0 {
		ssllib_new_error!{SslSerdeObjError,"not valid [{}]",instr};
	}

	let mut lasti :usize = 0;
	let mut idx :i32 = 0;
	while lasti < cparse.len() {
		if base == 10 {
			if cparse[lasti] >= ('0' as u8) && cparse[lasti] <= ('9' as u8) {
				curvi = (cparse[lasti] - ('0' as u8)) as i32;
			} else {
				bbchar = "".to_string();
				if cparse[lasti] >= 0x20 && cparse[lasti] <= 0x7e {
					bbchar.push(cparse[lasti] as char);
				} else {
					bbchar.push_str(&format!("char[0x{:x}]",cparse[lasti]));
				}
				
				ssllib_new_error!{SslSerdeObjError,"[{}] character not valid [{}]", idx + addi,bbchar}
			}
			curv = curvi.into();
			retv *= 10;
			retv += curv;
		} else {
			if cparse[lasti] >= ('0'  as u8) && cparse[lasti] <= ('9' as u8) {
				curvi = (cparse[lasti] - ('0' as u8)) as i32;
			} else if cparse[lasti] >= ('a'  as u8) && cparse[lasti] <= ('f' as u8){
				curvi = (cparse[lasti] - ('a' as u8)) as i32 + 10;
			} else if cparse[lasti] >= ('A' as u8 ) && cparse[lasti] <= ('F' as u8)  { 
				curvi = (cparse[lasti] - ('A' as u8)) as i32 + 10;
			} else {
				bbchar = "".to_string();
				if cparse[lasti] >= 0x20 && cparse[lasti] <= 0x7e {
					bbchar.push(cparse[lasti] as char);
				} else {
					bbchar.push_str(&format!("char[0x{:x}]",cparse[lasti]));
				}

				ssllib_new_error!{SslSerdeObjError,"[{}] character not valid [{}]", idx + addi,bbchar}
			}
			curv = curvi.into();
			retv *= 16;
			retv += curv;
		}
		lasti += 1;
		idx += 1;
	}

	if negv {
		retv = -retv;
	}
	Ok(retv)
}
