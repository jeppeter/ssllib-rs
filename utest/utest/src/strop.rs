#[allow(unused_imports)]
use super::{debug_trace,debug_buffer_trace,format_buffer_log};
#[allow(unused_imports)]
use super::loglib::{log_get_timestamp,log_output_function,init_log};

#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};

use base64;
use std::error::Error;

extargs_error_class!{StrOpError}


pub fn encode_base64(bb :&[u8]) -> String {
	return base64::encode(bb);
}

#[allow(dead_code)]
pub fn decode_base64(instr :&str) -> Result<Vec<u8>,Box<dyn Error>> {
	let res = base64::decode(instr);
	if res.is_err() {
		let err = res.err().unwrap();
		extargs_new_error!{StrOpError,"can not parse [{}] for base64 error [{:?}]", instr,err}
	}
	let bv = res.unwrap();
	Ok(bv)
}

pub fn parse_u64(instr :&str) -> Result<u64,Box<dyn Error>> {
	let mut cparse = format!("{}",instr);
	let mut base :u32 = 10;
	let retv :u64;
	if cparse.starts_with("0x") || cparse.starts_with("0X") {
		cparse = cparse[2..].to_string();
		base = 16;
	} else if cparse.starts_with("x") || cparse.starts_with("X") {
		cparse = cparse[1..].to_string();
		base = 16;
	}

	match u64::from_str_radix(&cparse,base) {
		Ok(v) => {
			retv = v;
		},
		Err(e) => {
			extargs_new_error!{StrOpError, "parse [{}] error [{:?}]", instr, e}
		}
	}
	Ok(retv)
}

