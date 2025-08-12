use base64;
use std::error::Error;
use crate::*;

ssllib_error_class!{SslibBase64Error}


pub (crate) fn encode_base64(bb :&[u8]) -> String {
	return base64::encode(bb);
}


pub (crate) fn decode_base64(instr :&str) -> Result<Vec<u8>,Box<dyn Error>> {
	let res = base64::decode(instr);
	if res.is_err() {
		let err = res.err().unwrap();
		ssllib_new_error!{SslibBase64Error,"can not parse [{}] for base64 error [{:?}]", instr,err}
	}
	let bv = res.unwrap();
	Ok(bv)
}
