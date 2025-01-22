
use ssllib::digest::{ssllib_get_digest_operator};
use ssllib::impls::Asn1DigestOp;
use std::sync::Arc;
use std::cell::RefCell;
use std::error::Error;

use extargsparse_worker::{extargs_new_error,extargs_error_class};

extargs_error_class!{DgstError}

pub fn dgst_get_value(dgstname :&str,times :u32,initv :&[u8],dcode:&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let ores = ssllib_get_digest_operator(dgstname);
	let dgstop :Arc<RefCell<dyn Asn1DigestOp>>;
	if ores.is_none() {
		extargs_new_error!{DgstError,"can not find {} cipher", dgstname}
	}
	dgstop = ores.unwrap();
	let _ = dgstop.borrow_mut().init_digest(times,initv)?;
	let mut outdata :Vec<u8> = vec![];

	let _ =  dgstop.borrow_mut().digest_update(dcode)?;
	outdata.extend(dgstop.borrow_mut().digest_final()?);
	Ok(outdata)
}