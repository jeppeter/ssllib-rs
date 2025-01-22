#[allow(unused_imports)]
use extargsparse_codegen::{extargs_load_commandline,ArgSet,extargs_map_function};
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};
#[allow(unused_imports)]
use extargsparse_worker::namespace::{NameSpaceEx};
#[allow(unused_imports)]
use extargsparse_worker::argset::{ArgSetImpl};
use extargsparse_worker::parser::{ExtArgsParser};
use extargsparse_worker::funccall::{ExtArgsParseFunc};



use std::cell::RefCell;
use std::sync::Arc;
use std::error::Error;
use std::boxed::Box;
#[allow(unused_imports)]
use regex::Regex;
#[allow(unused_imports)]
use std::any::Any;

use lazy_static::lazy_static;
use std::collections::HashMap;
use ssllib::encde::*;
use ssllib::digest::{ssllib_get_digest_operator};
use ssllib::impls::*;

use super::*;
use super::loglib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;

use crate::strop::*;

extargs_error_class!{EncDeError}



fn cipherenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	sarr = ns.get_array("subnargs");

	init_log(ns.clone())?;
	if sarr.len() < 4 {
		extargs_new_error!{EncDeError,"need ciphername keyfile ivfile infile [outfile]"}
	}

	let ciphername = format!("{}",sarr[0]);
	let keyfile = format!("{}",sarr[1]);
	let ivfile = format!("{}",sarr[2]);
	let infile = format!("{}",sarr[3]);
	let mut outfile = format!("");
	if sarr.len() > 4 {
		outfile = format!("{}",sarr[4]);
	}

	let key = read_file_bytes(&keyfile)?;
	let iv = read_file_bytes(&ivfile)?;
	let indata = read_file_bytes(&infile)?;
	let cipher :Arc<RefCell<dyn Asn1EncryptOp>>;
	let ores = get_encryptor(&ciphername);
	if ores.is_none() {
		extargs_new_error!{EncDeError,"can not find {} cipher", ciphername}
	}
	cipher = ores.unwrap();
	let _ = cipher.borrow_mut().init_encrypt(&key,&iv)?;
	let mut outdata :Vec<u8>;

	outdata = cipher.borrow_mut().encrypt_update(&indata)?;
	outdata.extend(cipher.borrow_mut().encrypt_final()?);

	if outfile.len() > 0 {
		let _ = write_file_bytes(&outfile,&outdata)?;
	} else {
		debug_buffer_trace!(indata.as_ptr(),indata.len(),"indata");
		debug_buffer_trace!(outdata.as_ptr(),outdata.len(), "outdata");
	}



	Ok(())
}

fn cipherdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	sarr = ns.get_array("subnargs");

	init_log(ns.clone())?;
	if sarr.len() < 4 {
		extargs_new_error!{EncDeError,"need ciphername keyfile ivfile infile [outfile]"}
	}

	let ciphername = format!("{}",sarr[0]);
	let keyfile = format!("{}",sarr[1]);
	let ivfile = format!("{}",sarr[2]);
	let infile = format!("{}",sarr[3]);
	let mut outfile = format!("");
	if sarr.len() > 4 {
		outfile = format!("{}",sarr[4]);
	}

	let key = read_file_bytes(&keyfile)?;
	let iv = read_file_bytes(&ivfile)?;
	let indata = read_file_bytes(&infile)?;
	let cipher :Arc<RefCell<dyn Asn1DecryptOp>>;
	let ores = get_decryptor(&ciphername);
	if ores.is_none() {
		extargs_new_error!{EncDeError,"can not find {} cipher", ciphername}
	}
	cipher = ores.unwrap();
	let _ = cipher.borrow_mut().init_decrypt(&key,&iv)?;
	let mut outdata :Vec<u8>;

	outdata = cipher.borrow_mut().decrypt_update(&indata)?;
	outdata.extend(cipher.borrow_mut().decrypt_final()?);

	if outfile.len() > 0 {
		let _ = write_file_bytes(&outfile,&outdata)?;
	} else {
		debug_buffer_trace!(indata.as_ptr(),indata.len(),"indata");
		debug_buffer_trace!(outdata.as_ptr(),outdata.len(), "outdata");
	}



	Ok(())
}


fn listenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	

	init_log(ns.clone())?;
	let names :Vec<String> = get_enc_names();
	let mut maxlen :usize = 1;
	let mut outs :String = "".to_string();
	let mut padlen :usize;
	for f in names.iter() {
		if maxlen < f.len() {
			maxlen = f.len();
		}
	}

	outs.push_str(&format!("encryption method:"));
	for i in 0..names.len() {
		if (i % 5) == 0 {
			outs.push_str("\n");
			outs.push_str("    ");
		}
		padlen = maxlen -  names[i].len();
		outs.push_str(&format!("{}",names[i]));
		for _ in 0..padlen {
			outs.push_str(" ");
		}
		outs.push_str("  ");
	}

	println!("{}",outs);
	Ok(())
}

fn dgst_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	

	init_log(ns.clone())?;
	let sarr :Vec<String>;
	let mut initv :Vec<u8> = vec![];
	let mut times :u32 = 0;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{EncDeError,"need digestname file [times] [initv]"}
	}
	let digestname = format!("{}",sarr[0]);
	let dcode = read_file_bytes(&sarr[1])?;
	let outfile = ns.get_string("output");
	let dgstop :Arc<RefCell<dyn Asn1DigestOp>>;
	if sarr.len() > 2 {
		times = parse_u64(&sarr[2])? as u32;
	}
	if sarr.len() > 3 {
		initv = read_file_bytes(&sarr[3])?;
	}

	let ores = ssllib_get_digest_operator(&digestname);
	if ores.is_none() {
		extargs_new_error!{EncDeError,"can not find {} cipher", digestname}
	}
	dgstop = ores.unwrap();
	let _ = dgstop.borrow_mut().init_digest(times,&initv)?;
	let mut outdata :Vec<u8> = vec![];

	let _ =  dgstop.borrow_mut().digest_update(&dcode)?;
	outdata.extend(dgstop.borrow_mut().digest_final()?);

	if outfile.len() > 0 {
		let _ = write_file_bytes(&outfile,&outdata)?;
	} else {
		out_buffer_data(&outdata,file!(),line!(),"outdata")?;
		//debug_buffer_trace!(dcode.as_ptr(),dcode.len(),"dcode");
		//debug_buffer_trace!(outdata.as_ptr(),outdata.len(), "outdata");
	}

	Ok(())
}

#[extargs_map_function(cipherenc_handler,cipherdec_handler,listenc_handler,dgst_handler)]
pub fn load_encde_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"cipherenc<cipherenc_handler>##encname keyfile ivfile infile [outfile]##" : {
			"$" : "+"
		},
		"cipherdec<cipherdec_handler>##encname keyfile ivfile infile [outfile]##" : {
			"$" : "+"
		},
		"listenc<listenc_handler>##to list encrypt method names##" : {
			"$" : 0
		},
		"dgst<dgst_handler>##dgsttype file [times] [ivfile] to display digest##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}