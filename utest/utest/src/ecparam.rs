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
use asn1obj::asn1impl::Asn1Op;

use ssllib::ec::*;


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

use super::*;
use super::loglib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;
use rand_core::OsRng; 


extargs_error_class!{EcParamError}


fn eck256gen_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	init_log(ns.clone())?;

	let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng); 
	let sk=signing_key.to_bytes();

	let verify_key = k256::ecdsa::VerifyingKey::from(&signing_key); 
	let vk=verify_key.to_bytes();

	debug_buffer_trace!(sk.as_ptr(),sk.len(),"secret key");
	debug_buffer_trace!(vk.as_ptr(),vk.len(),"public key");


	Ok(())
}


fn eck256sign_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	use k256::ecdsa::{signature::Signer};
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{EcParamError,"sarr [{}] < 2", sarr.len()}
	}

	let kb = read_file_bytes(&sarr[0])?;
	let conb = read_file_bytes(&sarr[1])?;
	let signk = k256::ecdsa::SigningKey::from_bytes(&kb)?; 
	let signb :k256::ecdsa::Signature = signk.sign(&conb);

	let outf = ns.get_string("output");
	let vb :&[u8] = signb.as_ref();


	if outf.len() > 0 {
		let _  = write_file_bytes(&outf,vb)?;
	} else {
		debug_buffer_trace!(vb.as_ptr(),vb.len(),"encode bytes");
	}


	Ok(())
}

fn eck256vfy_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	use k256::ecdsa::{signature::Verifier};
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 3 {
		extargs_new_error!{EcParamError,"sarr [{}] < 3", sarr.len()}
	}

	let pukb = read_file_bytes(&sarr[0])?;
	let conb = read_file_bytes(&sarr[1])?;
	let signb = read_file_bytes(&sarr[2])?;
	let vfyk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pukb)?; 
	let signk :k256::ecdsa::Signature = k256::ecdsa::Signature::try_from(signb.as_slice())?; 

	let ores = vfyk.verify(&conb,&signk);

	if ores.is_ok() {
		println!("verify ok");
	} else {
		extargs_new_error!{EcParamError,"not ok"}
	}



	Ok(())
}


fn ecp384gen_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	init_log(ns.clone())?;

	let signing_key = p384::ecdsa::SigningKey::random(&mut OsRng); 
	let sk=signing_key.to_bytes();

	let verify_key = p384::ecdsa::VerifyingKey::from(&signing_key); 
	let ep = verify_key.to_encoded_point(false);
	let vk= ep.to_bytes();

	debug_buffer_trace!(sk.as_ptr(),sk.len(),"secret key");
	debug_buffer_trace!(vk.as_ptr(),vk.len(),"public key");


	Ok(())
}


fn ecp384sign_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	use p384::ecdsa::{signature::Signer};
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{EcParamError,"sarr [{}] < 2", sarr.len()}
	}

	let kb = read_file_bytes(&sarr[0])?;
	let conb = read_file_bytes(&sarr[1])?;
	let signk = p384::ecdsa::SigningKey::from_bytes(&kb)?; 
	let signb :p384::ecdsa::Signature = signk.sign(&conb);

	let outf = ns.get_string("output");
	let vb :&[u8] = signb.as_ref();


	if outf.len() > 0 {
		let _  = write_file_bytes(&outf,vb)?;
	} else {
		debug_buffer_trace!(vb.as_ptr(),vb.len(),"encode bytes");
	}


	Ok(())
}

fn ecp384vfy_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	use p384::ecdsa::{signature::Verifier};
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 3 {
		extargs_new_error!{EcParamError,"sarr [{}] < 3", sarr.len()}
	}

	let pukb = read_file_bytes(&sarr[0])?;
	let conb = read_file_bytes(&sarr[1])?;
	let signb = read_file_bytes(&sarr[2])?;
	let vfyk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&pukb)?; 
	let signk :p384::ecdsa::Signature = p384::ecdsa::Signature::try_from(signb.as_slice())?; 

	let ores = vfyk.verify(&conb,&signk);

	if ores.is_ok() {
		println!("verify ok");
	} else {
		extargs_new_error!{EcParamError,"not ok"}
	}

	Ok(())
}

fn ecx9pentdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_bytes(f)?;
		let mut xname = X9_62_PENTANOMIAL::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("X9_62_PENTANOMIAL",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode X9_62_PENTANOMIAL");
	}

	Ok(())
}

fn ecchartwodec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_bytes(f)?;
		let mut xname = X9_62_CHARACTERISTIC_TWO::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("X9_62_CHARACTERISTIC_TWO",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode X9_62_CHARACTERISTIC_TWO");
	}

	Ok(())
}

#[extargs_map_function(eck256sign_handler,eck256vfy_handler,eck256gen_handler,ecp384sign_handler,ecp384vfy_handler,ecp384gen_handler,ecx9pentdec_handler,ecchartwodec_handler)]
pub fn load_ecparam_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"eck256gen<eck256gen_handler>##to generate ec keys##" : {
			"$" : 0
		},
		"eck256sign<eck256sign_handler>##key.bin content.bin to sign##" : {
			"$" : 2
		},
		"eck256vfy<eck256vfy_handler>##pubkey.bin content.bin sign.bin to verify##" : {
			"$" : 3
		},
		"ecp384gen<ecp384gen_handler>##to generate ec keys##" : {
			"$" : 0
		},
		"ecp384sign<ecp384sign_handler>##key.bin content.bin to sign##" : {
			"$" : 2
		},
		"ecp384vfy<ecp384vfy_handler>##pubkey.bin content.bin sign.bin to verify##" : {
			"$" : 3
		},
		"ecx9pentdec<ecx9pentdec_handler>##binfile .. to decode X9_62_PENTANOMIAL##" : {
			"$" : "+"
		},
		"ecchartwodec<ecchartwodec_handler>##binfile ... to decode X9_62_CHARACTERISTIC_TWO##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}