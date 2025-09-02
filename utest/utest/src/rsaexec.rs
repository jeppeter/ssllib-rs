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
use super::pemlib::*;
use ssllib::rsa::*;
//use ssllib::impls::{Asn1SignOp,Asn1VerifyOp};
use ssllib::consts::{OID_RSA_ENCRYPTION};
use ssllib::pkcs8::{Asn1Pkcs8PrivKeyInfo};
use ssllib::impls::{X509PrivateKey,X509PublickKey};
#[allow(unused_imports)]
use ssllib::digest::{SHA256Digest,MD5Digest,SHA1Digest,SHA224Digest,SHA384Digest,SHA512Digest};
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;


extargs_error_class!{RsaExecError}



fn rsaprivplaindec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	let mut stdout = std::io::stdout();

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut rsapriv :Asn1RsaPrivateKey = Asn1RsaPrivateKey::init_asn1();
		let _ = rsapriv.decode_asn1(&code)?;
		rsapriv.print_asn1("Asn1RsaPrivateKey",0,&mut stdout)?;
	}
	Ok(())
}


pub fn get_rsa_private_key_asn1(keydata :&[u8]) -> Result<Asn1RsaPrivateKey,Box<dyn Error>> {
	let mut pkcs8v :Asn1Pkcs8PrivKeyInfo = Asn1Pkcs8PrivKeyInfo::init_asn1();
	pkcs8v.decode_asn1(keydata)?;
	pkcs8v.elem.check_safe_one("Asn1Pkcs8PrivKeyInfoElem")?;
	let types = pkcs8v.elem.val[0].pkeyalg.get_algorithm()?;
	if types != OID_RSA_ENCRYPTION {
		extargs_new_error!{RsaExecError,"not [{}] [{}]",OID_RSA_ENCRYPTION,types}
	}
	let rsadata :Vec<u8> = pkcs8v.elem.val[0].pkey.data.clone();
	let mut retv :Asn1RsaPrivateKey = Asn1RsaPrivateKey::init_asn1();
	retv.decode_asn1(&rsadata)?;
	Ok(retv)
}


fn rsasign_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	let keyfile :String;
	let binfile :String;
	let signfile :String;
	let keydata :Vec<u8>;
	let bindata :Vec<u8>;
	let signdata :Vec<u8>;
	let privkey :Asn1RsaPrivateKey ;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 3 {
		extargs_new_error!{RsaExecError,"need keyfile binfile signfile"}
	}

	keyfile= format!("{}",sarr[0]);
	binfile = format!("{}",sarr[1]);
	signfile = format!("{}",sarr[2]);

	keydata = read_file_into_der(&keyfile)?;
	bindata = read_file_bytes(&binfile)?;
	privkey = get_rsa_private_key_asn1(&keydata)?;

	let digesttype = ns.get_string("digesttype");
	let initdata :Vec<u8> = vec![];
	let ckey :Vec<u8> = vec![];
	let mut rsadig :Box<dyn X509PrivateKey>;
	let usaltsize :usize;

	let saltlen = ns.get_int("psslength");
	if saltlen < 0 {
		usaltsize = 0xff;
	} else {
		usaltsize = saltlen as usize;
	}

	rsadig = get_rsa_x509_privkey(&privkey,&digesttype,usaltsize)?;
	rsadig.sign_init(&initdata,&ckey)?;
	signdata = rsadig.sign_exec(&bindata)?;

	write_file_bytes(&signfile,&signdata)?;

	Ok(())
}


fn rsavfy_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	let keyfile :String;
	let binfile :String;
	let signfile :String;
	let keydata :Vec<u8>;
	let bindata :Vec<u8>;
	let signdata :Vec<u8>;
	let privkey :Asn1RsaPrivateKey;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 3 {
		extargs_new_error!{RsaExecError,"need keyfile binfile signfile"}
	}

	keyfile= format!("{}",sarr[0]);
	binfile = format!("{}",sarr[1]);
	signfile = format!("{}",sarr[2]);

	keydata = read_file_into_der(&keyfile)?;
	bindata = read_file_bytes(&binfile)?;
	privkey = get_rsa_private_key_asn1(&keydata)?;
	signdata = read_file_bytes(&signfile)?;

	let digesttype = ns.get_string("digesttype");
	let initdata :Vec<u8> = vec![];
	let ckey :Vec<u8> = vec![];
	let mut rsadig :Box<dyn X509PublickKey>;

	let pubkey :Asn1RsaPubkey = privkey.export_public()?;
	let usaltsize :usize;

	let saltlen = ns.get_int("psslength");
	if saltlen < 0 {
		usaltsize = 0xff;
	} else {
		usaltsize = saltlen as usize;
	}

	rsadig = get_rsa_x509_pubkey(&pubkey,&digesttype,usaltsize)?;
	rsadig.verify_init(&initdata,&ckey)?;
	let valid = rsadig.verify_exec(&bindata,&signdata)?;

	if !valid {
		extargs_new_error!{RsaExecError,"not valid "}
	}

	println!("verify {} {} {} succ", keyfile,binfile,signfile);

	Ok(())
}





fn rsapssdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	let mut stdout = std::io::stdout();

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut rsapriv :Asn1RsaPssAlgoElem = Asn1RsaPssAlgoElem::init_asn1();
		let _ = rsapriv.decode_asn1(&code)?;
		rsapriv.print_asn1("Asn1RsaPssAlgoElem",0,&mut stdout)?;
	}
	Ok(())
}

fn pssinfodec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	let mut stdout = std::io::stdout();

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut rsapriv :RsaPssSigInfoElem = RsaPssSigInfoElem::init_asn1();
		let _ = rsapriv.decode_asn1(&code)?;
		rsapriv.print_asn1("RsaPssSigInfoElem",0,&mut stdout)?;
	}
	Ok(())
}




#[extargs_map_function(rsaprivplaindec_handler,rsasign_handler,rsavfy_handler,rsapssdec_handler,pssinfodec_handler)]
pub fn load_rsaexec_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"psslength##pss length 0 for digest length -1 for auto size##" : 0,
		"rsaprivplaindec<rsaprivplaindec_handler>##binfile ... to decode rsaprivdec ##" : {
			"$" : "+"
		},
		"rsasign<rsasign_handler>##keyfile binfile signfile to sign with rsa##" : {
			"$" : 3
		},
		"rsavfy<rsavfy_handler>##keyfile binfile signfile to verify with rsa##" : {
			"$" : 3
		},
		"rsapssdec<rsapssdec_handler>##to decode RsaPssAlgo##" : {
			"$" : "+"
		},
		"pssinfodec<pssinfodec_handler>##to decode RsaPssSigInfoElem##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}