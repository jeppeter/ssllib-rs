#[allow(unused_imports)]
use extargsparse_codegen::{extargs_load_commandline,ArgSet,extargs_map_function};
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};
#[allow(unused_imports)]
use extargsparse_worker::namespace::{NameSpaceEx};
#[allow(unused_imports)]
use extargsparse_worker::options::{ExtArgsOptions};
#[allow(unused_imports)]
use extargsparse_worker::argset::{ArgSetImpl};
use extargsparse_worker::parser::{ExtArgsParser};
use extargsparse_worker::funccall::{ExtArgsParseFunc};
#[allow(unused_imports)]
use extargsparse_worker::const_value::{COMMAND_SET,SUB_COMMAND_JSON_SET,COMMAND_JSON_SET,ENVIRONMENT_SET,ENV_SUB_COMMAND_JSON_SET,ENV_COMMAND_JSON_SET,DEFAULT_SET};


#[allow(unused_imports)]
use std::cell::RefCell;
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use std::error::Error;
use std::boxed::Box;
#[allow(unused_imports)]
use regex::Regex;
#[allow(unused_imports)]
use std::any::Any;
use lazy_static::lazy_static;
use std::collections::HashMap;


use super::loglib::*;
use super::pemlib::*;
use ssllib::pkcs7::*;
use ssllib::utils::*;
use ssllib::x509::*;
use asn1obj::asn1impl::*;

extargs_error_class!{Pkcs7Error}

fn pkcs7dec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs7 :Asn1Pkcs7 = Asn1Pkcs7::init_asn1();
		let size = pkcs7.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("Asn1Pkcs7 in {} size {}[0x{:x}]\n",f,size,size);
		pkcs7.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn pkcs7signerinfodec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs7siginfo :Asn1Pkcs7SignerInfo = Asn1Pkcs7SignerInfo::init_asn1();
		let size = pkcs7siginfo.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("Asn1Pkcs7SignerInfo in {} size {}[0x{:x}]\n",f,size,size);
		pkcs7siginfo.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn pkcs7appsignature_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");

	if sarr.len() < 3 {
		extargs_new_error!{Pkcs7Error,"need x509file pkeyname dgstname"}
	}

	let x509file = format!("{}",sarr[0]);
	let pkeyname = format!("{}",sarr[1]);
	let dgstname = format!("{}",sarr[2]);
	let ooidpkey = get_pkey_oid(&pkeyname);
	if ooidpkey.is_none() {
		extargs_new_error!{Pkcs7Error,"no pkey oid for {}",pkeyname}
	}

	let ooiddgst = get_digest_oid(&dgstname);
	if ooiddgst.is_none() {
		extargs_new_error!{Pkcs7Error,"no dgst oid for {}",dgstname}	
	}
	let oidpkey = ooidpkey.unwrap();
	let oiddgst = ooiddgst.unwrap();
	let x509code = read_file_into_der(&x509file)?;
	let mut cert :Asn1X509 = Asn1X509::init_asn1();
	let _ = cert.decode_asn1(&x509code)?;
	let signerinfo = Asn1Pkcs7SignerInfo::new_signer_info_from_cert(&cert,&oidpkey,&oiddgst)?;
	let mut outf = std::io::stdout();
	signerinfo.print_asn1("Asn1Pkcs7SignerInfo",0,&mut outf)?;


	Ok(())
}


#[extargs_map_function(pkcs7dec_handler,pkcs7signerinfodec_handler,pkcs7appsignature_handler)]
pub fn load_pkcs7_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"pkcs7dec<pkcs7dec_handler>##file ... ##" : {
			"$" : "+"
		},
		"pkcs7signerinfodec<pkcs7signerinfodec_handler>####" : {
			"$" : "+"
		},
		"pkcs7appsignature<pkcs7appsignature_handler>##x509file pkeyname dgstname to add##" : {
			"$" : 3
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}