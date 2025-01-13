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
use asn1obj::base::*;
use super::fileop::*;

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
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = signerinfo.encode_asn1()?;
		let _ = write_file_bytes(&output,&code)?;
	}


	Ok(())
}


fn pkcs7signerinfoaddauthattr_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");

	if sarr.len() < 3 {
		extargs_new_error!{Pkcs7Error,"need x509file pkeyname dgstname"}
	}

	let sifile = format!("{}",sarr[0]);
	let oid = format!("{}",sarr[1]);
	let oanyfile = format!("{}",sarr[2]);
	let sicode = read_file_into_der(&sifile)?;
	let oanycode = read_file_into_der(&oanyfile)?;

	let mut si :Asn1Pkcs7SignerInfo = Asn1Pkcs7SignerInfo::init_asn1();
	let _  =si.decode_asn1(&sicode)?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	let mut outf = std::io::stdout();
	oany.decode_asn1(&oanycode)?;
	si.append_auth_attr(&oid,&oany)?;

	si.print_asn1("Asn1Pkcs7SignerInfo",0,&mut outf)?;
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = si.encode_asn1()?;
		let _ = write_file_bytes(&output,&code)?;
	}


	Ok(())
}

const SPC_STATEMENT_TYPE_OBJID :&str = "1.3.6.1.4.1.311.2.1.11";
const SPC_INDIRECT_DATA_OBJID :&str = "1.3.6.1.4.1.311.2.1.4";
const PKCS9_CONTENT_TYPE_OID :&str = "1.2.840.113549.1.9.3";

fn pkcs7sign_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
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
	let mut si = Asn1Pkcs7SignerInfo::new_signer_info_from_cert(&cert,&oidpkey,&oiddgst)?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	let mut outf = std::io::stdout();
	let mut oany :Asn1Any = Asn1Any::init_asn1();


	let mut oid :String;
	let mut obj :Asn1Object = Asn1Object::init_asn1();
	let _ = obj.set_value(SPC_INDIRECT_DATA_OBJID)?;
	oid = PKCS9_CONTENT_TYPE_OID.to_string();
	oany.tag = 0x31;
	oany.data = obj.encode_asn1()?;

	let _ = si.append_auth_attr(&oid,&oany)?:

	oid = = SPC_STATEMENT_TYPE_OBJID.to_string();
	if ns.get_bool("pkcs7comm") {
		oany.tag = 0x31;
		oany.data = vec![0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x16];
	} else {
		oany.tag = 0x31;
		oany.data = vec![0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x15];
	}
	let _ = si.append_auth_attr(&oid,&oany)?;

	let mut pkcs7obj :Asn1Pkcs7 = Asn1Pkcs7::init_asn1();
	let _ = pkcs7obj.add_signer(&si)?;
	



	Ok(())
}


#[extargs_map_function(pkcs7dec_handler,pkcs7signerinfodec_handler,pkcs7appsignature_handler,pkcs7signerinfoaddauthattr_handler,pkcs7sign_handler)]
pub fn load_pkcs7_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"certs" : [],
		"xcerts" : [],
		"crls" : [],
		"pkcs7comm" : false,
		"pkcs7dec<pkcs7dec_handler>##file ... ##" : {
			"$" : "+"
		},
		"pkcs7signerinfodec<pkcs7signerinfodec_handler>####" : {
			"$" : "+"
		},
		"pkcs7appsignature<pkcs7appsignature_handler>##x509file pkeyname dgstname to add and output##" : {
			"$" : 3
		},
		"pkcs7signerinfoaddauthattr<pkcs7signerinfoaddauthattr_handler>##pkcs7signerinfofile oid oanyfile to append ##" : {
			"$" : 3
		},
		"pkcs7sign<pkcs7sign_handler>##x509file pkeyname dgstname ##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}