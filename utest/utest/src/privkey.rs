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

use super::loglib::*;
#[allow(unused_imports)]
use super::fileop::*;
use super::pemlib::*;
use ssllib::consts::*;
use ssllib::config::*;
use ssllib::x509::*;
use ssllib::rsa::*;
use asn1obj::asn1impl::*;
use std::io::Write;


extargs_error_class!{PrivKeyError}

fn rsaprivdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String>;
	let passin :String = ns.get_string("passin");
	let mut sout = std::io::stdout();

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let data = read_file_into_der(f)?;
		let mut envcfg :ConfigValue = ConfigValue::new("{}")?;
		let _ = envcfg.set_str(KEY_JSON_PASSIN,&passin)?;
		let mut sig :Asn1X509Sig = Asn1X509Sig::init_asn1();
		let _ = sig.decode_asn1(&data)?;
		let _ = sig.print_asn1("Asn1X509Sig",0,&mut sout)?;
		let cfg = sig.get_cmd(&envcfg)?;
		let types = cfg.get_str(KEY_JSON_TYPE)?;
		if types == KEY_JSON_PBES2 {
			let ores = cfg.get_config(KEY_JSON_PBES2)?;
			if ores.is_none() {
				extargs_new_error!{PrivKeyError,"no [{}] found", KEY_JSON_PBES2}
			}
			let pbes2 = ores.unwrap();
			let types2 = pbes2.get_str(KEY_JSON_TYPE)?;
			if types2 == KEY_JSON_PBKDF2  {
				let decdata = pbes2.get_u8_array(KEY_JSON_DECDATA)?;
				let mut netpkey :Asn1NetscapePkey = Asn1NetscapePkey::init_asn1();
				let _ = netpkey.decode_asn1(&decdata)?;
				let _ = netpkey.print_asn1("Asn1NetscapePkey",0,&mut sout)?;
				let cs = netpkey.get_algorithm()?;
				if cs == OID_RSA_ENCRYPTION {
					let mut privk :Asn1RsaPrivateKey = Asn1RsaPrivateKey::init_asn1();
					let decdata = netpkey.get_privdata()?;
					let _ = privk.decode_asn1(&decdata)?;
					privk.print_asn1("Asn1RsaPrivateKey",0,&mut sout)?;
				} else {
					extargs_new_error!{PrivKeyError,"not support oid[{}]",cs}
				}
			} else {
				extargs_new_error!{PrivKeyError,"not support type[{}]",types2}	
			}
		} else {
			extargs_new_error!{PrivKeyError,"not support type[{}]",types}
		}
	}

	Ok(())
}

#[extargs_map_function(rsaprivdec_handler)]
pub fn load_privkey_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"rsaprivdec<rsaprivdec_handler>##fname ... to encode base64##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}