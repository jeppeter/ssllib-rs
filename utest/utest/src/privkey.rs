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
use asn1obj::base::*;


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
use super::pemlib::*;
use super::consts::*;
use ssllib::consts::*;
use ssllib::config::*;
use ssllib::pkcs8::*;
use ssllib::x509::*;
use ssllib::rsa::*;
use ssllib::ec::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use std::io::Write;
use rand_core::OsRng; 

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
				debug_buffer_trace!(decdata.as_ptr(),decdata.len(),"decdata");
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

fn rsaprivgen_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String>;
	let passout :String = ns.get_string("passout");
	let mut sout = std::io::stdout();
	let mut randfile :Option<String> = None;
	let bits :usize;
	let ciphername :String;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{PrivKeyError,"need bits"}
	}

	match i64::from_str_radix(&(sarr[0]),10) {
		Ok(v) => {
			bits = v as usize;
		},
		Err(e) => {
			extargs_new_error!{PrivKeyError, "parse [{}] error [{:?}]", sarr[0], e}
		}
	}
	if sarr.len() > 1 {
		randfile = Some(format!("{}",sarr[1]));
	}
	let privk :Asn1RsaPrivateKey = Asn1RsaPrivateKey::generate(bits,randfile)?;
	let data = privk.encode_asn1()?;
	privk.print_asn1("Asn1RsaPrivateKey",0,&mut sout)?;
	debug_buffer_trace!(data.as_ptr(),data.len(),"data len");
	let mut netpkey :Asn1NetscapePkey = Asn1NetscapePkey::init_asn1();
	let mut cfg :ConfigValue = ConfigValue::new("{}")?;
	let _ = cfg.set_str(KEY_JSON_TYPE,KEY_JSON_RSA)?;
	let _ = cfg.set_str(KEY_JSON_PASSOUT,&passout)?;
	let _ = netpkey.set_algorithm(&cfg)?;
	let _ = netpkey.set_privdata(&data)?;
	let sdata = netpkey.encode_asn1()?;
	debug_buffer_trace!(sdata.as_ptr(),sdata.len(),"sdata");
	let mut ncfg :ConfigValue= ConfigValue::new("{}")?;
	let _ = ncfg.set_str(KEY_JSON_TYPE,KEY_JSON_PBKDF2)?;
	let _ = ncfg.set_u8_array(KEY_JSON_DECDATA,&sdata)?;
	ciphername = ns.get_string("ciphername");
	let _ = ncfg.set_str(KEY_JSON_ENCTYPE,&ciphername)?;
	let mut bcfg :ConfigValue = ConfigValue::new("{}")?;
	let _ = bcfg.set_str(KEY_JSON_DIGESTTYPE,KEY_HMAC_WITH_SHA256);
	let _ = bcfg.set_i64(KEY_JSON_TIMES,2048)?;
	let _ = bcfg.set_str(KEY_JSON_PASSIN,&passout)?;

	if sarr.len() > 1 {
		let _ = ncfg.set_str(KEY_JSON_RANDFILE,&sarr[1])?;
		let _ = bcfg.set_str(KEY_JSON_RANDFILE,&sarr[1])?;
	}
	let _ = ncfg.set_config(KEY_JSON_PBKDF2,&bcfg)?;
	let _ = ncfg.set_str(KEY_JSON_PASSIN,&passout)?;
	cfg = ConfigValue::new("{}")?;
	let _ = cfg.set_str(KEY_JSON_TYPE,KEY_JSON_PBES2)?;
	let _ = cfg.set_config(KEY_JSON_PBES2,&ncfg)?;
	let mut sigv :Asn1X509Sig = Asn1X509Sig::init_asn1();
	let _ = sigv.set_cmd(&cfg)?;
	let data = sigv.encode_asn1()?;
	let outfile = ns.get_string("output");
	if outfile.len() > 0 {
		let _ = write_file_bytes(&outfile,&data)?;
	} else {
		debug_buffer_trace!(data.as_ptr(),data.len(),"outbuf");
	}

	Ok(())
}

fn ecprivdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
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
				let mut p8priv :Asn1Pkcs8PrivKeyInfo = Asn1Pkcs8PrivKeyInfo::init_asn1();
				debug_buffer_trace!(decdata.as_ptr(),decdata.len(),"decdata");
				let _ = p8priv.decode_asn1(&decdata)?;
				let _ = p8priv.print_asn1("Asn1Pkcs8PrivKeyInfo",0,&mut sout)?;
				let data :Vec<u8> = p8priv.get_pkey()?;
				let algor :Asn1X509Algor = p8priv.get_algor()?;
				let algstr :String = algor.get_algorithm()?;
				if algstr == OID_EC_PUBLICK_KEY {
					let mut ecprivkey :EC_PRIVATEKEY = EC_PRIVATEKEY::init_asn1();
					let _ = ecprivkey.decode_asn1(&data)?;
					let oany :Option<Asn1Any> = algor.get_param()?;
					if oany.is_some() {
						let cany :Asn1Any = oany.as_ref().unwrap().clone();
						let mut ecobj :Asn1Object = Asn1Object::init_asn1();
						let objdata :Vec<u8> = cany.encode_asn1()?;
						let _ = ecobj.decode_asn1(&objdata)?;
						let s :String = format!("object {}\n",ecobj.get_value());
						let _ = sout.write(s.as_bytes())?;

					}
					ecprivkey.print_asn1("EC_PRIVATEKEY",0,&mut sout)?;
				} else {
					extargs_new_error!{PrivKeyError,"[{}] not valid key", algstr}
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

fn ecprivgen_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let mut typestr :String = format!("k256");
	let passin :String;
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() > 0 {
		typestr = format!("{}",sarr[0]);
	}

	if typestr == EC_K256_TYPE {
		let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng); 
		let sk=signing_key.to_bytes();

		let verify_key = k256::ecdsa::VerifyingKey::from(&signing_key); 
		let vk=verify_key.to_bytes();
		let mut privkey :EC_PRIVATEKEY = EC_PRIVATEKEY::init_asn1();
		let _ = privkey.set_private_key(&sk)?;
		let _ = privkey.set_public_key(&vk)?;

	} else {
		extargs_new_error!{PrivKeyError,"not supported type [{}]",typestr}
	}


	Ok(())
}


#[extargs_map_function(rsaprivdec_handler,rsaprivgen_handler,ecprivdec_handler,ecprivgen_handler)]
pub fn load_privkey_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"rsaprivdec<rsaprivdec_handler>##fname ... to encode base64##" : {
			"$" : "+"
		},
		"rsaprivgen<rsaprivgen_handler>##bits [randfile] to generate bits##" : {
			"$" : "+"
		},
		"ecprivdec<ecprivdec_handler>##fname ... to decode ec private key##" : {
			"$" : "+"
		},
		"ecprivgen<ecprivgen_handler>##[typename] to generate ec param k256 p384 p521##" : {
			"$" : "?"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}