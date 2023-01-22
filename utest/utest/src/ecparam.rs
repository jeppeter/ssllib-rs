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

//use super::*;
use super::loglib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;

extargs_error_class!{EcParamError}



fn ecp256sign_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	use k256::ecdsa::{signature::Signer,signature::Verifier};
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{EcParamError,"sarr [{}] < 2", sarr.len()}
	}

	let kb = read_file_bytes(&sarr[0])?;
	let conb = read_file_bytes(&sarr[1])?;
	let kbc = k256::ecdsa::SigningKey::from(&kb)?; 



	Ok(())
}



#[extargs_map_function(ecp256sign_handler)]
pub fn load_ecparam_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"ecp256sign<ecp256sign_handler>##key.bin content.bin to sign##" : {
			"$" : 2
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}