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
use ssllib::pkcs12::*;
use asn1obj::asn1impl::*;

fn pkcs12dec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs12 :Asn1Pkcs12 = Asn1Pkcs12::init_asn1();
		let size = pkcs12.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("Asn1Pkcs12 in {} size {}[0x{:x}]\n",f,size,size);
		pkcs12.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn pkcs12vfy_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let passin :String = ns.get_string("passin");

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs12 :Asn1Pkcs12 = Asn1Pkcs12::init_asn1();
		let _ = pkcs12.decode_asn1(&code)?;
		let retval = pkcs12.verify_digest(&passin)?;
		if retval {
			println!("{} verify Ok", f);
		} else {
			println!("{} verify not Ok", f);
		}
	}

	Ok(())
}


#[extargs_map_function(pkcs12dec_handler,pkcs12vfy_handler)]
pub fn load_pkcs12_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"pkcs12dec<pkcs12dec_handler>##file ... to diplay value of pkcs12##" : {
			"$" : "+"
		},
		"pkcs12vfy<pkcs12vfy_handler>##file ... to verify pkcs12##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}