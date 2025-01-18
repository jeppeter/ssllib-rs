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
use ssllib::genname::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use chrono::{Utc,DateTime,Datelike,Timelike};

use super::*;
use asn1obj::base::{Asn1Any};

extargs_error_class!{GenNameError}

fn gennamedec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut genname :Asn1_GENERAL_NAME = Asn1_GENERAL_NAME::init_asn1();
		let size = genname.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("Asn1_GENERAL_NAME in {} size {}[0x{:x}]\n",f,size,size);
		genname.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn directorynameenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{GenNameError,"need oid oanyfile"}
	}

	let oid = format!("{}",sarr[0]);
	let ofile = format!("{}",sarr[1]);
	let ocode = read_file_into_der(&ofile)?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	let _ = oany.decode_asn1(&ocode)?;
	let mut dname :DirectoryName = DirectoryName::init_asn1();
	dname.set_algo(&oid,&oany)?;
	let code = dname.encode_asn1()?;
	debug_buffer_trace!(code.as_ptr(),code.len(),"DirectoryName");

	Ok(())
}


#[extargs_map_function(gennamedec_handler)]
pub fn load_genname_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"gennamedec<gennamedec_handler>##file ... to decode_asn1 GENERNAL_NAME ##" : {
			"$" : "+"
		},
		"directorynameenc<directorynameenc_handler>##oid oanyfile to set DirectoryName##" : {
			"$" : 2
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}