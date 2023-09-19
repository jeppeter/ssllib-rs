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
//use asn1obj::asn1impl::Asn1Op;

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
use super::pemlib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;
//use asn1obj::consts::*;
//use asn1obj::base::*;


extargs_error_class!{PemHandleError}

fn dertopem_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let input :String;
	let output :String;
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	input = ns.get_string("input");
	if input.len() == 0 {
		extargs_new_error!{PemHandleError,"no input specified"}
	}

	output = ns.get_string("output");
	if output.len() == 0 {
		extargs_new_error!{PemHandleError,"no output specified"}	
	}

	sarr = ns.get_array("subnargs");
	if sarr.len()  < 1 {
		extargs_new_error!{PemHandleError,"need type string"}
	}

	let indata :Vec<u8> = read_file_bytes(&input)?;
	let outs :String = der_to_pem(&indata,&sarr[0])?;
	write_file(&output,&outs)?;
	println!("write [{}] data to [{}]",sarr[0],output);
	Ok(())
}

fn pemtoder_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let input :String;
	let output :String;

	init_log(ns.clone())?;

	input = ns.get_string("input");
	if input.len() == 0 {
		extargs_new_error!{PemHandleError,"no input specified"}
	}

	output = ns.get_string("output");
	if output.len() == 0 {
		extargs_new_error!{PemHandleError,"no output specified"}	
	}
	let ins :String = read_file(&input)?;
	let (data , types) = pem_to_der(&ins)?;
	write_file_bytes(&output,&data)?;
	println!("write [{}] data to [{}]",types,output);
	Ok(())
}


#[extargs_map_function(pemtoder_handler,dertopem_handler)]
pub fn load_pemhdl_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"pemtoder<pemtoder_handler>##from file input to output##" : {
			"$" : 0
		},
		"dertopem<dertopem_handler>##strtype to specified string##" : {
			"$" : 1
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}