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
use ssllib::x509::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;


extargs_error_class!{X509ExecError}


fn x509dec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut xname = Asn1X509::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("Asn1X509",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode Asn1X509");
	}

	Ok(())
}

fn csrdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut xname = Asn1X509Req::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("Asn1X509Req",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode Asn1X509Req");
	}

	Ok(())
}

#[extargs_map_function(x509dec_handler,csrdec_handler)]
pub fn load_x509exec_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"x509dec<x509dec_handler>##file ... to decode x509##" : {
			"$" : "+"
		},
		"csrdec<csrdec_handler>##file ... to decode x509_req##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}