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

#[allow(unused_imports)]
use super::{debug_trace,debug_buffer_trace,format_buffer_log,format_str_log};
#[allow(unused_imports)]
use super::loglib::{log_get_timestamp,log_output_function,init_log};

use super::fileop::{read_file_bytes};
use pe_parser::pe::{parse_portable_executable};

use super::strop::{parse_u64,out_buffer_data};
use super::pelib::{pe_get_digest,pe_get_calc_checksum};


extargs_error_class!{PeHdlError}


fn peparse_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	//let mut lastidx :usize;


	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_bytes(f)?;
		let pe = parse_portable_executable(&code)?;
		println!("{}", pe);
	}


	Ok(())
}




fn pedigest_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let mut times :u32 = 0;
	let mut initv :Vec<u8> = vec![];
	//let mut lastidx :usize;


	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{PeHdlError,"need digestname and pefile"}
	}

	if sarr.len() > 2 {
		times = parse_u64(&sarr[2])? as u32;
	}

	if sarr.len() > 3 {
		initv = read_file_bytes(&sarr[3])?;
	}

	let v = pe_get_digest(&sarr[0],&sarr[1],times,&initv)?;
	let note = format!("file [{}] digest [{}]",sarr[1],sarr[0]);
	out_buffer_data(&v,file!(),line!(),&note)?;

	Ok(())
}


fn pechecksum_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	//let mut lastidx :usize;


	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{PeHdlError,"need pefile ..."}
	}

	for f in sarr.iter() {
		let pecode = read_file_bytes(f)?;
		let checksum = pe_get_calc_checksum(&pecode)?;
		println!("{} checksum 0x{:x}", f, checksum);
	}

	Ok(())
}

#[extargs_map_function(peparse_handler,pedigest_handler,pechecksum_handler)]
pub fn load_pe_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"peparse<peparse_handler>##file ... to display pe##" : {
			"$" : "+"
		},
		"pedigest<pedigest_handler>##digestname pefile [times] [initfile] to display digest##" : {
			"$" : "+"
		},
		"pechecksum<pechecksum_handler>##pefile to get check sum for pe##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}

