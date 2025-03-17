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
use super::pelib::{pe_get_digest};


extargs_error_class!{ReqHdlError}


fn curl_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	//let mut lastidx :usize;


	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	let url = format!("{}",sarr[0]);


	Ok(())
}






#[extargs_map_function(curl_handler)]
pub fn load_req_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"method|X##method for GET POST##" : "GET",
		"curl<curl_handler>##to handle reqwest handle##" : {
			"$" : 1
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}

