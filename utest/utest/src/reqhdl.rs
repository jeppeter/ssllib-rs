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
use super::req::reqpost_data;


use super::loglib::*;
use super::{debug_buffer_trace,format_buffer_log};
#[allow(unused_imports)]
use chrono::{Utc,DateTime,Datelike,Timelike};

use super::fileop::{read_file_bytes};


extargs_error_class!{ReqHdlError}




fn reqpost_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{ReqHdlError,"need url"}
	}

	let infile = ns.get_string("input");
	let outdata = read_file_bytes(&infile)?;
	let url = format!("{}",sarr[0]);

	let indata = reqpost_data(&url,ns.clone(),&outdata)?;

	debug_buffer_trace!(indata.as_ptr(),indata.len(),"for [{}]", url);

	Ok(())
}


#[extargs_map_function(reqpost_handler)]
pub fn load_req_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"reqpost<reqpost_handler>##url for input data for ##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}