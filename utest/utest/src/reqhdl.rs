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


use super::{debug_error,debug_buffer_trace,format_str_log,format_buffer_log};
use std::str::FromStr;
use std::io::Read;
use super::loglib::*;
#[allow(unused_imports)]
use chrono::{Utc,DateTime,Datelike,Timelike};

use super::fileop::{read_file_bytes};
use reqwest::blocking::{Client,  Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};


extargs_error_class!{ReqHdlError}



fn reqpost_data(url :&str,ns :NameSpaceEx, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let mut bld = Client::builder();
	let timeout = ns.get_int("timeout");
	if timeout != 0 {
		bld = bld.timeout(std::time::Duration::from_secs(timeout as u64));
	}

	let client = bld.build()?;
	let mut reqbld :reqwest::blocking::RequestBuilder = client.post(url);
	let mut hdrmap :HeaderMap = HeaderMap::new();
	let mut hdrname :HeaderName;
	let mut hdrval :HeaderValue;
	let mut resp : Response;
	hdrname = HeaderName::from_str("Content-Type")?;
	hdrval = HeaderValue::from_str("application/timestamp-query")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());

	hdrname = HeaderName::from_str("Accept")?;
	hdrval = HeaderValue::from_str("application/timestamp-reply")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());

	hdrname = HeaderName::from_str("User-Agent")?;
	hdrval = HeaderValue::from_str("Transport")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());


	hdrname = HeaderName::from_str("Cache-Control")?;
	hdrval = HeaderValue::from_str("no-cache")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());

	reqbld = reqbld.headers(hdrmap);
	reqbld = reqbld.body(data.to_vec().clone());

	loop {
		let ores = reqbld.try_clone();
		if ores.is_none() {
			debug_error!("clone error");
			continue;
		}
		let cbld = ores.unwrap();
		let ores = cbld.send();
		if ores.is_err() {
			let e = ores.err().unwrap();
			debug_error!("clone {:?}", e);
			continue;
		}
		resp = ores.unwrap();
		break;
	}

	let totalsize = resp.content_length().unwrap();
	let mut retv :Vec<u8> = vec![];
	let mut cbuf = [0;2096];
	while retv.len() < totalsize as usize {
		let rcnt = resp.read(&mut cbuf)?;
		for i in 0..rcnt {
			retv.push(cbuf[i]);
		}
	}
	Ok(retv)

}

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