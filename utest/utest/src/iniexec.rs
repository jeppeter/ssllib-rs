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
use std::any::Any;

use lazy_static::lazy_static;
use std::collections::HashMap;

use super::*;
use super::loglib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;
use ini::Ini;


extargs_error_class!{IniExecError}


fn iniread_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let i = Ini::load_from_file(f)?;
		for (sec,prop) in i.iter() {
			debug_trace!("[{}] section [{:?}]", f,sec);
			for (k,v) in prop.iter() {
				debug_trace!("[{}]=[{}]",k,v);
			}
		}
	}

	Ok(())
}

#[extargs_map_function(iniread_handler)]
pub fn load_iniexec_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"iniread<iniread_handler>##file ... to decode x509##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}