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

#[allow(unused_imports)]
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
	let mut sout = std::io::stdout();
	let mut s :String;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let i = Ini::load_from_file(f)?;
		for (sec,prop) in i.iter() {
			s = format!("[{}] section [{:?}]\n", f,sec);
			sout.write(s.as_bytes())?;
			for (k,v) in prop.iter() {
				s = format!("    [{}]=[{}]\n",k,v);
				sout.write(s.as_bytes())?;
			}
		}
	}

	Ok(())
}

fn iniwrite_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	//let mut sout = std::io::stdout();
	let mut i :Ini;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{IniExecError,"need file at least"}
	}

	i = Ini::load_from_file(&(sarr[0]))?;

	for f in sarr[1..].iter() {
		let carr :Vec<&str>;
		carr = f.split("=").collect();
		if carr.len() > 1 {
			let barr :Vec<&str>;
			barr = carr[0].split(".").collect();
			if barr.len() > 1 {
				debug_trace!("set [{}].[{}] = [{}]",barr[0],barr[1],carr[1]);
				i.with_section(Some(barr[0])).set(barr[1],carr[1]);
			} else {
				debug_trace!("set [{}] = [{}]",carr[0],carr[1]);
				i.with_section(None::<String>).set(carr[0],carr[1]);
			}
		} 
	}

	let _ = i.write_to_file(&sarr[0])?;

	Ok(())
}

fn inidel_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	//let mut sout = std::io::stdout();
	let mut i :Ini;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{IniExecError,"need file at least"}
	}

	i = Ini::load_from_file(&(sarr[0]))?;

	for f in sarr[1..].iter() {
		let carr :Vec<&str>;
		carr = f.split(".").collect();
		if carr.len() > 1 {
			i.delete_from(Some(carr[0]),carr[1]);
		} else {
			i.delete(Some(carr[0]));
		}
	}

	let _ = i.write_to_file(&sarr[0])?;

	Ok(())
}

#[extargs_map_function(iniread_handler,iniwrite_handler,inidel_handler)]
pub fn load_iniexec_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"iniread<iniread_handler>##file ... to read ini file##" : {
			"$" : "+"
		},
		"iniwrite<iniwrite_handler>##file sec.key=val ... to set ini value##" : {
			"$" : "+"
		},
		"inidel<inidel_handler>##file sec[.key] ... to delete ini value##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}