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
use ssllib::consts::KEY_JSON_AES256CBC;

mod consts;
#[cfg(windows)]
mod wchar_windows;
#[cfg(windows)]
mod loglib_windows;
mod loglib;
mod strop;
mod pemlib;
mod fileop;
mod iniexec;
mod asn1parse;
mod x509exec;
mod ecparam;
mod privkey;


#[extargs_map_function()]
fn main() -> Result<(),Box<dyn Error>> {
	let parser :ExtArgsParser = ExtArgsParser::new(None,None)?;
	let commandline = format!(r#"
	{{
		"output|o" : null,
		"input|i" : null,
		"passin" : null,
		"passout" : null,
		"ciphername" : "{}"
	}}
	"#,KEY_JSON_AES256CBC);
	extargs_load_commandline!(parser,&commandline)?;
	loglib::prepare_log(parser.clone())?;
	privkey::load_privkey_handler(parser.clone())?;
	ecparam::load_ecparam_handler(parser.clone())?;
	x509exec::load_x509exec_handler(parser.clone())?;
	iniexec::load_iniexec_handler(parser.clone())?;
	asn1parse::load_asn1parse_handler(parser.clone())?;
	let ores = parser.parse_commandline_ex(None,None,None,None);
	if ores.is_err() {
		let e = ores.err().unwrap();
		eprintln!("{:?}", e);
		return Err(e);
	}
	return Ok(());
}
