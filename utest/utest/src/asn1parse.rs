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
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;
use asn1obj::consts::*;
use asn1obj::base::*;


extargs_error_class!{Asn1ParseError}


fn asn1_parse_out<T : std::io::Write>(code :&[u8],fname :&str, outf :&mut T,tabs :i32,offseti :usize) -> Result<(),Box<dyn Error>> {
	let mut curv :usize = 0;
	let mut capv :usize = code.len();
	let mut stepi :i32 = 0;

	while curv < code.len() {
		let mut oany :Asn1Any = Asn1Any::init_asn1();
		let ores = oany.decode_asn1(&(code[curv..(curv+capv)]));

		if ores.is_err() {
			extargs_new_error!{Asn1ParseError,"parse at [0x{:x}] offset error", curv + offseti}
		}
		let stepv = ores.unwrap();
		let btag = oany.tag as u8;
		let incode = oany.encode_asn1()?;
		if btag == ASN1_BOOLEAN_FLAG {
			let mut basn1 :Asn1Boolean = Asn1Boolean::init_asn1();
			let _ = basn1.decode_asn1(&incode)?;
			if basn1.val {
				write_tab_line!(outf,tabs,"[0x{:x}]: Asn1Boolean True", curv + offseti);
			} else {
				write_tab_line!(outf,tabs,"[0x{:x}]: Asn1Boolean False", curv + offseti);
			}

		} else if btag == ASN1_INTEGER_FLAG {

		} else if btag == ASN1_BIT_STRING_FLAG {

		} else if btag == ASN1_OCT_STRING_FLAG {

		} else if btag == ASN1_NULL_FLAG {

		} else if btag == ASN1_OBJECT_FLAG {

		} else if btag == ASN1_ENUMERATED_FLAG {

		} else if btag == ASN1_UTF8STRING_FLAG {

		} else if btag == ASN1_PRINTABLE_FLAG {

		} else if btag == ASN1_T61STRING_FLAG {

		} else if btag == ASN1_PRINTABLE2_FLAG {

		} else if btag == ASN1_UTCTIME_FLAG {

		} else if btag == ASN1_GENERALTIME_FLAG {

		} else if btag == ASN1_SEQ_MASK {

		} else if btag == ASN1_SET_MASK {

		} else if (btag & ASN1_IMP_FLAG_MASK) == ASN1_IMP_FLAG_MASK {

		} else if (btag & ASN1_IMP_SET_MASK) == ASN1_IMP_SET_MASK {

		} else {
			extargs_new_error!{Asn1ParseError,"parse at [0x{:x}] offset", curv + offseti}
		}
	}
	Ok(())
}

fn asn1parse_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let mut sout = std::io::stdout();

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let _ = asn1_parse_out(&code,f, &mut sout,0,0)?;
	}

	Ok(())
}

#[extargs_map_function(asn1parse_handler)]
pub fn load_asn1parse_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"asn1parse<asn1parse_handler>##file ... to dump file asn1 value##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}