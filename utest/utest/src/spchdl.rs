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


use super::loglib::*;
use super::pemlib::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use chrono::{Utc,DateTime,Datelike,Timelike};

use super::*;
use super::spc::*;
use super::strop::{parse_u64,out_buffer_data};
use super::fileop::{read_file_bytes};
use asn1obj::base::*;
use super::pelib::pe_get_digest;
use ssllib::digest::ssllib_get_digest_oid;

extargs_error_class!{SpcHdlError}

fn spcpeimgdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut spc :SpcPeImageData = SpcPeImageData::init_asn1();
		let size = spc.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("SpcPeImageData in {} size {}[0x{:x}]\n",f,size,size);
		spc.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn spcpeimgenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{SpcHdlError,"need flags unicodename"}
	}
	let flags :i32 = parse_u64(&sarr[0])? as i32;
	let fstr = format!("{}",sarr[1]);
	let mut spc :SpcPeImageData = SpcPeImageData::init_asn1();
	spc.add_code(flags,&fstr)?;
	let ucode = spc.encode_asn1()?;
	debug_buffer_trace!(ucode.as_ptr(),ucode.len(),"SpcPeImageData");

	Ok(())
}

fn sidcdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut spc :SpcIndirectDataContent = SpcIndirectDataContent::init_asn1();
		let size = spc.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("SpcIndirectDataContent in {} size {}[0x{:x}]\n",f,size,size);
		spc.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn sidcform_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let mut times :u32 = 0;
	let mut initv :Vec<u8> = vec![];

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 4 {
		extargs_new_error!{SpcHdlError,"need flags fstr dgstname exefile "}
	}

	let flags = parse_u64(&sarr[0])? as i32;
	let fstr = format!("{}",sarr[1]);
	let dgstname = format!("{}",sarr[2]);
	let pefile =format!("{}",sarr[3]);
	if sarr.len() > 4 {
		times = parse_u64(&sarr[4])? as u32;
	}
	if sarr.len() > 5 {
		initv = read_file_bytes(&sarr[5])?;
	}
	let mut sidc :SpcIndirectDataContent = SpcIndirectDataContent::init_asn1();
	let mut spi :SpcPeImageData = SpcPeImageData::init_asn1();
	spi.add_code(flags,&fstr)?;
	let spicode = spi.encode_asn1()?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	oany.decode_asn1(&spicode)?;
	sidc.set_data("1.3.6.1.4.1.311.2.1.4",Some(oany))?;
	let dgstcode = pe_get_digest(&dgstname,&pefile,times,&initv)?;
	let ooid = ssllib_get_digest_oid(&dgstname);
	if ooid.is_none() {
		extargs_new_error!{SpcHdlError,"not support {} dgst",dgstname}
	}
	let oidname = ooid.unwrap();
	sidc.set_digest(&oidname,None,&dgstcode)?;
	let ocode = sidc.encode_asn1()?;
	let mut outf = std::io::stdout();
	let cstr = format!("SpcIndirectDataContent \n");
	sidc.print_asn1(&cstr,0,&mut outf)?;
	out_buffer_data(&ocode,file!(),line!(),"sidc form")?;

	Ok(())
}


#[extargs_map_function(spcpeimgdec_handler,spcpeimgenc_handler,sidcdec_handler,sidcform_handler)]
pub fn load_spc_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"spcpeimgdec<spcpeimgdec_handler>##file ... to decode_asn1 SpcPeImageData ##" : {
			"$" : "+"
		},
		"spcpeimgenc<spcpeimgenc_handler>##flags str to encode SpcPeImageData##" : {
			"$" : 2
		},
		"sidcdec<sidcdec_handler>##file ... to decode_asn1 SpcIndirectDataContent##" : {
			"$" : "+"
		},
		"sidcform<sidcform_handler>##flags str dgstname exefile [times] [initfile] to form sidc##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}