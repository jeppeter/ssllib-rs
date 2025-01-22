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

use ssllib::digest::get_digest_operator;
use super::strop::{parse_u64,out_buffer_data};


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

pub struct PeHeader {
	pub headersize :usize,
	pub pe32plus :usize,
}

impl PeHeader {
	pub fn new(pecode :&[u8]) -> Result<Self,Box<dyn Error>> {
		let mut retv :Self = Self {
			headersize : 0,
			pe32plus :  0,
		};
		if pecode.len() < 64 {
			extargs_new_error!{PeHdlError,"must at least 64"}
		}
		let mut idx :usize = 0;
		while idx < 4 {
			retv.headersize += (pecode[idx+60] as usize) << (idx * 8);
			idx += 1;
		}
		if pecode.len() < (retv.headersize + 24 + 2) {
			extargs_new_error!{PeHdlError,"must at least {} + 24 + 2",retv.headersize}	
		}
		let mut magic :u16 = 0;
		idx = 0;
		while idx < 2 {
			magic += (pecode[retv.headersize + 24 + idx] as u16) << (idx * 8);
			idx += 1;
		}
		if magic == 0x20b {
			retv.pe32plus = 1;
		} else if magic == 0x10b {
			retv.pe32plus = 0;
		} else {
			extargs_new_error!{PeHdlError,"0x{:x} not valid magic",magic}
		}
		Ok(retv)
	}
}

fn get_pe_header(pefile :&str) -> Result<PeHeader,Box<dyn Error>> {
	let pecode = read_file_bytes(pefile)?;
	let retv :PeHeader = PeHeader::new(&pecode)?;

	return Ok(retv);
}

fn pe_get_digest(digestname :&str, pefile :&str,times :u32,initv :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let pehdr = get_pe_header(pefile)?;
	let ores = get_digest_operator(&digestname);
	let mut start:usize;
	let mut end :usize;
	let mut incode :Vec<u8>;
	let mut digcode :Vec<u8> = vec![];
	if ores.is_none() {
		extargs_new_error!{PeHdlError,"can not find {} digest", digestname}
	}
	let pecode = read_file_bytes(pefile)?;
	let digop = ores.unwrap();

	digop.borrow_mut().init_digest(times,initv)?;
	/*first before header size*/
	start = 0;
	end = pehdr.headersize + 88;
	digcode.extend(&pecode[start..end]);
	digop.borrow_mut().digest_update(&pecode[start..end])?;
	debug_trace!("pecode [{}..{}]",start,end);
	/*the place is checksum*/
	start = pehdr.headersize + 88 + 4;
	end = start + 60;
	if pehdr.pe32plus != 0 {
		end += pehdr.pe32plus * 16;
	}
	digcode.extend(&pecode[start..end]);
	digop.borrow_mut().digest_update(&pecode[start..end])?;
	debug_trace!("pecode [{}..{}]",start,end);
	/*now at the end*/
	start = end + 8;
	end = pecode.len();
	digcode.extend(&pecode[start..end]);
	digop.borrow_mut().digest_update(&pecode[start..end])?;
	debug_trace!("pecode [{}..{}]",start,end);

	/*be 8 bytes alignment*/
	if (pecode.len() % 8) != 0 {
		let nlen :usize = 8 - (pecode.len() % 8);
		incode = vec![];
		while incode.len() != nlen {
			incode.push(0);
		}
		digcode.extend(&incode);
		digop.borrow_mut().digest_update(&incode)?;
		debug_trace!("incode [{}]",incode.len());
	}
	debug_buffer_trace!(digcode.as_ptr(),digcode.len(),"digcode");

	return digop.borrow_mut().digest_final();
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


#[extargs_map_function(peparse_handler,pedigest_handler)]
pub fn load_pe_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"peparse<peparse_handler>##file ... to display pe##" : {
			"$" : "+"
		},
		"pedigest<pedigest_handler>##digestname pefile [times] [initfile] to display digest##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}

