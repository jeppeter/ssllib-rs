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

use asn1obj_codegen::*;
use asn1obj::*;
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::strop::*;

use ssllib::consts::*;

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
use ssllib::x509::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;


extargs_error_class!{X509ExecError}


fn x509dec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut xname = Asn1X509::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("Asn1X509",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode Asn1X509");
	}

	Ok(())
}

fn csrdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut xname = Asn1X509Req::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("Asn1X509Req",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode Asn1X509Req");
	}

	Ok(())
}

fn crldec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut xname = Asn1X509Crl::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("Asn1X509Crl",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode Asn1X509Crl");
	}

	Ok(())
}

fn x509sigdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut xname = Asn1X509Sig::init_asn1();
		let _ = xname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		xname.print_asn1("Asn1X509Sig",0,&mut f)?;
		let vcode = xname.encode_asn1()?;
		debug_buffer_trace!(vcode.as_ptr(),vcode.len(),"encode Asn1X509Sig");
	}

	Ok(())
}


fn x509auxenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{X509ExecError,"need jsonfile"}
	}
	let jsons = read_file(&sarr[0])?;
	let jval :serde_json::Value = serde_json::from_str(&jsons)?;
	let mut bag :Asn1X509AuxCert = Asn1X509AuxCert::init_asn1();
	let _ = bag.decode_json("",&jval)?;
	let cstr = format!("[{}] format Asn1X509AuxCert\n",sarr[0]);
	let mut outf = std::io::stdout();
	let _ = bag.print_asn1(&cstr,0,&mut outf)?;
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = bag.encode_asn1()?;
		write_file_bytes(&output,&code)?;
	}

	Ok(())
}

fn x509auxdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{X509ExecError,"need binfile"}
	}

	for f in sarr.iter() {
		let code = read_file_bytes(f)?;
		let mut bag :Asn1X509AuxCert = Asn1X509AuxCert::init_asn1();
		bag.decode_asn1(&code)?;
		let mut jval :serde_json::Value = serde_json::from_str("{}")?;
		bag.encode_json("",&mut jval)?;
		let s = serde_json::to_string_pretty(&jval)?;
		let cstr = format!("{} X509AuxCert\n",f);
		let mut outf = std::io::stdout();
		let _ = bag.print_asn1(&cstr,0,&mut outf)?;
		println!("{} out\n{}", f,s);
	}
	Ok(())
}

#[asn1_sequence()]
struct pss_encode_elem {
	kaglo1 : Asn1ImpSet<Asn1X509Algor,0>,
	kaglo2 :Asn1ImpSet<Asn1X509Algor,1>,
	size : Asn1ImpSet<Asn1Integer,2>,
}

#[asn1_sequence()]
struct pss_encode {
	elem :Asn1Seq<pss_encode_elem>,
}

fn psstypeenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	init_log(ns.clone())?;

	let mut pssenc :pss_encode = pss_encode::init_asn1();
	let mut nalgor :Asn1X509Algor = Asn1X509Algor::init_asn1();
	let mut nany :Asn1Any = Asn1Any::init_asn1();
	let nullobj :Asn1Null = Asn1Null::init_asn1();
	let mut code :Vec<u8>;

	pssenc.elem.val.push(pss_encode_elem::init_asn1());
	pssenc.elem.val[0].kaglo1.val.push(Asn1X509Algor::init_asn1());
	pssenc.elem.val[0].kaglo1.val[0].elem.val.push(Asn1X509AlgorElem::init_asn1());
	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].algorithm.set_value(OID_SHA256_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].parameters.val = Some(nany.clone());

	pssenc.elem.val[0].kaglo2.val.push(Asn1X509Algor::init_asn1());
	pssenc.elem.val[0].kaglo2.val[0].elem.val.push(Asn1X509AlgorElem::init_asn1());
	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].algorithm.set_value(OID_RSA_MGF1).unwrap();

	nalgor.elem.val.push(Asn1X509AlgorElem::init_asn1());
	nalgor.elem.val[0].algorithm.set_value(OID_SHA256_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();
	nalgor.elem.val[0].parameters.val = Some(nany.clone());
	code = nalgor.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].parameters.val = Some(nany.clone());
	pssenc.elem.val[0].size.val.push(Asn1Integer::init_asn1());
	pssenc.elem.val[0].size.val[0].val = 0x20;

	code = pssenc.encode_asn1().unwrap();
	debug_buffer_trace!(code.as_ptr(),code.len(), "pss enc1");

	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].algorithm.set_value(OID_SHA384_DIGEST).unwrap();

	nalgor.elem.val[0].algorithm.set_value(OID_SHA384_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();
	nalgor.elem.val[0].parameters.val = Some(nany.clone());
	code = nalgor.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].parameters.val = Some(nany.clone());

	pssenc.elem.val[0].size.val[0].val = 0x30;
	code = pssenc.encode_asn1().unwrap();
	debug_buffer_trace!(code.as_ptr(),code.len(), "pss enc2");


	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].algorithm.set_value(OID_SHA512_DIGEST).unwrap();

	nalgor.elem.val[0].algorithm.set_value(OID_SHA512_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();
	nalgor.elem.val[0].parameters.val = Some(nany.clone());
	code = nalgor.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].parameters.val = Some(nany.clone());

	pssenc.elem.val[0].size.val[0].val = 0x40;
	code = pssenc.encode_asn1().unwrap();
	debug_buffer_trace!(code.as_ptr(),code.len(), "pss enc3");



	Ok(())
}




#[extargs_map_function(x509dec_handler,csrdec_handler,crldec_handler,x509sigdec_handler,x509auxdec_handler,x509auxenc_handler,psstypeenc_handler)]
pub fn load_x509exec_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"x509dec<x509dec_handler>##file ... to decode x509##" : {
			"$" : "+"
		},
		"csrdec<csrdec_handler>##file ... to decode x509_req##" : {
			"$" : "+"
		},
		"crldec<crldec_handler>##file ... to decode crl##" : {
			"$" : "+"
		},
		"x509sigdec<x509sigdec_handler>##file ... to decode Asn1X509Sig##" : {
			"$" : "+"
		},
		"x509auxenc<x509auxenc_handler>##jsonfile to encode Asn1X509AuxCert##" : {
			"$" : 1
		},
		"x509auxdec<x509auxdec_handler>##binfile ... to decode Asn1X509AuxCert##" : {
			"$" : 1
		},
		"psstypeenc<psstypeenc_handler>##to display pss type encryption##" : {
			"$" : 0
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}