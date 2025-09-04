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

use asn1obj_codegen::{asn1_sequence};
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
use ssllib::x509build::*;
use ssllib::impls::*;
use ssllib::rsa::*;
#[allow(unused_imports)]
use super::fileop::*;
use super::rsaexec::{get_rsa_private_key_asn1};
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
	let bag :Asn1X509AuxCert ;
	bag = serde_json::from_str(&jsons)?;
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
		let s = serde_json::to_string_pretty(&bag)?;
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


fn pkixnamedec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut pkixname :Asn1PkixName = Asn1PkixName::init_asn1();
		let _ = pkixname.decode_asn1(&code)?;
		let mut f = std::io::stderr();
		pkixname.print_asn1("Asn1PkixName",0,&mut f)?;
		pkixname.fixup()?;
		pkixname.print_asn1("Asn1PkixName",0,&mut f)?;
	}
	Ok(())
}


fn exportbuild_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut x509 :Asn1X509 = Asn1X509::init_asn1();
		let _ = x509.decode_asn1(&code)?;
		debug_trace!("decode x509 succ");
		let build :X509BuildConfig;
		build = x509.to_export_build()?;
		println!("{:?}",build);
	}
	Ok(())
}

fn x509selfverify_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut x509 :Asn1X509 = Asn1X509::init_asn1();
		let _ = x509.decode_asn1(&code)?;
		debug_trace!("decode x509 succ");
		let retv = x509.self_verify()?;
		if retv {
			println!("verify {} succ", f);
		} else {
			println!("verify {} failed",f);
		}
	}
	Ok(())
}

fn csrselfverify_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut x509 :Asn1X509Req = Asn1X509Req::init_asn1();
		let _ = x509.decode_asn1(&code)?;
		debug_trace!("decode x509req succ");
		let retv = x509.self_verify()?;
		if retv {
			println!("verify {} succ", f);
		} else {
			println!("verify {} failed",f);
		}
	}
	Ok(())
}

fn csrcfgexport_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut x509req :Asn1X509Req = Asn1X509Req::init_asn1();
		let _ = x509req.decode_asn1(&code)?;
		debug_trace!("decode x509 succ");
		let build :X509RequestBuildConfig;
		build = x509req.to_export_build()?;
		println!("{:?}",build);
	}
	Ok(())
}


fn csrcreate_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	let keyfile :String;
	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{X509ExecError,"need csr json file"}
	}
	keyfile = ns.get_string("keyfile");
	if keyfile.len() == 0 {
		extargs_new_error!{X509ExecError,"need specified keyfile"}
	}
	let usaltsize :usize;
	let saltlen = ns.get_int("psslength");
	if saltlen < 0 {
		usaltsize = 0xff;
	} else {
		usaltsize = saltlen as usize;
	}

	let keydata = read_file_into_der(&keyfile)?;
	let csrjson = format!("{}",sarr[0]);
	let jsons = read_file(&csrjson)?;
	let build :X509RequestBuildConfig = serde_json::from_str(&jsons)?;
	let digesttype = ns.get_string("digesttype");
	let privkey :Asn1RsaPrivateKey = get_rsa_private_key_asn1(&keydata)?;
	let mut signop :Box<dyn X509PrivateKey> = get_rsa_x509_privkey(&privkey,&digesttype,usaltsize)?;

	let req :Asn1X509Req = Asn1X509Req::from_cfg_build(&build,&mut signop)?;
	let code = req.encode_asn1()?;
	let outs = der_to_pem(&code,"CERTIFICATE REQUEST")?;
	let output = ns.get_string("output");
	let _ = write_file(&output,&outs)?;

	Ok(())
}


fn x509permex_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	init_log(ns.clone())?;
	let mut fo = std::io::stdout();

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut x509permex :Asn1PermsExcludes = Asn1PermsExcludes::init_asn1();
		let _ = x509permex.decode_asn1(&code)?;
		debug_trace!("decode x509 succ");
		x509permex.print_asn1("Asn1PermsExcludes",0,&mut fo)?;
	}
	Ok(())
}

fn x509create_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");

	if sarr.len() < 1 {
		extargs_new_error!{X509ExecError,"need jsonfile least"}
	}
	let jsonfile = format!("{}",sarr[0]);
	let jsons = read_file(&jsonfile)?;
	let cfg :X509BuildConfig = serde_json::from_str(&jsons)?;
	let keyfile = ns.get_string("keyfile");
	if keyfile.len() == 0 {
		extargs_new_error!{X509ExecError,"need set keyfile"}
	}
	let keydata = read_file_into_der(&keyfile)?;

	let privkey :Asn1RsaPrivateKey = get_rsa_private_key_asn1(&keydata)?;

	let digesttype = ns.get_string("digesttype");
	let mut privop :Box<dyn X509PrivateKey>;
	let pubop :Box<dyn X509PublicKey>;

	let usaltsize :usize;
	let saltlen = ns.get_int("psslength");
	if saltlen < 0 {
		usaltsize = 0xff;
	} else {
		usaltsize = saltlen as usize;
	}

	privop = get_rsa_x509_privkey(&privkey,&digesttype,usaltsize)?;
	if sarr.len() > 1 {
		let csrkeyfile = format!("{}",sarr[1]);
		let csrkeydata = read_file_into_der(&csrkeyfile)?;
		let csrkeypriv :Asn1RsaPrivateKey = get_rsa_private_key_asn1(&csrkeydata)?;
		let csrkeypub :Asn1RsaPubkey = csrkeypriv.export_public()?;
		pubop = get_rsa_x509_pubkey(&csrkeypub,&digesttype,usaltsize)?;
	} else {
		let pubkey :Asn1RsaPubkey = privkey.export_public()?;
		pubop = get_rsa_x509_pubkey(&pubkey,&digesttype,usaltsize)?;
	}

	let x509asn1 :Asn1X509 = Asn1X509::from_build(&cfg,&pubop,&mut privop)?;

	let code = x509asn1.encode_asn1()?;
	let outs = der_to_pem(&code,"CERTIFICATE")?;
	let output = ns.get_string("output");
	let _ = write_file(&output,&outs)?;

	Ok(())
}



#[extargs_map_function(x509dec_handler,csrdec_handler,crldec_handler,x509sigdec_handler,x509auxdec_handler,x509auxenc_handler,psstypeenc_handler,pkixnamedec_handler,exportbuild_handler,x509selfverify_handler,csrselfverify_handler,csrcfgexport_handler,csrcreate_handler,x509permex_handler,x509create_handler)]
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
		},
		"pkixnamedec<pkixnamedec_handler>##binfile ... to decode for Asn1PkixName##" : {
			"$" : "+"
		},
		"exportbuild<exportbuild_handler>##binfile ... to export x509 Config Build##" : {
			"$" : "+"
		},
		"x509selfverify<x509selfverify_handler>##binfile .. to self verify x509##" : {
			"$" : "+"
		},
		"csrselfverify<csrselfverify_handler>##binfile ... to check self verify##" : {
			"$" : "+"
		},
		"csrcfgexport<csrcfgexport_handler>##binfile ... to export X509 Request Config Build##" : {
			"$" : "+"
		},
		"csrcreate<csrcreate_handler>##jsonfile to create from keyfile get keyfile ##" : {
			"$" : 1
		},
		"x509permex<x509permex_handler>##binfile ... to decode Asn1PermsExcludes##" : {
			"$" : "+"
		},
		"x509create<x509create_handler>##jsonfile [child.rsa] to encode Asn1X509##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}