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
use super::pelib::{PeHeader,get_pe_header_by_bytes,pe_set_calc_checksum};


use super::loglib::*;
use super::pemlib::*;
use super::*;
use ssllib::pkcs7::*;
use ssllib::pkcs12::*;
use ssllib::utils::*;
use ssllib::x509::*;
use ssllib::consts::*;
use asn1obj::asn1impl::*;
use asn1obj::base::*;
use asn1obj::complex::*;
use ssllib::digest::ssllib_get_digest_operator;
use super::fileop::*;
use super::spc::form_sidc_from_pefile;
use super::dgstlib::dgst_get_value;
use super::spc::{SPC_RFC3161_OBJID};
use ssllib::ts::{TimeStampReq,TimeStampResp};
use super::req::{reqpost_data};
#[allow(unused_imports)]
use chrono::{Utc,DateTime,Datelike,Timelike};

extargs_error_class!{Pkcs7Error}

fn pkcs7dec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs7 :Asn1Pkcs7 = Asn1Pkcs7::init_asn1();
		let size = pkcs7.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("Asn1Pkcs7 in {} size {}[0x{:x}]\n",f,size,size);
		pkcs7.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn pkcs7signerinfodec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs7siginfo :Asn1Pkcs7SignerInfo = Asn1Pkcs7SignerInfo::init_asn1();
		let size = pkcs7siginfo.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("Asn1Pkcs7SignerInfo in {} size {}[0x{:x}]\n",f,size,size);
		pkcs7siginfo.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

fn pkcs7attrexp_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs7siginfo :Asn1Pkcs7SignerInfo = Asn1Pkcs7SignerInfo::init_asn1();
		let _ = pkcs7siginfo.decode_asn1(&code)?;
		let attrs :Asn1Set<Asn1X509Attribute> = pkcs7siginfo.export_auth_attr()?;
		//let mut outf = std::io::stdout();
		let code = attrs.encode_asn1()?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"export [{}]",f);
	}

	Ok(())
}


fn pkcs7appsignature_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");

	if sarr.len() < 3 {
		extargs_new_error!{Pkcs7Error,"need x509file pkeyname dgstname"}
	}

	let x509file = format!("{}",sarr[0]);
	let pkeyname = format!("{}",sarr[1]);
	let dgstname = format!("{}",sarr[2]);
	let ooidpkey = ssllib_get_pkey_oid(&pkeyname);
	if ooidpkey.is_none() {
		extargs_new_error!{Pkcs7Error,"no pkey oid for {}",pkeyname}
	}

	let ooiddgst = ssllib_get_digest_oid(&dgstname);
	if ooiddgst.is_none() {
		extargs_new_error!{Pkcs7Error,"no dgst oid for {}",dgstname}	
	}
	let oidpkey = ooidpkey.unwrap();
	let oiddgst = ooiddgst.unwrap();
	let x509code = read_file_into_der(&x509file)?;
	let mut cert :Asn1X509 = Asn1X509::init_asn1();
	let _ = cert.decode_asn1(&x509code)?;
	let signerinfo = Asn1Pkcs7SignerInfo::new_signer_info_from_cert(&cert,&oidpkey,&oiddgst)?;
	let mut outf = std::io::stdout();
	signerinfo.print_asn1("Asn1Pkcs7SignerInfo",0,&mut outf)?;
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = signerinfo.encode_asn1()?;
		let _ = write_file_bytes(&output,&code)?;
	}


	Ok(())
}


fn pkcs7signerinfoaddauthattr_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");

	if sarr.len() < 3 {
		extargs_new_error!{Pkcs7Error,"need x509file pkeyname dgstname"}
	}

	let sifile = format!("{}",sarr[0]);
	let oid = format!("{}",sarr[1]);
	let oanyfile = format!("{}",sarr[2]);
	let sicode = read_file_into_der(&sifile)?;
	let oanycode = read_file_into_der(&oanyfile)?;

	let mut si :Asn1Pkcs7SignerInfo = Asn1Pkcs7SignerInfo::init_asn1();
	let _  =si.decode_asn1(&sicode)?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	let mut outf = std::io::stdout();
	oany.decode_asn1(&oanycode)?;
	si.append_auth_attr(&oid,&oany)?;


	si.print_asn1("Asn1Pkcs7SignerInfo",0,&mut outf)?;
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = si.encode_asn1()?;
		let _ = write_file_bytes(&output,&code)?;
	}


	Ok(())
}

const SPC_STATEMENT_TYPE_OBJID :&str = "1.3.6.1.4.1.311.2.1.11";
const SPC_INDIRECT_DATA_OBJID :&str = "1.3.6.1.4.1.311.2.1.4";
const PKCS9_CONTENT_TYPE_OID :&str = "1.2.840.113549.1.9.3";
const PKCS9_MESSAGE_DIGEST_TYPE_OID :&str = "1.2.840.113549.1.9.4";
const WIN_CERT_REVISION_2_0 :u16 = 0x0200;
const WIN_CERT_TYPE_PKCS_SIGNED_DATA :u16 = 0x0002;

fn pkcs7sign_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let passin :String;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");

	if sarr.len() < 4 {
		extargs_new_error!{Pkcs7Error,"need x509file pkeyname dgstname pefile"}
	}

	passin = ns.get_string("passin");

	let pkcs12file = format!("{}",sarr[0]);
	let pkeyname = format!("{}",sarr[1]);
	let dgstname = format!("{}",sarr[2]);
	let pefile = format!("{}",sarr[3]);
	let ooidpkey = ssllib_get_pkey_oid(&pkeyname);
	let pkcs12code = read_file_into_der(&pkcs12file)?;
	let mut pkcs12obj :Asn1Pkcs12 = Asn1Pkcs12::init_asn1();
	pkcs12obj.decode_asn1(&pkcs12code)?;
	if ooidpkey.is_none() {
		extargs_new_error!{Pkcs7Error,"no pkey oid for {}",pkeyname}
	}

	let ooiddgst = ssllib_get_digest_oid(&dgstname);
	if ooiddgst.is_none() {
		extargs_new_error!{Pkcs7Error,"no dgst oid for {}",dgstname}	
	}
	let oidpkey = ooidpkey.unwrap();
	let oiddgst = ooiddgst.unwrap();
	let (keycert,certs) = pkcs12obj.get_key_certs(passin.as_bytes())?;
	//let x509code = read_file_into_der(&x509file)?;
	if keycert.len() < 1 {
		extargs_new_error!{Pkcs7Error,"can not get keycert"}
	}
	let mut cert :Asn1X509 = keycert[0].clone();
	if cert.aux.val.is_some() {
		cert.aux.val = None;
	}
	let mut si = Asn1Pkcs7SignerInfo::new_signer_info_from_cert(&cert,&oidpkey,&oiddgst)?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	let mut outf = std::io::stdout();

	let mut oid :String;
	let mut obj :Asn1Object = Asn1Object::init_asn1();
	let _ = obj.set_value(SPC_INDIRECT_DATA_OBJID)?;
	oid = PKCS9_CONTENT_TYPE_OID.to_string();
	let code = obj.encode_asn1()?;
	oany.decode_asn1(&code)?;

	let _ = si.append_auth_attr(&oid,&oany)?;

	let mut ctime :String;
	ctime = ns.get_string("utctime");
	if ctime.len() == 0 {
		ctime = ns.get_string("localtime");
		if ctime.len() == 0 {
			let nowt = Utc::now();
			si.add_time_attr(&nowt)?;
		} else {
			si.add_time_str_attr_local(&ctime)?;
		}
	} else {
		si.add_time_str_attr(&ctime)?;
	}





	oid = SPC_STATEMENT_TYPE_OBJID.to_string();
	let ccode :Vec<u8>;
	if ns.get_bool("pkcs7comm") {
		ccode = vec![0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x16];
	} else {
		ccode = vec![0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x15];
	}
	oany.decode_asn1(&ccode)?;
	let _ = si.append_auth_attr(&oid,&oany)?;
	oany.tag = 0x31;

	/*now we get the trusted */


	let mut pkcs7obj :Asn1Pkcs7 = Asn1Pkcs7::init_asn1();
	pkcs7obj.set_type(PKCS7_TYPE_SIGNED)?;



	let initv :Vec<u8>= vec![];
	let sidc = form_sidc_from_pefile(&dgstname,&pefile,0,&initv)?;
	let mut pk7 :Asn1Pkcs7 = Asn1Pkcs7::init_asn1();
	pk7.set_type(SPC_INDIRECT_DATA_OBJID)?;
	let code = sidc.encode_asn1()?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	oany.decode_asn1(&code)?;
	pk7.set_oany(&oany)?;


	pkcs7obj.set_content_new_pkcs7(PKCS7_TYPE_DATA)?;
	pkcs7obj.add_cert(&cert)?;

	for i in 0..certs.len() {
		if !certs[i].equal_asn1(&cert) {
			let mut ncert = certs[i].clone();
			if ncert.aux.val.is_some() {
				ncert.aux.val = None;
			}
			pkcs7obj.add_cert(&ncert)?;
		}
	}

	let dgstcode = dgst_get_value(&dgstname,0,&initv,&(oany.content))?;
	debug_buffer_trace!(dgstcode.as_ptr(),dgstcode.len(),"dgstcode");
	let  mut setdgst :Asn1OctData = Asn1OctData::init_asn1();
	setdgst.data = dgstcode.clone();
	let mut odgst :Asn1Any = Asn1Any::init_asn1();
	let ocode = setdgst.encode_asn1()?;
	odgst.decode_asn1(&ocode)?;
	si.append_auth_attr(PKCS9_MESSAGE_DIGEST_TYPE_OID,&odgst)?;
	let expc  = si.export_auth_attr()?;
	let updc = expc.encode_asn1()?;
	debug_buffer_trace!(updc.as_ptr(),updc.len(),"update code");
	let odigop = ssllib_get_digest_operator(&dgstname);
	if odigop.is_none() {
		extargs_new_error!{Pkcs7Error,"no [{}] digest" ,dgstname}
	}
	let digop = odigop.unwrap();
	let v :Vec<u8> = vec![];
	digop.borrow_mut().init_digest(0,&v)?;
	digop.borrow_mut().digest_update(&updc)?;
	let digcode = digop.borrow_mut().digest_final()?;
	debug_buffer_trace!(digcode.as_ptr(),digcode.len(),"to set enc_digest dgstname {}",dgstname);
	let osignop = pkcs12obj.get_sign_op(passin.as_bytes())?;
	if osignop.is_none() {
		extargs_new_error!{Pkcs7Error,"no sign op"}
	}
	let signop = osignop.unwrap();
	let code = signop.borrow_mut().sign_exec(&digcode)?;
	debug_buffer_trace!(code.as_ptr(),code.len(),"sign code");
	let _ = si.set_enc_digest(&code)?;

	/*to make digest*/
	digop.borrow_mut().init_digest(0,&v)?;
	digop.borrow_mut().digest_update(&code)?;

	let ndigcode = digop.borrow_mut().digest_final()?;

	debug_buffer_trace!(ndigcode.as_ptr(),ndigcode.len(), "digest code for enc_digest");

	let mut tsreq :TimeStampReq = TimeStampReq::init_asn1();
	tsreq.set_version(1)?;
	let nullobj :Asn1Null = Asn1Null::init_asn1();
	let mut oanyobj :Asn1Any = Asn1Any::init_asn1();
	let code = nullobj.encode_asn1()?;
	oanyobj.decode_asn1(&code)?;
	tsreq.set_digest_param(&oiddgst,&oanyobj)?;
	tsreq.set_digest(&ndigcode)?;
	tsreq.set_certreq(true)?;
	let url = ns.get_string("tsurl");
	let incode = tsreq.encode_asn1()?;
	let outcode = reqpost_data(&url,ns.clone(),&incode)?;
	debug_buffer_trace!(outcode.as_ptr(),outcode.len(),"outcode");
	let mut reply :TimeStampResp = TimeStampResp::init_asn1();
	let _ = reply.decode_asn1(&outcode)?;
	let ists = reply.get_status()?;
	let mut outbytes :Vec<u8>;
	if ists != 0 {
		extargs_new_error!{Pkcs7Error,"status {} != 0", ists}
	}

	let code = reply.get_token_code()?;
	si.append_unauth_attr(SPC_RFC3161_OBJID,&code)?;



	/*now we should give the value for handle*/

	/*now we should give the value*/


	let _ = pkcs7obj.add_signer(&si)?;

	let certs :Vec<String> = ns.get_array("certs");
	let mut acert :Asn1X509 = Asn1X509::init_asn1();
	for i in 0..certs.len() {
		let code = read_file_into_der(&certs[i])?;
		acert.decode_asn1(&code)?;
		if acert.equal_asn1(&cert) {
			continue;
		}
		pkcs7obj.add_cert(&acert)?;
	}

	pkcs7obj.set_content_pk7(&pk7)?;

	/*now to give the idc value*/
	/*
	let mut sidc :SpcPeImageData = SpcPeImageData::init_asn1();
	sidc.add_flags(0,"<<<Obsolete>>>")?;
	let pk7code = sidc.encode_asn1()?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	oany.decode_asn1(&pk7code)?;
	let mut pk7 :Asn1Pkcs7 = Asn1Pkcs7::init_asn1();
	pk7.set_type(SPC_INDIRECT_DATA_OBJID)?;
	pk7.set_oany(&oany)?;
	pkcs7obj.set_content_pk7(&pk7)?;
	*/

	let _ = pkcs7obj.print_asn1("Asn1Pkcs7",0,&mut outf)?;

	outbytes = read_file_bytes(&pefile)?;

	let pehdr :PeHeader = get_pe_header_by_bytes(&outbytes)?;
	let code = pkcs7obj.encode_asn1()?;
	let endoff :usize = pehdr.headersize + 152 + pehdr.pe32plus * 16;


	/*we change the buffer*/
	if outbytes.len() < (endoff+8) {
		extargs_new_error!{Pkcs7Error,"endoff {} + 8 > len(outbytes) {}", endoff, outbytes.len()}
	}
	debug_trace!("at 0x{:x} put 0x{:x}", endoff,outbytes.len());
	for i in 0..4 {
		outbytes[endoff + i] = ((outbytes.len() >> (i*8)) & 0xff) as u8;
	}



	/*now to extend total size*/
	let mut appsize :usize = 8;
	let mut addsize :usize = 8;
	appsize += code.len();
	if (appsize % 8) != 0 {
		appsize += 8 - (appsize % 8)
	}



	for i in 0..4 {
		outbytes[endoff + 4 +i] = ((appsize >> (i*8)) & 0xff) as u8;
	}

	let mut idx :usize = 0;
	while idx < 4 {
		outbytes.push( ((appsize >> (idx * 8)) & 0xff) as u8);
		idx += 1;
	}

	idx = 0;
	while idx < 2 {
		outbytes.push( ((WIN_CERT_REVISION_2_0 >> (idx * 8)) & 0xff) as u8);
		idx += 1;
	}

	idx = 0;
	while idx < 2 {
		outbytes.push( ((WIN_CERT_TYPE_PKCS_SIGNED_DATA >> (idx * 8)) & 0xff) as u8);
		idx += 1;		
	}

	outbytes.extend(&code);
	addsize += code.len();
	while addsize < appsize {
		outbytes.push(0);
		addsize += 1;
	}



	let _ = pe_set_calc_checksum(&mut outbytes)?;

	let outfile = ns.get_string("output");
	if outfile.len() > 0 {
		write_file_bytes(&outfile,&outbytes)?;
	}




	Ok(())
}


#[extargs_map_function(pkcs7dec_handler,pkcs7signerinfodec_handler,pkcs7appsignature_handler,pkcs7signerinfoaddauthattr_handler,pkcs7sign_handler,pkcs7attrexp_handler)]
pub fn load_pkcs7_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"certs" : [],
		"xcerts" : [],
		"crls" : [],
		"pkcs7comm" : false,
		"utctime" : null,
		"localtime" : null,
		"tsurl" : "https://tsa.swisssign.net",
		"pkcs7dec<pkcs7dec_handler>##file ... ##" : {
			"$" : "+"
		},
		"pkcs7signerinfodec<pkcs7signerinfodec_handler>####" : {
			"$" : "+"
		},
		"pkcs7appsignature<pkcs7appsignature_handler>##x509file pkeyname dgstname to add and output##" : {
			"$" : 3
		},
		"pkcs7signerinfoaddauthattr<pkcs7signerinfoaddauthattr_handler>##pkcs7signerinfofile oid oanyfile to append ##" : {
			"$" : 3
		},
		"pkcs7sign<pkcs7sign_handler>##x509file pkeyname dgstname pefile##" : {
			"$" : "+"
		},
		"pkcs7attrexp<pkcs7attrexp_handler>##pkcs7signer to export auth attr##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}