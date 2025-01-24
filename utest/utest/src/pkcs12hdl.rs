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
use super::*;
use asn1obj::asn1impl::*;
use asn1obj::complex::*;
use asn1obj::base::*;
use ssllib::pkcs12::*;
use ssllib::pkcs7::*;
use ssllib::x509::*;
use ssllib::consts::*;
use ssllib::digest::*;
use ssllib::encde::*;
use ssllib::rsa::*;
use ssllib::ec::ECPrivateKeyAsn1;
use ssllib::impls::{Asn1DigestOp};

extargs_error_class!{UtestPkcs12Error}

fn pkcs12dec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs12 :Asn1Pkcs12 = Asn1Pkcs12::init_asn1();
		let size = pkcs12.decode_asn1(&code)?;
		let mut outf = std::io::stdout();
		let cstr = format!("Asn1Pkcs12 in {} size {}[0x{:x}]\n",f,size,size);
		pkcs12.print_asn1(&cstr,0,&mut outf)?;
	}

	Ok(())
}

pub fn get_hmac_sha256_key(passv8 :&[u8], saltv8 :&[u8], itertimes : usize) -> Vec<u8> {
	let mut omac = HmacSha256Digest::new().unwrap();
	omac.init_digest(itertimes as u32,passv8).unwrap();
	omac.digest_update(saltv8).unwrap();
	return omac.digest_final().unwrap();
}



pub fn get_algor_pbkdf2_private_data(x509algorbytes :&[u8],encdata :&[u8],passin :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let mut algor :Asn1X509Algor = Asn1X509Algor::init_asn1();
	let _ = algor.decode_asn1(x509algorbytes)?;
	let types = algor.elem.val[0].algorithm.get_value();
	if types == OID_PBES2 {
		let params :&Asn1Any = algor.elem.val[0].parameters.val.as_ref().unwrap();
		let decdata :Vec<u8> = params.content.clone();
		let mut pbe2 : Asn1Pbe2ParamElem = Asn1Pbe2ParamElem::init_asn1();
		let _ = pbe2.decode_asn1(&decdata)?;
		let pbe2types = pbe2.keyfunc.elem.val[0].algorithm.get_value();
		if pbe2types == OID_PBKDF2 {
            debug_trace!("debug {}", OID_PBKDF2);
            let params :&Asn1Any = pbe2.keyfunc.elem.val[0].parameters.val.as_ref().unwrap();
            let decdata :Vec<u8> = params.content.clone();
            let mut pbkdf2 :Asn1Pbkdf2ParamElem = Asn1Pbkdf2ParamElem::init_asn1();
            let _ = pbkdf2.decode_asn1(&decdata)?;
            let aeskey :Vec<u8> = get_hmac_sha256_key(passin,&pbkdf2.salt.content,pbkdf2.iter.val as usize);
            let types = pbe2.encryption.elem.val[0].algorithm.get_value();
            let odecrypt = get_decryptor_by_oid(&types);
            if odecrypt.is_none() {
            	extargs_new_error!{UtestPkcs12Error,"not supported types [{}]",types}
            }
            	let params :Asn1Any = pbe2.encryption.elem.val[0].parameters.val.as_ref().unwrap().clone();
            	let ivkey :Vec<u8> = params.content.clone();
            let decrypt = odecrypt.unwrap();
            let _ = decrypt.borrow_mut().init_decrypt(&aeskey,&ivkey)?;
            let mut decdata :Vec<u8> = decrypt.borrow_mut().decrypt_update(encdata)?;
            decdata.extend(decrypt.borrow_mut().decrypt_final()?);
            return Ok(decdata);
        }
        extargs_new_error!{UtestPkcs12Error,"not support OID_PBES2 types [{}]",pbe2types}
    }
    extargs_new_error!{UtestPkcs12Error,"can not support types [{}]", types}
}


pub fn get_rsa_private_key(x509sigbytes :&[u8],passin :&[u8]) -> Result<Asn1RsaPrivateKey,Box<dyn Error>> {
	let mut x509sig = Asn1X509Sig::init_asn1();
	let mut ores = x509sig.decode_asn1(x509sigbytes);
	let mut serr = std::io::stderr();
	if ores.is_err() {
		let s :&str = std::str::from_utf8(x509sigbytes)?;
		let (code,_) = pem_to_der(s)?;
		ores = x509sig.decode_asn1(&code);
	}
	if ores.is_err() {
		let e = Err(ores.err().unwrap());
		return e;
	}
	x509sig.print_asn1("Asn1X509Sig",0, &mut serr)?;
	let algordata = x509sig.elem.val[0].algor.encode_asn1()?;
	let encdata = x509sig.elem.val[0].digest.data.clone();
	let decdata = get_algor_pbkdf2_private_data(&algordata,&encdata,passin)?;
	let mut netpkey :Asn1NetscapePkey = Asn1NetscapePkey::init_asn1();
	let _ = netpkey.decode_asn1(&decdata)?;
	netpkey.print_asn1("Asn1NetscapePkey",0,&mut serr)?;
	let types = netpkey.elem.val[0].algor.elem.val[0].algorithm.get_value();
	if types == OID_RSA_ENCRYPTION {
		let decdata :Vec<u8> = netpkey.elem.val[0].privdata.data.clone();
		let mut privkey :Asn1RsaPrivateKey = Asn1RsaPrivateKey::init_asn1();
		let _ = privkey.decode_asn1(&decdata)?;
		return Ok(privkey);
	}
	extargs_new_error!{UtestPkcs12Error,"not support [{}]",types}
}

pub fn get_ec_private_key(x509sigbytes :&[u8],passin :&[u8]) -> Result<ECPrivateKeyAsn1,Box<dyn Error>> {
	let mut x509sig = Asn1X509Sig::init_asn1();
	let mut ores = x509sig.decode_asn1(x509sigbytes);
	let mut serr = std::io::stderr();
	if ores.is_err() {
		let s :&str = std::str::from_utf8(x509sigbytes)?;
		let (code,_) = pem_to_der(s)?;
		ores = x509sig.decode_asn1(&code);
	}
	if ores.is_err() {
		let e = Err(ores.err().unwrap());
		return e;
	}
	x509sig.print_asn1("Asn1X509Sig",0, &mut serr)?;
	let algordata = x509sig.elem.val[0].algor.encode_asn1()?;
	let encdata = x509sig.elem.val[0].digest.data.clone();
	let decdata = get_algor_pbkdf2_private_data(&algordata,&encdata,passin)?;
	let mut netpkey :Asn1NetscapePkey = Asn1NetscapePkey::init_asn1();
	let _ = netpkey.decode_asn1(&decdata)?;
	netpkey.print_asn1("Asn1NetscapePkey",0,&mut serr)?;
	let types = netpkey.elem.val[0].algor.elem.val[0].algorithm.get_value();
	if types == OID_EC_PUBLICKEY_ENCRYPTION {
		let decdata :Vec<u8> = netpkey.elem.val[0].privdata.data.clone();
		let mut privkey :ECPrivateKeyAsn1 = ECPrivateKeyAsn1::init_asn1();
		let _ = privkey.decode_asn1(&decdata)?;
		/*now to give the */
		if netpkey.elem.val[0].algor.elem.val[0].parameters.val.is_some() && privkey.elem.val.len() > 0  {
			let data = netpkey.elem.val[0].algor.elem.val[0].parameters.encode_asn1()?;
			let mut objdata :Asn1Object = Asn1Object::init_asn1();
			let _ = objdata.decode_asn1(&data)?;
			let ectype = objdata.get_value();
			privkey.set_ec_type_oid(&ectype)?;
		}

		return Ok(privkey);
	}
	extargs_new_error!{UtestPkcs12Error,"not support [{}]",types}
}


fn decode_pkcs12_code(code :&[u8],passin :&[u8]) -> Result<(),Box<dyn Error>> {
	debug_buffer_trace!(code.as_ptr(),code.len(),"code value");
    let mut safes :Asn1AuthSafes = Asn1AuthSafes::init_asn1();
    let rlen = safes.decode_asn1(code)?;
    let mut f = std::io::stderr();
    debug_trace!("rlen [{}:0x{:x}]", rlen,rlen);
    let _ = safes.print_asn1("safes", 0, &mut f)?;
    let mut safeidx :usize= 0;

    /**/
    for idx in 0..safes.safes.val.len() {            
        let types = safes.safes.val[idx].elem.val[0].selector.val.get_value();
        debug_trace!("types [{}]",types);
        if types == OID_PKCS7_ENCRYPTED_DATA {
            let pk7encdata :&Asn1Pkcs7Encrypt = safes.safes.val[idx].elem.val[0].encryptdata.val.as_ref().unwrap();
            let encdata = pk7encdata.elem.val[0].enc_data.elem.val[0].enc_data.val.data.clone();
            let algordata = pk7encdata.elem.val[0].enc_data.elem.val[0].algorithm.encode_asn1()?;
            debug_trace!(" ");
            let decdata = get_algor_pbkdf2_private_data(&algordata,&encdata,passin)?;
            debug_buffer_trace!(decdata.as_ptr(),decdata.len(),"decdata");
            let mut octdata :Asn1Seq<Asn1Pkcs12SafeBag> = Asn1Seq::init_asn1();
            debug_trace!(" ");
            let _ = octdata.decode_asn1(&decdata)?;
            debug_trace!(" ");
            let _ = octdata.print_asn1("safebag encdata", 0, &mut f)?;
            let mut certidx :usize = 0;
            debug_trace!(" ");
            for certd in octdata.val.iter() {
                let objs = certd.elem.val[0].selectelem.valid.val.get_value();
                debug_trace!(" ");
                if objs == OID_PKCS12_CERT_BAG {
                    debug_trace!(" ");
                    let certtype = certd.elem.val[0].selectelem.bag.val[0].elem.val[0].valid.val.get_value();
                    if certtype == OID_PKCS12_SAFE_BAG_X509_CERT {
                        let certdata = certd.elem.val[0].selectelem.bag.val[0].elem.val[0].x509cert.val[0].data.clone();
                        let mut certp :Asn1X509 = Asn1X509::init_asn1();
                        let _ = certp.decode_asn1(&certdata)?;
                        let tagn = format!("safebag[{}]x509cert[{}]",safeidx,certidx);
                        let _ = certp.print_asn1(&tagn,0,&mut f)?;
                    } 
                } else if objs == OID_PKCS8_SHROUDED_KEY_BAG {
                    debug_trace!(" ");
                    let x509sig :Asn1X509Sig = certd.elem.val[0].selectelem.shkeybag.val[0].clone();
                    let v8 = x509sig.encode_asn1()?;
                    let pkey = get_rsa_private_key(&v8,passin)?;
                    let kname = format!("safebag[{}]shroudbag cert[{}]", safeidx,certidx);
                    let _ = pkey.print_asn1(&kname, 0, &mut f)?;                        
                }
                certidx += 1;
            }

        } else if types ==  OID_PKCS7_DATA {
            debug_trace!(" ");
            let pk7data :&Asn1OctData = safes.safes.val[idx].elem.val[0].data.val.as_ref().unwrap();
            let decdata = pk7data.data.clone();
            let mut octdata :Asn1Seq<Asn1Pkcs12SafeBag> = Asn1Seq::init_asn1();
            let _ = octdata.decode_asn1(&decdata)?;
            let _ = octdata.print_asn1("safebag data", 0, &mut f)?;
            let mut bagidx :usize = 0;
            for bag in octdata.val.iter() {
                debug_trace!(" ");
                let objs = bag.elem.val[0].selectelem.valid.val.get_value();
                if objs == OID_PKCS8_SHROUDED_KEY_BAG {
                    debug_trace!(" ");
                    let x509sig :Asn1X509Sig = bag.elem.val[0].selectelem.shkeybag.val[0].clone();
                    let v8 = x509sig.encode_asn1()?;
                    let ores = get_rsa_private_key(&v8,passin);
                    if ores.is_ok() {
                        let pkey = ores.unwrap();
                        let kname = format!("safebag[{}]shroudbag[{}] rsa key", safeidx,bagidx);
                        let _ = pkey.print_asn1(&kname, 0, &mut f)?;
                    } else {
                        let pkey = get_ec_private_key(&v8,passin)?;
                        let kname = format!("safebag[{}]shroudbag[{}] ec key", safeidx,bagidx);
                        let _ = pkey.print_asn1(&kname, 0, &mut f)?;
                    }
                } else if objs == OID_PKCS12_CERT_BAG {
                    debug_trace!(" ");
                    let certtype = bag.elem.val[0].selectelem.bag.val[0].elem.val[0].valid.val.get_value();
                    if certtype == OID_PKCS12_SAFE_BAG_X509_CERT {
                        let certdata = bag.elem.val[0].selectelem.bag.val[0].elem.val[0].x509cert.val[0].data.clone();
                        let mut certp :Asn1X509 = Asn1X509::init_asn1();
                        let _ = certp.decode_asn1(&certdata)?;
                        let tagn = format!("safebag[{}]x509cert bag[{}]",safeidx,bagidx);
                        let _ = certp.print_asn1(&tagn,0,&mut f)?;
                    }                        
                }
                bagidx += 1;
            }
        }
        safeidx += 1;
    }
    Ok(())
}


fn pkcs12vfy_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let passin :String = ns.get_string("passin");

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let mut pkcs12 :Asn1Pkcs12 = Asn1Pkcs12::init_asn1();
		let _ = pkcs12.decode_asn1(&code)?;
		let retval = pkcs12.verify_digest(&passin)?;
		if retval {
			println!("{} verify Ok", f);
	        let types = pkcs12.get_authsafe_oid()?;
	        if types == OID_PKCS7_DATA {
	            let code = pkcs12.get_authsafe_data()?;
	            let _ = decode_pkcs12_code(&code,passin.as_bytes())?;
	        }
		} else {
			println!("{} verify not Ok", f);
		}
	}

	Ok(())
}

fn pkcs12load_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let passin :String = ns.get_string("passin");

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	if sarr.len() < 2 {
		extargs_new_error!{UtestPkcs12Error,"need file type digest|enc|dec"}
	}
	let code = read_file_into_der(&sarr[0])?;
	let types = format!("{}", sarr[1]);
	let mut pkcs12 :Asn1Pkcs12 = Asn1Pkcs12::init_asn1();
	pkcs12.decode_asn1(&code)?;

	if types == "digest" {
		let _ = pkcs12.get_digest_op(passin.as_bytes())?;
	} else if types == "enc" {
		let _ = pkcs12.get_enc_op(passin.as_bytes())?;
	} else if types == "dec" {
		let _ = pkcs12.get_dec_op(passin.as_bytes())?;
	} else {
		extargs_new_error!{UtestPkcs12Error,"not support type [{}]",types}
	}

	Ok(())
}


#[extargs_map_function(pkcs12dec_handler,pkcs12vfy_handler,pkcs12load_handler)]
pub fn load_pkcs12_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"pkcs12dec<pkcs12dec_handler>##file ... to diplay value of pkcs12##" : {
			"$" : "+"
		},
		"pkcs12vfy<pkcs12vfy_handler>##file ... to verify pkcs12##" : {
			"$" : "+"
		},
		"pkcs12load<pkcs12load_handler>##file type to load pkcs12 digest|enc|dec type##" : {
			"$": 2
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}