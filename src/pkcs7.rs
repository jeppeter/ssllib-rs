#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use asn1obj::*;

use std::error::Error;
use std::sync::Arc;
use std::cell::RefCell;
use std::io::{Write};

#[allow(unused_imports)]
use crate::{ssllib_new_error,ssllib_error_class};
#[allow(unused_imports)]
use crate::{ssllib_log_error,ssllib_buffer_trace,ssllib_format_buffer_log};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};

use crate::x509::*;
use crate::impls::*;
use crate::digest::*;
use crate::consts::*;
//use crate::utils::*;


ssllib_error_class!{SslPkcs7Error}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7ContentElem {
	pub objval : Asn1Object,
	pub data :Asn1Opt<Asn1Any>,	
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7Content {
	pub elem :Asn1Seq<Asn1Pkcs7ContentElem>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7IssuerAndSerialElem {
	pub issuer : Asn1X509Name,
	pub serial : Asn1BigNum,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7IssuerAndSerial {
	pub elem :Asn1Seq<Asn1Pkcs7IssuerAndSerialElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AttrPack {
	pub elem :Asn1Set<Asn1X509Attribute>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7SignerInfoElem {
	pub version : Asn1Integer,
	pub issuer_and_serial : Asn1Pkcs7IssuerAndSerial,
	pub digest_alg : Asn1X509Algor,
	pub auth_attr : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,0>>,
	pub digest_enc_alg : Asn1X509Algor,
	pub enc_digest : Asn1OctData,
	pub unauth_attr : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,1>>,
}

impl Asn1Pkcs7SignerInfoElem {
	pub fn set_version(&mut self, val :i64) -> Result<i64,Box<dyn Error>> {
		let retv :i64 = self.version.val;
		self.version.val = val;
		Ok(retv)
	}

	pub fn set_issuer(&mut self,name :&Asn1X509Name) -> Result<Option<Asn1X509Name>,Box<dyn Error>> {
		let mut retv :Option<Asn1X509Name> =  None;
		if self.issuer_and_serial.elem.val.len() > 0 {
			retv = Some(self.issuer_and_serial.elem.val[0].issuer.clone());
		}
		if self.issuer_and_serial.elem.val.len() < 1 {
			self.issuer_and_serial.elem.val.push(Asn1Pkcs7IssuerAndSerialElem::init_asn1());
		}
		self.issuer_and_serial.elem.val[0].issuer = name.clone();
		Ok(retv)
	}

	pub fn set_issuer_serial(&mut self,serialnum :&Asn1BigNum) -> Result<Option<Asn1BigNum>,Box<dyn Error>> {
		let mut retv :Option<Asn1BigNum> =  None;
		if self.issuer_and_serial.elem.val.len() > 0 {
			retv = Some(self.issuer_and_serial.elem.val[0].serial.clone());
		}
		if self.issuer_and_serial.elem.val.len() < 1 {
			self.issuer_and_serial.elem.val.push(Asn1Pkcs7IssuerAndSerialElem::init_asn1());
		}
		self.issuer_and_serial.elem.val[0].serial = serialnum.clone();
		Ok(retv)
	}

	pub fn set_enc_and_digest(&mut self,pkey :&str, dgst:&str) -> Result<(Option<Asn1X509Algor>,Option<Asn1X509Algor>),Box<dyn Error>> {
		let keyalgor :Option<Asn1X509Algor> = Some(self.digest_enc_alg.clone());
		let dgstalgor :Option<Asn1X509Algor> = Some(self.digest_alg.clone());

		let _ = self.digest_alg.set_algorithm_null(dgst)?;
		let _ = self.digest_enc_alg.set_algorithm(pkey)?;
		let _ = self.digest_enc_alg.set_param(None)?;


		Ok((keyalgor,dgstalgor))
	}

	pub fn append_auth_attr(&mut self, oid :&str,oany :&Asn1Any) -> Result<(),Box<dyn Error>> {
		let mut attr :Asn1X509Attribute = Asn1X509Attribute::init_asn1();
		attr.elem.val.push(Asn1X509AttributeElem::init_asn1());
		let _ = attr.elem.val[0].object.set_value(oid)?;
		let mut impset :Asn1ImpSet<Asn1X509Attribute,0> = Asn1ImpSet::init_asn1();
		attr.elem.val[0].set = oany.clone();
		if self.auth_attr.val.is_none() {
			impset.val.push(attr);
			self.auth_attr.val = Some(impset);
		} else {
			let mut v :Asn1ImpSet<Asn1X509Attribute,0> = self.auth_attr.val.as_ref().unwrap().clone();
			v.val.push(attr);
			self.auth_attr.val = Some(v);
		}
		Ok(())
	}


}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7SignerInfo {
	pub elem : Asn1Seq<Asn1Pkcs7SignerInfoElem>,
}

impl Asn1Pkcs7SignerInfo {
	pub fn set_issuer(&mut self, name :&Asn1X509Name) -> Result<Option<Asn1X509Name>,Box<dyn Error>> {
		let mut retv :Option<Asn1X509Name> = None;
		if self.elem.val.len() > 0 {
			retv = self.elem.val[0].set_issuer(name)?;
		} else {
			self.elem.val.push(Asn1Pkcs7SignerInfoElem::init_asn1());
			let _ = self.elem.val[0].set_issuer(name)?;
		}
		Ok(retv)
	}

	pub fn set_issuer_serial(&mut self,serialnum :&Asn1BigNum) -> Result<Option<Asn1BigNum>,Box<dyn Error>> {
		let mut retv :Option<Asn1BigNum> = None;
		if self.elem.val.len() > 0 {
			retv = self.elem.val[0].set_issuer_serial(serialnum)?;
		} else {
			self.elem.val.push(Asn1Pkcs7SignerInfoElem::init_asn1());
			let _ = self.elem.val[0].set_issuer_serial(serialnum)?;
		}
		Ok(retv)
	}

	pub fn set_enc_and_digest(&mut self,pkey :&str, dgst:&str) -> Result<(Option<Asn1X509Algor>,Option<Asn1X509Algor>),Box<dyn Error>> {
		let mut keyalgor :Option<Asn1X509Algor> = None;
		let mut dgstalgor :Option<Asn1X509Algor> = None;
		if self.elem.val.len() > 0 {
			(keyalgor,dgstalgor) = self.elem.val[0].set_enc_and_digest(pkey,dgst)?;
		} else {
			self.elem.val.push(Asn1Pkcs7SignerInfoElem::init_asn1());
			let _ = self.elem.val[0].set_enc_and_digest(pkey,dgst)?;
		}
		Ok((keyalgor,dgstalgor))
	}

	pub fn append_auth_attr(&mut self,oid :&str ,oany :&Asn1Any) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() > 0 {
			let _ = self.elem.val[0].append_auth_attr(oid,oany)?;
		} else {
			let mut elm :Asn1Pkcs7SignerInfoElem = Asn1Pkcs7SignerInfoElem::init_asn1();
			let _ = elm.append_auth_attr(oid,oany)?;
			self.elem.val.push(elm);
		}
		Ok(())
	}

}

impl Asn1Pkcs7SignerInfo {
	pub fn new_signer_info_from_cert(cert :&Asn1X509,pkey :&str ,dgst :&str) -> Result<Asn1Pkcs7SignerInfo,Box<dyn Error>> {
		let mut retv :Asn1Pkcs7SignerInfo = Asn1Pkcs7SignerInfo::init_asn1();
		if retv.elem.val.len() < 1 {
			retv.elem.val.push(Asn1Pkcs7SignerInfoElem::init_asn1());
		}
		retv.elem.val[0].version.val = 1;
		let oissuer = cert.get_x509_name0();
		if oissuer.is_none() {
			ssllib_new_error!{SslPkcs7Error,"no issuer for x509"}
		}
		let issuer = oissuer.unwrap();
		let _ = retv.set_issuer(&issuer)?;

		let onumber = cert.get_serial_number0();
		if onumber.is_none() {
			ssllib_new_error!{SslPkcs7Error,"no serial number for x509"}
		}
		let number = onumber.unwrap();
		let _ = retv.set_issuer_serial(&number)?;

		let _ = retv.set_enc_and_digest(pkey,dgst)?;

		Ok(retv)
	}

	pub fn get_auth_attrs(&self) -> Result<Vec<Asn1X509Attribute>,Box<dyn Error>> {
		let mut retv :Vec<Asn1X509Attribute> = Vec::new();
		if self.elem.val.len() != 1 && self.elem.val.len() != 0 {
			ssllib_new_error!{SslPkcs7Error,"val [{}] != 0 or 1",self.elem.val.len()}
		}

		if self.elem.val.len() == 1 {
			if self.elem.val[0].auth_attr.val.is_some() {
				let cset :&Asn1ImpSet<Asn1X509Attribute,0> = self.elem.val[0].auth_attr.val.as_ref().unwrap();
				for k in cset.val.iter() {
					retv.push(k.clone());
				}
			}
		}

		Ok(retv)
	}

	pub fn set_auth_attrs(&mut self, attrs :&Vec<Asn1X509Attribute>) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() != 1 && self.elem.val.len() != 0 {
			ssllib_new_error!{SslPkcs7Error,"val [{}] != 0 or 1",self.elem.val.len()}	
		}

		if self.elem.val.len() == 0 {
			self.elem.val.push(Asn1Pkcs7SignerInfoElem::init_asn1());
		}

		if attrs.len() == 0 {
			self.elem.val[0].auth_attr.val = None;
		} else {
			let mut cset :Asn1ImpSet<Asn1X509Attribute,0> = Asn1ImpSet::init_asn1();
			cset.val = attrs.clone();
			self.elem.val[0].auth_attr.val = Some(cset);
		}
		Ok(())
	}

	fn format_auth_attr_data(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut attrs :Asn1X509AttrPack = Asn1X509AttrPack::init_asn1();
		if self.elem.val[0].auth_attr.val.is_some() {
			let c = self.elem.val[0].auth_attr.val.as_ref().unwrap();

			for k in c.val.iter() {
				attrs.elem.val.push(k.clone());
			}
		}
		let data = attrs.encode_asn1()?;
		Ok(data)
	}

	fn get_digest_op(&self) -> Result<Arc<RefCell<dyn Asn1DigestOp>>,Box<dyn Error>> {
		let mut retv :Arc<RefCell<dyn Asn1DigestOp>> = Arc::new(RefCell::new(Sha256Digest::new()));

		if self.elem.val[0].digest_alg.elem.val.len() > 0 {
			let c = &(self.elem.val[0].digest_alg.elem.val[0]);
			let digval :String = c.algorithm.get_value();
			if digval.eq(OID_SHA256_DIGEST) {
				retv = Arc::new(RefCell::new(Sha256Digest::new()));
			}
		}


		Ok(retv)
	}

	pub fn sign_auth_attr_enc<T : Asn1SignOp>(&mut self, signer :&mut T) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() != 1 && self.elem.val.len() != 0 {
			ssllib_new_error!{SslPkcs7Error,"val [{}] != 0 or 1",self.elem.val.len()}	
		}
		if self.elem.val.len() != 0 {
			let encdata = self.format_auth_attr_data()?;
			ssllib_buffer_trace!(encdata.as_ptr(),encdata.len(),"sign data");
			let digop = self.get_digest_op()?;
			let _ = signer.sign_update(&encdata,digop.clone())?;
			self.elem.val[0].enc_digest.data = signer.sign_final(digop.clone())?;
		}
		Ok(())
	}

}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7SignedElem {
	pub version :Asn1Integer,
	pub md_algs : Asn1Set<Asn1X509Algor>,
	pub contents : Asn1Pkcs7Content,
	pub cert :Asn1Opt<Asn1ImpSet<Asn1X509,0>>,
	pub crl : Asn1ImpSet<Asn1X509Crl,1>,
	pub signer_info : Asn1Set<Asn1Pkcs7SignerInfo>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7Signed {
	pub elem : Asn1Seq<Asn1Pkcs7SignedElem>,
}


impl Asn1Pkcs7Signed {
	pub fn get_certs(&self) -> Result<Vec<Asn1X509>,Box<dyn Error>> {
		let mut retv :Vec<Asn1X509> = Vec::new();
		if self.elem.val.len() != 1 && self.elem.val.len() != 0 {
			ssllib_new_error!{SslPkcs7Error,"elem [{}] not valid", self.elem.val.len()}
		}
		if self.elem.val.len() > 0 {
			if self.elem.val[0].cert.val.is_some() {
				let b = self.elem.val[0].cert.val.as_ref().unwrap();
				for v in b.val.iter() {
					let code = v.encode_asn1()?;
					let mut cv :Asn1X509 = Asn1X509::init_asn1();
					let _ = cv.decode_asn1(&code)?;
					retv.push(cv);
				}
			}
		}
		Ok(retv)
	}
	pub fn set_certs(&mut self, certs :&Vec<Asn1X509>) -> Result<(),Box<dyn Error>> {
		let mut cimp :Asn1ImpSet<Asn1X509,0> = Asn1ImpSet::init_asn1();
		cimp.val = certs.clone();
		if self.elem.val.len() != 1 && self.elem.val.len() != 0 {
			ssllib_new_error!{SslPkcs7Error,"elem [{}] not valid",self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			let c = Asn1Pkcs7SignedElem::init_asn1();
			self.elem.val.push(c);
		}
		self.elem.val[0].cert.val = Some(cimp);
		return Ok(());
	}

	pub fn get_signer_info_mut(&mut self,i :usize) -> Option<&mut Asn1Pkcs7SignerInfo> {
		if self.elem.val.len() != 1 && self.elem.val.len() != 0 {
			return None;
		}

		if self.elem.val.len() != 0 {
			if i < self.elem.val[0].signer_info.val.len() {
				return Some(&mut self.elem.val[0].signer_info.val[i]);
			}
		}
		return None;
	}


}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7EncContentElem {
	pub content_type : Asn1Object,
	pub algorithm : Asn1X509Algor,
	pub enc_data :Asn1Imp<Asn1OctData,0>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7EncContent {
	pub elem :Asn1Seq<Asn1Pkcs7EncContentElem>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7EncryptElem {
	pub version : Asn1Integer,
	pub enc_data : Asn1Pkcs7EncContent,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7Encrypt {
	pub elem : Asn1Seq<Asn1Pkcs7EncryptElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7RecipInfoElem {
	pub version :Asn1Integer,
	pub issuer_and_serial :Asn1Pkcs7IssuerAndSerial,
	pub key_enc_algor :Asn1X509Algor,
	pub enc_key :Asn1OctData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7RecipInfo {
	pub elem :Asn1Seq<Asn1Pkcs7RecipInfoElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7EnvelopeElem {
	pub version :Asn1Integer,
	pub recipientinfo :Asn1Pkcs7RecipInfo,
	pub enc_data :Asn1Pkcs7EncContent,	
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7Envelope {
	pub elem :Asn1Seq<Asn1Pkcs7EnvelopeElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7SignedEnvelopeElem {
	pub version :Asn1Integer,
	pub recipientinfo :Asn1Opt<Asn1Set<Asn1Pkcs7RecipInfo>>,
	pub md_algs :Asn1Opt<Asn1Set<Asn1X509Algor>>,
	pub enc_data :Asn1Pkcs7EncContent,
	pub cert:Asn1Opt<Asn1ImpSet<Asn1X509,0>>,
	pub crl :Asn1Opt<Asn1ImpSet<Asn1X509Crl,1>>,
	pub signer_info :Asn1Opt<Asn1Set<Asn1Pkcs7SignerInfo>>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7SignedEnvelope {
	pub elem :Asn1Seq<Asn1Pkcs7SignedEnvelopeElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7DigestElem {
	pub version :Asn1Integer,
	pub md :Asn1X509Algor,
	pub contents :Asn1Pkcs7,
	pub digest :Asn1OctData,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7Digest {
	pub elem :Asn1Seq<Asn1Pkcs7DigestElem>,
}

//#[asn1_obj_selector(debug=enable,anyobj=default,signed="1.2.840.113549.1.7.2",encryptdata="1.2.840.113549.1.7.6",data="1.2.840.113549.1.7.1")]
#[asn1_obj_selector(anyobj=default,data="1.2.840.113549.1.7.1",signed="1.2.840.113549.1.7.2",envlop="1.2.840.113549.1.7.3",envlopsigned="1.2.840.113549.1.7.4",digestdata="1.2.840.113549.1.7.5",encryptdata="1.2.840.113549.1.7.6")]
#[derive(Clone)]
pub struct Asn1Pkcs7Selector {
	pub val :Asn1Object,
}


//#[asn1_choice(selector=selector,debug=enable)]
#[asn1_choice(selector=selector)]
#[derive(Clone)]
pub struct Asn1Pkcs7Elem {
	pub selector :Asn1Pkcs7Selector,
	pub data : Asn1Ndef<Asn1OctData,0>,
	pub signed : Asn1Ndef<Asn1Pkcs7Signed,0>,
	pub envlop :Asn1Ndef<Asn1Pkcs7Envelope,0>,
	pub envlopsigned :Asn1Ndef<Asn1Pkcs7SignedEnvelope,0>,
	pub digestdata :Asn1Ndef<Asn1Pkcs7Digest,0>,
	pub encryptdata : Asn1Ndef<Asn1Pkcs7Encrypt,0>,
}

impl Asn1Pkcs7Elem {
	pub fn set_type(&mut self,types :&str) -> Result<(),Box<dyn Error>> {
		let oid :String;
		if types == PKCS7_TYPE_DATA {
			oid = PKCS7_DATA_OID.to_string();
		} else if types == PKCS7_TYPE_SIGNED  {
			oid = PKCS7_SIGNED_DATA_OID.to_string();
		} else if types == PKCS7_TYPE_ENVLOP  {
			oid = PKCS7_ENVLOP_DATA_OID.to_string();
		} else if types == PKCS7_TYPE_ENVLOP_AND_SIGNED  {
			oid = PKCS7_ENVLOP_AND_SIGNED_DATA_OID.to_string();
		} else if types == PKCS7_TYPE_DIGEST  {
			oid = PKCS7_DIGEST_DATA_OID.to_string();
		} else if types == PKCS7_TYPE_ENCRYPTED  {
			oid = PKCS7_ENCRYPTED_DATA_OID.to_string();
		} else {
			ssllib_new_error!{SslPkcs7Error,"not supported type {}", types}
		}
		self.selector.val.set_value(&oid)?;

		self.data = Asn1Ndef::init_asn1();
		self.signed = Asn1Ndef::init_asn1();
		self.envlop = Asn1Ndef::init_asn1();
		self.envlopsigned = Asn1Ndef::init_asn1();
		self.digestdata = Asn1Ndef::init_asn1();
		self.encryptdata = Asn1Ndef::init_asn1();
		Ok(())
	}

	pub fn add_signer(&mut self,si :&Asn1Pkcs7SignerInfo) -> Result<(),Box<dyn Error>> {
		let selstr :String = self.selector.encode_select()?;
		let mut osi :Option<&Asn1Set<Asn1Pkcs7SignerInfo>> = None;
		let mut omd :Option<&Asn1Set<Asn1X509Algor>> = None;
		if selstr == PKCS7_TYPE_SIGNED {
			if self.signed.val.is_some() {
				let refv = self.signed.val.as_ref().unwrap();
				if refv.elem.val.len() > 0 {
					osi = Some(&refv.elem.val[0].signer_info);
					omd = Some(&refv.elem.val[0].md_algs);
				}
			}
		} else if selstr == PKCS7_TYPE_ENVLOP_AND_SIGNED {
			if self.envlopsigned.val.is_some() {
				let refv = self.envlopsigned.val.as_ref().unwrap();
				if refv.elem.val.len() > 0 {
					if refv.elem.val[0].signer_info.val.is_some() {
						osi = Some(refv.elem.val[0].signer_info.val.as_ref().unwrap());						
					}
					if refv.elem.val[0].md_algs.val.is_some() {
						omd = Some(refv.elem.val[0].md_algs.val.as_ref().unwrap());
					}
				}
			}
		} else {
			ssllib_new_error!{SslPkcs7Error,"not supported type [{}] for add signer",selstr}
		}
		let mut searched :bool = false;
		if si.elem.val.len() < 1{ 
			ssllib_new_error!{SslPkcs7Error,"val {} < 1",si.elem.val.len()}
		}
		let cmdstr :String = si.elem.val[0].digest_alg.get_algorithm()?;
		if osi.is_some() && omd.is_some() {
			let mut mdstr :String;
			if si.elem.val.len() > 0 {
				let cv = omd.unwrap();

				for idx in 0..cv.val.len()	{
					mdstr = cv.val[idx].get_algorithm()?;
					if mdstr == cmdstr {
						searched = true;
						break;
					}
				}
			}
		}

		if !searched {
			// let mut csigner :Asn1Pkcs7SignerInfo = Asn1Pkcs7SignerInfo::init_asn1();
			// if selstr == PKCS7_TYPE_SIGNED {
			// 	if self.signed.val.is_some() {
			// 		csigner  = self.signed.val.as_ref().unwrap().clone();
			// 	}
			// } else if selstr == PKCS7_TYPE_ENVLOP_AND_SIGNED {
			// 	if self.envlopsigned.val.is_some() {
			// 		csigner = self.envlopsigned.val.as_ref().unwrap().clone();
			// 	}
			// }

			// csigner.
		}

		Ok(())
	}
}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7 {
	pub elem :Asn1Seq<Asn1Pkcs7Elem>,
}

#[allow(dead_code)]
impl Asn1Pkcs7 {

	pub fn set_type(&mut self,types :&str) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			self.elem.val.push(Asn1Pkcs7Elem::init_asn1());
		}
		return self.elem.val[0].set_type(types);
	}

	pub fn is_signed_data(&self) -> bool {
		if self.elem.val.len() < 1 {
			return false;
		}
		let ores = self.elem.val[0].selector.encode_select();
		if ores.is_err() {
			return false;
		}
		let val = ores.unwrap();
		if val == "signed" {
			return true;
		}
		return false;
	}

	pub fn get_signed_data(&self) -> Result<&Asn1Pkcs7Signed,Box<dyn Error>> {
		if self.is_signed_data() {
			let p = self.elem.val[0].signed.val.as_ref().unwrap();
			return Ok(p);
		}
		ssllib_new_error!{SslPkcs7Error,"not signed data"}
	}

	pub fn get_signed_data_mut(&mut self) -> Result<&mut Asn1Pkcs7Signed,Box<dyn Error>> {
		if self.is_signed_data() {
			return Ok(self.elem.val[0].signed.val.as_mut().unwrap());
		}
		ssllib_new_error!{SslPkcs7Error,"not signed data"}	
	}

	pub fn add_signer(&mut self,si :&Asn1Pkcs7SignerInfo) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			self.elem.val.push(Asn1Pkcs7Elem::init_asn1());
		}

		let _ = self.elem.val[0].add_signer(si)?;

		Ok(())
	}

}
