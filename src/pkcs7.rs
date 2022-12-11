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
	pub digest_algo : Asn1X509Algor,
	pub auth_attr : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,0>>,
	pub digest_enc_algo : Asn1X509Algor,
	pub enc_digest : Asn1OctData,
	pub unauth_attr : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,1>>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs7SignerInfo {
	pub elem : Asn1Seq<Asn1Pkcs7SignerInfoElem>,
}

impl Asn1Pkcs7SignerInfo {
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

	fn get_digest_op(&self) -> Box<dyn Asn1DigestOp> {
		let mut retv :Box<dyn Asn1DigestOp> = Box::new(Sha256Digest::new());

		if self.elem.val[0].digest_algo.elem.val.len() > 0 {
			let c = &(self.elem.val[0].digest_algo.elem.val[0]);
			let digval :String = c.algorithm.get_value();
			if digval.eq(OID_SHA256_DIGEST) {
				retv = Box::new(Sha256Digest::new());
			}
		}


		retv
	}

	pub fn sign_auth_attr_enc<T : Asn1SignOp>(&mut self, signer :&T) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() != 1 && self.elem.val.len() != 0 {
			ssllib_new_error!{SslPkcs7Error,"val [{}] != 0 or 1",self.elem.val.len()}	
		}
		if self.elem.val.len() != 0 {
			let encdata = self.format_auth_attr_data()?;
			ssllib_buffer_trace!(encdata.as_ptr(),encdata.len(),"sign data");
			let digop = self.get_digest_op();
			self.elem.val[0].enc_digest.data = signer.sign(&encdata,digop)?;
		}
		Ok(())
	}

}
