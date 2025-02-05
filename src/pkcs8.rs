#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use asn1obj::*;

use std::error::Error;
use std::io::{Write};


use crate::*;
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};
use crate::x509::*;
use crate::ec::*;
use crate::consts::*;

ssllib_error_class!{SslPkcs8Error}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs8PrivKeyInfoElem {
	pub version :Asn1Integer,
	pub pkeyalg : Asn1X509Algor,
	pub pkey : Asn1OctData,
	pub attributes : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,0>>,
}

impl Asn1Pkcs8PrivKeyInfoElem {
	pub fn get_pkey(&self) -> Vec<u8> {
		return self.pkey.data.clone();
	}

}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs8PrivKeyInfo {
	pub elem : Asn1Seq<Asn1Pkcs8PrivKeyInfoElem>,
}

impl Asn1Pkcs8PrivKeyInfo {
	pub fn get_pkey(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.elem.val.len() < 1 {
			ssllib_new_error!{SslPkcs8Error,"Asn1Pkcs8PrivKeyInfo elem [{}] < 1", self.elem.val.len()}
		}
		Ok(self.elem.val[0].get_pkey())
	}

	pub fn get_algor(&self) -> Result<Asn1X509Algor,Box<dyn Error>> {
		if self.elem.val.len() < 1 {
			ssllib_new_error!{SslPkcs8Error,"Asn1Pkcs8PrivKeyInfo elem [{}] < 1", self.elem.val.len()}
		}
		Ok(self.elem.val[0].pkeyalg.clone())
	}

	pub fn set_pkey(&mut self,key :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.elem.val.len() != 0 && self.elem.val.len() != 1 {
			ssllib_new_error!{SslPkcs8Error,"Asn1Pkcs8PrivKeyInfo elem [{}] not valid" ,self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			self.elem.val.push(Asn1Pkcs8PrivKeyInfoElem::init_asn1());
		}

		let retv :Vec<u8> = self.elem.val[0].pkey.data.clone();
		self.elem.val[0].pkey.data = key.to_vec().clone();
		Ok(retv)
	}

	pub fn set_algorithm(&mut self,algor :&Asn1X509Algor) -> Result<Asn1X509Algor,Box<dyn Error>> {
		if self.elem.val.len() != 0 && self.elem.val.len() != 1 {
			ssllib_new_error!{SslPkcs8Error,"Asn1Pkcs8PrivKeyInfo elem [{}] not valid" ,self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			self.elem.val.push(Asn1Pkcs8PrivKeyInfoElem::init_asn1());
		}

		let retv :Asn1X509Algor = self.elem.val[0].pkeyalg.clone();
		self.elem.val[0].pkeyalg = algor.clone();
		Ok(retv)
	}

	pub fn get_private_key(&self,_passin :&[u8]) -> Result<(String,Vec<u8>),Box<dyn Error>> {
		/*now get the type*/
		let mut obj :Asn1Object =  Asn1Object::init_asn1();
		let _ = self.elem.check_safe_one("Asn1Pkcs8PrivKeyInfo")?;
		let types = self.elem.val[0].pkeyalg.get_algorithm()?;
		let rets :String;
		let retdata :Vec<u8>;
		if types == OID_EC_PUBLICKEY_ENCRYPTION {
			let ooany :Option<Asn1Any> = self.elem.val[0].pkeyalg.get_param()?;
			if ooany.is_none() {
				ssllib_new_error!{SslPkcs8Error,"no param in Asn1Pkcs8PrivKeyInfo"}
			}
			let oany = ooany.unwrap();
			let data = oany.encode_asn1()?;
			obj.decode_asn1(&data)?;
			let mut ecpriv :ECPrivateKeyAsn1 = ECPrivateKeyAsn1::init_asn1();
			let mut necpriv :ECPrivateKeyAsn1 = ECPrivateKeyAsn1::init_asn1();
			ecpriv.decode_asn1(&self.elem.val[0].pkey.data)?;
			let ectype = obj.get_value();
			ssllib_log_trace!("ectype set [{}]",ectype);
			necpriv.set_ec_type_oid(&ectype)?;
			let data = ecpriv.get_private_key()?;
			let _ = necpriv.set_private_key(&data)?;
			
			let odata = ecpriv.get_public_key()?;
			if odata.is_some() {
				let data = odata.unwrap();
				let _ = necpriv.set_public_key(&data)?;
			}
			

			rets = format!("{}",types);
			retdata = necpriv.encode_asn1()?;			
		} else {
			ssllib_new_error!{SslPkcs8Error,"not supported type {}",types}
		}

		Ok((rets,retdata))
	}
}

