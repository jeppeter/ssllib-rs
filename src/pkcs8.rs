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
use crate::x509::*;

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
}

