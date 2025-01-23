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

use crate::x509::*;
use crate::pkcs7::*;
use crate::kdfutils::{get_pkcs12kdf_sha256};
use crate::digest::{calc_hmac_sha256};
use crate::utils::{check_equal_u8,expand_uni};
use crate::consts::{OID_SHA256_DIGEST,PKCS12_MAC_ID,SHA256_DIGEST_SIZE};

ssllib_error_class!{SslPkcs12Error}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1AuthSafes {
	pub safes :Asn1Seq<Asn1Pkcs7>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12MacDataElem {
	pub dinfo : Asn1X509Sig,
	pub salt : Asn1OctData,
	pub iternum : Asn1Integer,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12MacData {
	pub elem : Asn1Seq<Asn1Pkcs12MacDataElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12Elem {
	pub version : Asn1Integer,
	pub authsafes : Asn1Pkcs7,
	pub mac : Asn1Opt<Asn1Pkcs12MacData>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12 {
	pub elem : Asn1Seq<Asn1Pkcs12Elem>,
}

impl Asn1Pkcs12 {
	#[allow(unused_comparisons)]
	pub fn verify_digest(&self,passwd:&str) -> Result<bool,Box<dyn Error>> {
		let mut retval :bool = false;
		if self.elem.val.len() < 1 {
			ssllib_new_error!{SslPkcs12Error,"elem {} < 1",self.elem.val.len()}
		}
		if self.elem.val[0].mac.val.is_none() {
			ssllib_new_error!{SslPkcs12Error,"mac none"}
		}
		let macdata :&Asn1Pkcs12MacData = self.elem.val[0].mac.val.as_ref().unwrap();
		if macdata.elem.val.len() < 1 {
			ssllib_new_error!{SslPkcs12Error,"macdata elem {} <１",macdata.elem.val.len()}
		}
		let dinfo :Asn1X509Sig = macdata.elem.val[0].dinfo.clone();
		if dinfo.elem.val.len() < 1 {
			ssllib_new_error!{SslPkcs12Error,"dinfo elem {} < 1", dinfo.elem.val.len()}
		}
		if dinfo.elem.val[0].algor.elem.val.len() < 0 {
			ssllib_new_error!{SslPkcs12Error,"dinfo.algor elem {} < 1", dinfo.elem.val[0].algor.elem.val.len()}	
		}
		if dinfo.elem.val[0].algor.elem.val[0].algorithm.get_value() == OID_SHA256_DIGEST {
			let digest :Vec<u8> = dinfo.elem.val[0].digest.data.clone();
			let salt :Vec<u8> = macdata.elem.val[0].salt.data.clone();
			let iternum = macdata.elem.val[0].iternum.val;
			let hmac = get_pkcs12kdf_sha256(passwd.as_bytes(),&salt,PKCS12_MAC_ID,iternum as usize,SHA256_DIGEST_SIZE);
			if self.elem.val[0].authsafes.elem.val.len() < 0 {
				ssllib_new_error!{SslPkcs12Error,"authsafes {} < 0",self.elem.val[0].authsafes.elem.val.len()}
			}
			if self.elem.val[0].authsafes.elem.val[0].data.val.is_none() {
				ssllib_new_error!{SslPkcs12Error,"authsafes.data none"}	
			}
			let chkd :&Asn1OctData = self.elem.val[0].authsafes.elem.val[0].data.val.as_ref().unwrap();
			let chkdata = chkd.data.clone();
			let calcdigest = calc_hmac_sha256(&hmac,&chkdata);
			if !check_equal_u8(&calcdigest,&digest) {
				let unipass = expand_uni(passwd.as_bytes());
				let hmac = get_pkcs12kdf_sha256(&unipass,&salt,PKCS12_MAC_ID,iternum as usize,SHA256_DIGEST_SIZE);
				let calcdigest = calc_hmac_sha256(&hmac,&chkdata);
				if check_equal_u8(&calcdigest,&digest) {
					retval = true;
				}
			} else {
				retval = true;
			}
		} else {
			ssllib_new_error!{SslPkcs12Error,"algorithm {} not supported", dinfo.elem.val[0].algor.elem.val[0].algorithm.get_value()}
		}
		Ok(retval)
	}

	pub fn get_authsafe_oid(&self) -> Result<String,Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			ssllib_new_error!{SslPkcs12Error,"no elems"}
		}
		if self.elem.val[0].authsafes.elem.val.len() == 0 {
			ssllib_new_error!{SslPkcs12Error,"no authsafes"}	
		}
		Ok(self.elem.val[0].authsafes.elem.val[0].selector.val.get_value())
	}

	pub fn get_authsafe_data(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			ssllib_new_error!{SslPkcs12Error,"no elems"}
		}
		if self.elem.val[0].authsafes.elem.val.len() == 0 {
			ssllib_new_error!{SslPkcs12Error,"no authsafes"}	
		}
		if self.elem.val[0].authsafes.elem.val[0].data.val.is_none() {
			ssllib_new_error!{SslPkcs12Error,"data authsafes none"}		
		}
		return Ok(self.elem.val[0].authsafes.elem.val[0].data.val.as_ref().unwrap().data.clone());
	}

}

#[asn1_obj_selector(selector=val,any=default,x509cert="1.2.840.113549.1.9.22.1")]
#[derive(Clone)]
pub struct Asn1Pkcs12BagsSelector {
	pub val : Asn1Object,
}


#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1Pkcs12BagsElem {
	pub valid : Asn1Pkcs12BagsSelector,
	pub x509cert : Asn1ImpSet<Asn1OctData,0>,
	pub any :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12Bags {
	pub elem :Asn1Seq<Asn1Pkcs12BagsElem>,
}

#[asn1_obj_selector(selector=val,any=default,shkeybag="1.2.840.113549.1.12.10.1.2",bag=["1.2.840.113549.1.12.10.1.3"])]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelector {
	pub val : Asn1Object,
}

#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelectElem {
	pub valid : Asn1Pkcs12SafeBagSelector,
	pub shkeybag : Asn1ImpSet<Asn1X509Sig,0>,
	pub bag : Asn1ImpSet<Asn1Pkcs12Bags,0>,
	pub any :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagElem {
	pub selectelem : Asn1Pkcs12SafeBagSelectElem,
	pub attrib : Asn1Opt<Asn1Set<Asn1X509Attribute>>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBag {
	pub elem : Asn1Seq<Asn1Pkcs12SafeBagElem>,
}
