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
use crate::{ssllib_new_error,ssllib_error_class,ssllib_log_trace,ssllib_buffer_trace,ssllib_format_buffer_log};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};
use crate::consts::{OID_PKCS7_DATA,OID_PKCS7_ENCRYPTED_DATA,OID_PKCS8_SHROUDED_KEY_BAG};

use crate::x509::*;
use crate::pkcs7::*;
use crate::pkcs8::Asn1Pkcs8PrivKeyInfo;
use crate::kdfutils::{get_pkcs12kdf_sha256};
use crate::digest::{calc_hmac_sha256};
use crate::utils::{check_equal_u8,expand_uni};
use crate::consts::{OID_SHA256_DIGEST,PKCS12_MAC_ID,SHA256_DIGEST_SIZE,PKCS8_PRIVATE_KEY_TYPE};
use std::sync::Arc;
use std::cell::RefCell;
use crate::impls::{Asn1DigestOp,Asn1EncryptOp,Asn1DecryptOp};

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


	fn _get_enctype(&self,passin :&[u8]) -> Result<(String,String,Vec<u8>),Box<dyn Error>> {
		let oid = self.get_authsafe_oid()?;
		if oid != OID_PKCS7_DATA {
			ssllib_new_error!{SslPkcs12Error,"oid [{}] not supported",oid}
		}
		let data = self.get_authsafe_data()?;
		let mut safes :Asn1AuthSafes = Asn1AuthSafes::init_asn1();
		safes.decode_asn1(&data)?;
		for idx in 0..safes.safes.val.len() {            
			let types = safes.safes.val[idx].elem.val[0].selector.val.get_value();
			ssllib_log_trace!("types [{}]",types);
			if types == OID_PKCS7_ENCRYPTED_DATA {
				let pk7encdata :&Asn1Pkcs7Encrypt = safes.safes.val[idx].elem.val[0].encryptdata.val.as_ref().unwrap();
				let encdata = pk7encdata.elem.val[0].enc_data.elem.val[0].enc_data.val.data.clone();
				let algordata = pk7encdata.elem.val[0].enc_data.elem.val[0].algorithm.encode_asn1()?;
				ssllib_log_trace!(" ");
				let decdata = get_algor_pbkdf2_private_data(&algordata,&encdata,passin)?;
				ssllib_buffer_trace!(decdata.as_ptr(),decdata.len(),"decdata");
				let mut octdata :Asn1Seq<Asn1Pkcs12SafeBag> = Asn1Seq::init_asn1();
				ssllib_log_trace!(" ");
				let _ = octdata.decode_asn1(&decdata)?;
				let mut certidx :usize = 0;
				ssllib_log_trace!(" ");
				for certd in octdata.val.iter() {
					let objs = certd.elem.val[0].selectelem.valid.val.get_value();
					//ssllib_buffer_trace!(encd.as_ptr(),encd.len(),"PKCS12_SAFEBAG");
					if objs == OID_PKCS8_SHROUDED_KEY_BAG {
						ssllib_log_trace!(" ");
						let x509sig :Asn1X509Sig = certd.elem.val[0].selectelem.shkeybag.val[0].clone();
						let algr :&Asn1X509Algor = x509sig.get_algor()?;
						let v8 :Vec<u8> = x509sig.get_encrypt_data()?;
						let algrdata = algr.encode_asn1()?;
						let ddata = get_algor_pbkdf2_private_data(&algrdata,&v8,passin)?;
						ssllib_buffer_trace!(ddata.as_ptr(),ddata.len(),"certidx [{}] x509",certidx);
						let mut pkcs8obj :Asn1Pkcs8PrivKeyInfo = Asn1Pkcs8PrivKeyInfo::init_asn1();
						pkcs8obj.decode_asn1(&ddata)?;
						//let v8 = x509sig.encode_asn1()?;
						let ores = pkcs8obj.get_private_key(passin);
						if ores.is_ok() {
							let (enctype,odata) = ores.unwrap();
							return Ok((enctype,PKCS8_PRIVATE_KEY_TYPE.to_string(),odata));							
						} else {
							ssllib_log_trace!("error {:?}",ores.err().unwrap());
						}
					} else  {
						ssllib_log_trace!("certidx [{}] objs [{}]",certidx,objs);
					}
					certidx += 1;
				}

			} else if types ==  OID_PKCS7_DATA {
				let pk7data :&Asn1OctData = safes.safes.val[idx].elem.val[0].data.val.as_ref().unwrap();
				let decdata = pk7data.data.clone();
				let mut octdata :Asn1Seq<Asn1Pkcs12SafeBag> = Asn1Seq::init_asn1();
				let _ = octdata.decode_asn1(&decdata)?;
				let mut bagidx :usize = 0;
				for certd in octdata.val.iter() {
					let objs = certd.elem.val[0].selectelem.valid.val.get_value();
					ssllib_log_trace!("bag [{}] objs[{}]",bagidx,objs);
					if objs == OID_PKCS8_SHROUDED_KEY_BAG {
						ssllib_log_trace!(" ");
						let x509sig :Asn1X509Sig = certd.elem.val[0].selectelem.shkeybag.val[0].clone();
						let algr :&Asn1X509Algor = x509sig.get_algor()?;
						let v8 :Vec<u8> = x509sig.get_encrypt_data()?;
						let algrdata = algr.encode_asn1()?;
						let ddata = get_algor_pbkdf2_private_data(&algrdata,&v8,passin)?;
						ssllib_buffer_trace!(ddata.as_ptr(),ddata.len(),"bagidx [{}] x509",bagidx);
						let mut pkcs8obj :Asn1Pkcs8PrivKeyInfo = Asn1Pkcs8PrivKeyInfo::init_asn1();
						pkcs8obj.decode_asn1(&ddata)?;
						//let v8 = x509sig.encode_asn1()?;
						let ores = pkcs8obj.get_private_key(passin);
						if ores.is_ok() {
							let (enctype,odata) = ores.unwrap();
							return Ok((enctype,PKCS8_PRIVATE_KEY_TYPE.to_string(),odata));							
						} else {
							ssllib_log_trace!("error {:?}",ores.err().unwrap());
						}
					}
					bagidx += 1;
				}
			}
		}

		ssllib_new_error!{SslPkcs12Error,"no part for pkcs7"}
	}

	pub fn get_digest_op(&self,passin :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1DigestOp>>>,Box<dyn Error>> {
		let (enctype,objtype,odata) = self._get_enctype(passin)?;
		ssllib_buffer_trace!(odata.as_ptr(),odata.len(),"enctype {} objtype {}",enctype,objtype);
		ssllib_new_error!{SslPkcs12Error,"not supported digest"}
	}

	pub fn get_enc_op(&self,passin :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1EncryptOp>>>,Box<dyn Error>> {
		let (enctype,objtype,odata) = self._get_enctype(passin)?;
		ssllib_buffer_trace!(odata.as_ptr(),odata.len(),"enctype {} objtype {}",enctype,objtype);
		ssllib_new_error!{SslPkcs12Error,"not supported digest"}
	}

	pub fn get_dec_op(&self,passin :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1DecryptOp>>>,Box<dyn Error>> {
		let (enctype,objtype,odata) = self._get_enctype(passin)?;
		ssllib_buffer_trace!(odata.as_ptr(),odata.len(),"enctype {} objtype {}",enctype,objtype);
		ssllib_new_error!{SslPkcs12Error,"not supported digest"}
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
