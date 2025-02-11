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
use crate::consts::*;

use crate::x509::*;
use crate::pkcs7::*;
use crate::pkcs8::Asn1Pkcs8PrivKeyInfo;
use crate::kdfutils::{get_pkcs12kdf_sha256};
use crate::digest::{calc_hmac_sha256};
use crate::utils::{check_equal_u8,expand_uni};
use std::sync::Arc;
use std::cell::RefCell;
use crate::impls::{Asn1EncryptOp,Asn1DecryptOp,Asn1SignOp};
use crate::ec::{ECSign};

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


impl Asn1Pkcs12Elem {

	#[allow(unused_comparisons)]
	pub fn verify_digest(&self,passin :&[u8]) -> Result<bool,Box<dyn Error>> {
		let mut retval :bool = false;
		if self.mac.val.is_none() {
			ssllib_new_error!{SslPkcs12Error,"mac none"}
		}
		let macdata :&Asn1Pkcs12MacData = self.mac.val.as_ref().unwrap();
		let _ = macdata.elem.check_safe_one("Asn1Pkcs12MacData")?;
		let dinfo :Asn1X509Sig = macdata.elem.val[0].dinfo.clone();
		let _ = dinfo.elem.check_safe_one("Asn1X509Sig")?;
		let _ = dinfo.elem.val[0].algor.elem.check_safe_one("Asn1X509Algor")?;
		if dinfo.elem.val[0].algor.elem.val[0].algorithm.get_value() == OID_SHA256_DIGEST {
			let digest :Vec<u8> = dinfo.elem.val[0].digest.data.clone();
			let salt :Vec<u8> = macdata.elem.val[0].salt.data.clone();
			let iternum = macdata.elem.val[0].iternum.val;
			let hmac = get_pkcs12kdf_sha256(passin,&salt,PKCS12_MAC_ID,iternum as usize,SHA256_DIGEST_SIZE);
			let _ = self.authsafes.elem.check_safe_one("Asn1Pkcs12SafeBag")?;
			if self.authsafes.elem.val[0].data.val.is_none() {
				ssllib_new_error!{SslPkcs12Error,"authsafes.data none"}	
			}
			let chkd :&Asn1OctData = self.authsafes.elem.val[0].data.val.as_ref().unwrap();
			let chkdata = chkd.data.clone();
			let calcdigest = calc_hmac_sha256(&hmac,&chkdata);
			if !check_equal_u8(&calcdigest,&digest) {
				let unipass = expand_uni(passin);
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

	fn _get_key_certs_with_bags(&self,passin :&[u8],bags :&Asn1Seq<Asn1Pkcs12SafeBag>) -> Result<(Vec<Asn1X509>,Vec<Asn1X509>),Box<dyn Error>> {
		let mut bagidx :usize = 0;
		let mut keycert :Vec<Asn1X509> = vec![];
		let mut certs :Vec<Asn1X509> = vec![];
		for certd in bags.val.iter() {
			let _ = certd.elem.check_safe_one("Asn1Pkcs12Bags")?;
			let objs = certd.get_type_oid()?;
			let ofriendly = certd.get_attrib(OID_FRIEDLY_NAME)?;
			let olkid = certd.get_attrib(OID_LOCAL_KEY_ID)?;
			ssllib_log_trace!("bag [{}] objs[{}]",bagidx,objs);
			if objs == OID_PKCS12_CERT_BAG {
				let ores = certd.get_bag_oid();
				if ores.is_ok() {
					let bagoid = ores.unwrap();
					if bagoid == OID_X509_CERTIFICATE {
						let ores = certd.get_x509_cert();
						if ores.is_ok() {
							let mut curx509 :Asn1X509 = ores.unwrap();
							if ofriendly.is_some() {
								
							}
						}
					}
				}
			} else if objs == OID_SAFE_CONTENT_BAG {
				/**/
			}
			bagidx += 1;
		}
		return Ok((keycert,certs));
	}

	fn _get_key_certs(&self,passin :&[u8]) -> Result<(Vec<Asn1X509>,Vec<Asn1X509>),Box<dyn Error>> {
		let mut keycert :Vec<Asn1X509> = vec![];
		let mut certs :Vec<Asn1X509> = vec![];
		let oid = self.get_authsafe_oid()?;
		if oid != OID_PKCS7_DATA {
			ssllib_new_error!{SslPkcs12Error,"oid [{}] not supported",oid}
		}
		let data = self.get_authsafe_data()?;
		let mut safes :Asn1AuthSafes = Asn1AuthSafes::init_asn1();
		safes.decode_asn1(&data)?;
		for idx in 0..safes.safes.val.len() {
			let _ = safes.safes.val[idx].elem.check_safe_one("Asn1Pkcs7")?;
			let octdata = safes.safes.val[idx].elem.val[0].get_safe_bags(passin)?;
			let (nkey,ncerts) = self._get_key_certs_with_bags(passin,&octdata)?;
			if nkey.len() != 0 {
				if keycert.len() > 0 {
					keycert[0] = nkey[0].clone();
				} else {
					keycert.push(nkey[0].clone());
				}
			}
			certs.extend(ncerts);
		}

		return Ok((keycert,certs));
	}


	pub fn get_key_certs(&self,passin :&[u8]) -> Result<(Vec<Asn1X509>,Vec<Asn1X509>),Box<dyn Error>> {
		if passin.len() == 0 {
			if self.mac.val.is_some() {
				let vfy = self.verify_digest(passin)?;
				if !vfy {
					ssllib_new_error!{SslPkcs12Error,"not verify digest"}
				}
			}
		}

		return self._get_key_certs(passin);
	}

	pub fn get_authsafe_oid(&self) -> Result<String,Box<dyn Error>> {
		if self.authsafes.elem.val.len() == 0 {
			ssllib_new_error!{SslPkcs12Error,"no authsafes"}	
		}
		Ok(self.authsafes.elem.val[0].selector.val.get_value())
	}

	pub fn get_authsafe_data(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.authsafes.elem.val.len() == 0 {
			ssllib_new_error!{SslPkcs12Error,"no authsafes"}	
		}
		if self.authsafes.elem.val[0].data.val.is_none() {
			ssllib_new_error!{SslPkcs12Error,"data authsafes none"}		
		}
		return Ok(self.authsafes.elem.val[0].data.val.as_ref().unwrap().data.clone());
	}


	fn _get_sign(&self,signtype :&str,pktype :&str, data :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1SignOp>>>,Box<dyn Error>> {
		let mut retv :Option<Arc<RefCell<dyn Asn1SignOp>>> = None;
		if pktype == PKCS8_PRIVATE_KEY_TYPE {
			if signtype == OID_EC_PUBLICKEY_ENCRYPTION {
				let mut signv :ECSign = ECSign::new();
				let initv :Vec<u8> = vec![];
				signv.sign_init(data,&initv)?;
				retv = Some(Arc::new(RefCell::new(signv)));
			}
		}
		return Ok(retv);
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
			let _ = safes.safes.val[idx].elem.check_safe_one("Asn1Pkcs7")?;
			let octdata = safes.safes.val[idx].elem.val[0].get_safe_bags(passin)?;
			let mut bagidx :usize = 0;
			for certd in octdata.val.iter() {
				let _ = certd.elem.check_safe_one("Asn1Pkcs12Bags")?;
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
					let ores = pkcs8obj.get_private_key(passin);
					if ores.is_ok() {
						let (enctype,odata) = ores.unwrap();
						return Ok((enctype,PKCS8_PRIVATE_KEY_TYPE.to_string(),odata));
					} else {
						ssllib_log_trace!("error {:?}",ores.err().unwrap());
					}
				} else if objs == OID_KEY_BAG {
					if certd.elem.val[0].selectelem.keybag.val.len() > 0 {
						let  pkcs8obj :&Asn1Pkcs8PrivKeyInfo = &certd.elem.val[0].selectelem.keybag.val[0];	
						let ores = pkcs8obj.get_private_key(passin);
						if ores.is_ok() {
							let (enctype,odata) = ores.unwrap();
							return Ok((enctype,PKCS8_PRIVATE_KEY_TYPE.to_string(),odata));
						} else {
							ssllib_log_trace!("error {:?}",ores.err().unwrap());
						}

					}
					
				}
				bagidx += 1;
			}
		}

		ssllib_new_error!{SslPkcs12Error,"no part for pkcs7"}
	}


	pub fn get_sign_op(&self,passin :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1SignOp>>>,Box<dyn Error>> {
		let (enctype,objtype,odata) = self._get_enctype(passin)?;
		ssllib_buffer_trace!(odata.as_ptr(),odata.len(),"enctype {} objtype {}",enctype,objtype);
		return self._get_sign(&enctype,&objtype,&odata);
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

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12 {
	pub elem : Asn1Seq<Asn1Pkcs12Elem>,
}

impl Asn1Pkcs12 {
	#[allow(unused_comparisons)]
	pub fn verify_digest(&self,passin :&[u8]) -> Result<bool,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1Pkcs12")?;
		return self.elem.val[0].verify_digest(passin);
	}

	pub fn get_authsafe_oid(&self) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1Pkcs12")?;
		return self.elem.val[0].get_authsafe_oid();
	}

	pub fn get_authsafe_data(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1Pkcs12")?;
		return self.elem.val[0].get_authsafe_data();
	}




	pub fn get_sign_op(&self,passin :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1SignOp>>>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1Pkcs12")?;
		return self.elem.val[0].get_sign_op(passin);
	}

	pub fn get_enc_op(&self,passin :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1EncryptOp>>>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1Pkcs12")?;
		return self.elem.val[0].get_enc_op(passin);
	}

	pub fn get_dec_op(&self,passin :&[u8]) -> Result<Option<Arc<RefCell<dyn Asn1DecryptOp>>>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1Pkcs12")?;
		return self.elem.val[0].get_dec_op(passin);
	}

	pub fn get_key_certs(&self,passin :&[u8]) -> Result<(Vec<Asn1X509>,Vec<Asn1X509>),Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1Pkcs12")?;
		return self.elem.val[0].get_key_certs(passin);
	}
}

#[asn1_obj_selector(selector=val,other=default,x509cert="1.2.840.113549.1.9.22.1",sdsicert="1.2.840.113549.1.9.22.2",x509crl="1.2.840.113549.1.9.23.1")]
#[derive(Clone)]
pub struct Asn1Pkcs12BagsSelector {
	pub val : Asn1Object,
}


#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1Pkcs12BagsElem {
	#[asn1_gen(jsonalias="type")]
	pub valid : Asn1Pkcs12BagsSelector,
	pub x509cert : Asn1ImpSet<Asn1OctData,0>,
	pub x509crl :Asn1ImpSet<Asn1OctData,0>,
	pub sdsicert :Asn1ImpSet<Asn1IA5String,0>,
	pub other :Asn1ImpSet<Asn1Any,0>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12Bags {
	pub elem :Asn1Seq<Asn1Pkcs12BagsElem>,
}

#[asn1_obj_selector(selector=val,other=default,keybag="1.2.840.113549.1.12.10.1.1",shkeybag="1.2.840.113549.1.12.10.1.2",bag=["1.2.840.113549.1.12.10.1.3","1.2.840.113549.1.12.10.1.4","1.2.840.113549.1.12.10.1.5"],safes="1.2.840.113549.1.12.10.1.6")]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelector {
	pub val : Asn1Object,
}

#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelectElem {
	#[asn1_gen(jsonalias="type")]
	pub valid : Asn1Pkcs12SafeBagSelector,
	pub keybag :Asn1ImpSet<Asn1Pkcs8PrivKeyInfo,0>,
	pub shkeybag : Asn1ImpSet<Asn1X509Sig,0>,
	pub bag : Asn1ImpSet<Asn1Pkcs12Bags,0>,
	pub safes :Asn1ImpSet<Asn1Seq<Asn1Pkcs12SafeBag>,0>,
	pub other :Asn1ImpSet<Asn1Seq<Asn1Any>,0>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagElem {
	#[asn1_gen(jsonskip="true")]
	pub selectelem : Asn1Pkcs12SafeBagSelectElem,
	pub attrib : Asn1Opt<Asn1Set<Asn1X509Attribute>>,
}

impl Asn1Pkcs12SafeBagElem {
	pub fn get_attrib(&self,oid :&str) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let mut retv :Option<Asn1Any> = None;
		if self.attrib.val.is_some() {
			let c :&Asn1Set<Asn1X509Attribute> = self.attrib.val.as_ref().unwrap();
			for d in c.val.iter() {
				if d.elem.val.len() > 0 {
					let otype = d.elem.val[0].object.get_value();
					if otype == oid {
						if d.elem.val[0].set.val.len() > 0 {
							retv = Some(d.elem.val[0].set.val[0].clone());
						}						
						break;
					}
				}
			}
		}
		return Ok(retv);
	}

	pub fn get_type_oid(&self) -> Result<String,Box<dyn Error>> {
		Ok(self.selectelem.valid.val.get_value())
	}

	pub fn get_bag_oid(&self) -> Result<String,Box<dyn Error>> {
		let types = self.get_type_oid()?;
		if types != OID_PKCS12_CERT_BAG && types != OID_PKCS12_CRL_BAG && types != OID_SAFE_CONTENT_BAG {
			ssllib_new_error!{SslPkcs12Error,"not valid oid {}",types}
		}

		if self.selectelem.bag.val.len() == 0  || self.selectelem.bag.val[0].elem.val.len() < 1 {
			ssllib_new_error!{SslPkcs12Error,"no bag"}
		}
		Ok(self.selectelem.bag.val[0].elem.val[0].valid.val.get_value())
	}

	pub fn get_x509_cert(&self) -> Result<Asn1X509,Box<dyn Error>> {
		let bagoid = self.get_bag_oid()?;
		if bagoid != OID_X509_CERTIFICATE {
			ssllib_new_error!{SslPkcs12Error,"not valid OID_X509_CERTIFICATE {}",bagoid}
		}
		let mut retv :Asn1X509 = Asn1X509::init_asn1();
		if self.selectelem.bag.val[0].elem.val[0].x509cert.val.len() < 1 {
			ssllib_new_error!{SslPkcs12Error,"no x509cert"}	
		}

		let data = self.selectelem.bag.val[0].elem.val[0].x509cert.val[0].data.clone();
		retv.decode_asn1(&data)?;
		Ok(retv)
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBag {
	pub elem : Asn1Seq<Asn1Pkcs12SafeBagElem>,
}

impl Asn1Pkcs12SafeBag {
	pub fn get_attrib(&self,oid :&str) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let ores = self.elem.check_safe_one("Asn1Pkcs12SafeBag");
		if ores.is_err() {
			return Ok(None);
		}
		return self.elem.val[0].get_attrib(oid);
	}
	pub fn get_type_oid(&self) -> Result<String,Box<dyn Error>> {
		self.elem.check_safe_one("Asn1Pkcs12Bag")?;
		return self.elem.val[0].get_type_oid();
	}

	pub fn get_bag_oid(&self) -> Result<String,Box<dyn Error>> {
		self.elem.check_safe_one("Asn1Pkcs12Bag")?;
		return self.elem.val[0].get_bag_oid();
	}

	pub fn get_x509_cert(&self) -> Result<Asn1X509,Box<dyn Error>> {
		self.elem.check_safe_one("Asn1Pkcs12Bag")?;
		return self.elem.val[0].get_x509_cert();
	}
}

