#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
use asn1obj::asn1impl::*;
use asn1obj::complex::*;
use asn1obj::base::*;
use asn1obj::strop::{asn1_format_line};
use serde_json;
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use std::error::Error;
use std::io::Write;

use crate::{ssllib_error_class,ssllib_new_error};
use crate::x509::{Asn1X509Extension};
use crate::pkcs7::{Asn1Pkcs7};
use crate::digest::{ssllib_get_digest_by_oid};
use std::sync::Arc;
use std::cell::RefCell;
use crate::impls::{Asn1DigestOp};

ssllib_error_class!{SslTsError}


#[asn1_sequence()]
#[derive(Clone)]
pub struct AlgorithmIdentifierElem {
	pub algorithm :Asn1Object,
	pub parameters :Asn1Opt<Asn1Any>,
}

impl AlgorithmIdentifierElem {
	pub fn set_value(&mut self, oid :&str, oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		self.algorithm.set_value(oid)?;
		if oany.is_some() {
			self.parameters.val = Some(oany.as_ref().unwrap().clone());
		} else {
			self.parameters.val = None;
		}
		Ok(())
	}

	pub fn get_hash_algo(&self)	-> Result<String,Box<dyn Error>> {
		Ok(self.algorithm.get_value())
	}

	pub fn get_param(&self) -> Result<Option<Asn1Any>, Box<dyn Error>> {
		if self.parameters.val.is_none() {
			return Ok(None);
		}
		let val = self.parameters.val.as_ref().unwrap().clone();
		Ok(Some(val))
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct AlgorithmIdentifier {
	pub elem :Asn1Seq<AlgorithmIdentifierElem>,
}

impl AlgorithmIdentifier {
	fn _make_sure_elem(&mut self) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			self.elem.val.push(AlgorithmIdentifierElem::init_asn1());
		}
		Ok(())		
	}
	pub fn set_value(&mut self, oid :&str, oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		self._make_sure_elem()?;
		return self.elem.val[0].set_value(oid,oany);
	}
	pub fn get_hash_algo(&self)	-> Result<String,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("AlgorithmIdentifierElem")?;
		return self.elem.val[0].get_hash_algo();
	}
	pub fn get_param(&self) -> Result<Option<Asn1Any>, Box<dyn Error>> {
		let _ = self.elem.check_safe_one("AlgorithmIdentifierElem")?;
		return self.elem.val[0].get_param();
	}
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct MessageImprintElem {
	pub digestAlgorithm :AlgorithmIdentifier,
	pub digest :Asn1OctData,
}

impl MessageImprintElem {
	pub fn set_digest_param(&mut self, digoid :&str, param :&Asn1Any) -> Result<(),Box<dyn Error>> {
		let _  = self.digestAlgorithm.set_value(digoid,Some(param.clone()))?;
		Ok(())
	}

	pub fn get_digest_algo(&self) -> Result<AlgorithmIdentifier,Box<dyn Error>> {
		Ok(self.digestAlgorithm.clone())
	}

	pub fn set_digest(&mut self,digcode :&[u8]) -> Result<(),Box<dyn Error>> {
		self.digest.data = digcode.to_vec().clone();
		Ok(())
	}

	pub fn get_digest(&self) -> Result<Vec<u8>, Box<dyn Error>> {
		Ok(self.digest.data.clone())
	}
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct MessageImprint {
	pub elem :Asn1Seq<MessageImprintElem>,
}



impl MessageImprint {
	pub fn set_digest_param(&mut self, digoid :&str, param :&Asn1Any) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("MessageImprintElem")?;
		return self.elem.val[0].set_digest_param(digoid,param);
	}

	pub fn set_digest(&mut self,digcode :&[u8]) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("MessageImprintElem")?;
		return self.elem.val[0].set_digest(digcode);
	}

	pub fn get_digest_algo(&self) -> Result<AlgorithmIdentifier,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("MessageImprintElem")?;
		return self.elem.val[0].get_digest_algo();
	}

	pub fn get_digest(&self) -> Result<Vec<u8>, Box<dyn Error>> {
		let _ = self.elem.check_safe_one("MessageImprintElem")?;
		return self.elem.val[0].get_digest();
	}

}


#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampAccuracyElem {
	pub seconds :Asn1Opt<Asn1Integer>,
	pub millis :Asn1Opt<Asn1Imp<Asn1Integer,0>>,
	pub micros :Asn1Opt<Asn1Imp<Asn1Integer,1>>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampAccuracy {
	pub elem :Asn1Seq<TimeStampAccuracyElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampTokenElem {
	pub version :Asn1Integer,
	pub policy_id :Asn1Object,
	pub messageImprint :MessageImprint,
	pub serial :Asn1BigNum,
	pub time :Asn1Time,
	pub accuracy :TimeStampAccuracy,
	pub ordering :Asn1Boolean,
	pub nonce :Asn1Integer,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampToken {
	pub elem :Asn1Seq<TimeStampTokenElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampReqElem {
	version :Asn1Integer,
	messageimprint :MessageImprint,
	reqpolicy :Asn1Opt<Asn1Object>,
	nonce :Asn1Opt<Asn1Integer>,
	certreq :Asn1Boolean,
	extensions :Asn1Opt<Asn1ImpSet<Asn1X509Extension,0>>,
}

impl TimeStampReqElem {
	pub fn check_request_base(&self) -> Result<bool, Box<dyn Error>> {
		if self.version.val != 1 {
			ssllib_new_error!{SslTsError,"version {} != 1", self.version.val}
		}
		let msgprnt :&MessageImprint = &self.messageimprint;
		let _algo :AlgorithmIdentifier = msgprnt.get_digest_algo()?;
		let bytes :Vec<u8> = vec![0,0,0,0];
		let initv :Vec<u8> = vec![];
		let _digoid = _algo.get_hash_algo()?;
		let odigop  = ssllib_get_digest_by_oid(&_digoid);
		if odigop.is_none() {
			ssllib_new_error!{SslTsError,"no [{}] for digest", _digoid}
		}
		let digop :Arc<RefCell<dyn Asn1DigestOp>> = odigop.unwrap();
		digop.borrow_mut().init_digest(0,&initv)?;
		digop.borrow_mut().digest_update(&bytes)?;
		let result = digop.borrow_mut().digest_final()?;
		let digval = msgprnt.get_digest()?;
		if result.len() != digval.len() {
			ssllib_new_error!{SslTsError,"{} length != {}", result.len(),digval.len()}
		}

		Ok(true)
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampReq {
	pub elem :Asn1Seq<TimeStampReqElem>,
}

impl TimeStampReq {
	pub fn check_request_base(&self) -> Result<bool,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("TimeStampReqElem")?;
		return self.elem.val[0].check_request_base();
	}
}

impl TimeStampReqElem {
	pub fn set_version(&mut self, vernum :i32) -> Result<(),Box<dyn Error>> {
		self.version.val = vernum as i64;
		Ok(())
	}

	pub fn set_digest_param(&mut self, digoid :&str, param :&Asn1Any) -> Result<(),Box<dyn Error>> {
		return self.messageimprint.set_digest_param(digoid,param);
	}
 
	pub fn set_digest(&mut self,odigest:&[u8]) -> Result<(),Box<dyn Error>> {
		return self.messageimprint.set_digest(odigest);
	}

	pub fn set_certreq(&mut self, val :bool) -> Result<(),Box<dyn Error>> {
		self.certreq.val = val;
		Ok(())
	}

}

impl TimeStampReq {
	pub fn set_version(&mut self, vernum :i32) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("TimeStampReqElem")?;
		return self.elem.val[0].set_version(vernum);
	}

	pub fn set_digest_param(&mut self, digoid :&str, param :&Asn1Any) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("TimeStampReqElem")?;
		return self.elem.val[0].set_digest_param(digoid,param);
	}
 
	pub fn set_digest(&mut self,odigest:&[u8]) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("TimeStampReqElem")?;
		return self.elem.val[0].set_digest(odigest);
	}

	pub fn set_certreq(&mut self, val :bool) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("TimeStampReqElem")?;
		return self.elem.val[0].set_certreq(val);
	}

}


#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampRequestBlobElem {
	#[asn1_gen(jsonalias="type")]
	pub stype :Asn1Object,
	pub signature :Asn1OctData,	
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampRequestBlob {
	pub elem :Asn1Seq<TimeStampRequestBlobElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampRequestElem {
	#[asn1_gen(jsonalias="type")]
	pub stype :Asn1Object,
	pub blob :TimeStampRequestBlob,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampRequest {
	pub elem :TimeStampRequestElem,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct PKIStatusInfoElem {
	pub status :Asn1Integer,
	pub statusString :Asn1Opt<Asn1Seq<Asn1String>>,
	pub failInfo :Asn1Opt<Asn1BitDataFlag>,
}

impl PKIStatusInfoElem {
	pub fn get_status(&self) -> Result<i32, Box<dyn Error>> {
		Ok(self.status.val as i32)
	}

	pub fn set_status(&mut self, val :i64) -> Result<i64, Box<dyn Error>> {
		let retv :i64;
		retv = self.status.val;
		self.status.val = val;
		Ok(retv)
	}

	pub fn set_status_string(&mut self, val :&str) -> Result<Option<String>,Box<dyn Error>> {
		let mut retv :Option<String> = None;
		if self.statusString.val.is_some() {
			let elm :&Asn1Seq<Asn1String> = self.statusString.val.as_ref().unwrap();
			if elm.val.len() > 0 {
				retv = Some(format!("{}",elm.val[0].val));
			}
		}
		if val.len() > 0 {
			let mut selm :Asn1Seq<Asn1String> = Asn1Seq::init_asn1();
			let mut s :Asn1String = Asn1String::init_asn1();
			s.val = format!("{}",val);
			selm.val.push(s);
			self.statusString.val = Some(selm);			
		} else {
			self.statusString.val = None;
		}
		Ok(retv)
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct PKIStatusInfo {
	pub elem :Asn1Seq<PKIStatusInfoElem>,
}

impl PKIStatusInfo {
	pub fn get_status(&self) -> Result<i32, Box<dyn Error>> {
		let _ = self.elem.check_safe_one("PKIStatusInfoElem")?;
		return self.elem.val[0].get_status();
	}

	pub fn set_status(&mut self, val :i64) -> Result<i64, Box<dyn Error>> {
		let _ = self.elem.make_safe_one("PKIStatusInfoElem")?;
		return self.elem.val[0].set_status(val);
	}

	pub fn set_status_string(&mut self, val :&str) -> Result<Option<String>,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("PKIStatusInfoElem")?;
		return self.elem.val[0].set_status_string(val);
	}

}



#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampRespElem {
	pub status :PKIStatusInfo,
	pub token :Asn1Opt<Asn1Pkcs7>,
}

impl TimeStampRespElem {
	pub fn get_status(&self) -> Result<i32, Box<dyn Error>> {
		return self.status.get_status();
	}

	pub fn get_token_code(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.token.val.is_none() {
			ssllib_new_error!{SslTsError,"no token"}
		}
		let refv :&Asn1Pkcs7 = self.token.val.as_ref().unwrap();
		return refv.encode_asn1();
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct TimeStampResp {
	pub elem :Asn1Seq<TimeStampRespElem>,
}

impl TimeStampResp {
	pub fn get_status(&self) -> Result<i32,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("TimeStampRespElem")?;
		return self.elem.val[0].get_status();
	}

	pub fn get_token_code(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("TimeStampRespElem")?;
		return self.elem.val[0].get_token_code();		
	}
}
