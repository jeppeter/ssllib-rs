#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use asn1obj::*;
use asn1obj::consts::*;

use std::error::Error;
use std::io::{Write};

use crate::{ssllib_new_error,ssllib_error_class};
//use crate::{ssllib_log_error};
use crate::rsa::*;
use crate::consts::*;
use crate::digest::*;
use crate::impls::*;
//use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};
use crate::config::ConfigValue;


ssllib_error_class!{SslX509Error}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509NameElement {
	pub obj : Asn1Object,
	pub name :Asn1PrintableString,
}

impl Asn1X509NameElement {
	pub fn format_name(&self) -> String {
		let rets :String;
		rets = format!("{}:{}",self.obj.get_value(),self.name.val);
		return rets;
	}
}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509NameEntry {
	pub names : Asn1Set<Asn1Seq<Asn1X509NameElement>>,
}


impl Asn1X509NameEntry {
	pub fn get_names(&self) -> Vec<String>{
		let mut retn :Vec<String> = Vec::new();
		for v in self.names.val.iter() {
			for bv in v.val.iter() {
				retn.push(bv.format_name());
			}
		}
		return retn;
	}
}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Name {
	pub entries : Asn1Seq<Asn1X509NameEntry>,
}

impl  PartialEq for Asn1X509Name {

	fn ne(&self,other :&Self) -> bool {
		let snames :Vec<String>;
		let onames :Vec<String>;
		let mut bmatched :bool;

		if self.entries.val.len() == 0 && other.entries.val.len() == 0 {
			return false;
		} else if self.entries.val.len() == 0 {
			return true;
		} else if other.entries.val.len() == 0 {
			return true;
		} else {
			snames = self.entries.val[0].get_names();
			onames = other.entries.val[0].get_names();
			if snames.len() == 0 && onames.len() == 0 {
				return false;
			} else if snames.len() == 0 {
				return true;
			} else if onames.len() == 0 {
				return true;
			}
			for i in 0..snames.len() {
				bmatched = false;
				for j in 0..onames.len() {
					if snames[i].eq(&(onames[j])) {
						bmatched = true;
						break;
					}
				}

				if !bmatched {
					return true;
				}
			}

			for j in 0..onames.len() {
				bmatched = false;
				for i in 0..snames.len() {
					if onames[j].eq(&snames[i]) {
						bmatched = true;
						break;
					}
				}
				if !bmatched {
					return true;
				}
			}
		}
		return false;
	}

	fn eq(&self, other :&Self) -> bool {
		if self.ne(other) {
			return false;
		}
		return true;
	}

}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AttributeElem {
	pub object :Asn1Object,
	pub set :Asn1Any,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Attribute {
	pub elem : Asn1Seq<Asn1X509AttributeElem>,
}

impl Asn1X509Attribute {
	pub fn set_value_with_object(&mut self,objval :&Asn1Object,setval :&Asn1Any) -> Result<bool,Box<dyn Error>> {
		let mut retv :bool = false;
		if self.elem.val.len() != 0 && self.elem.val.len()!=1 {
			ssllib_new_error!{SslX509Error,"val [{}] != 0 or 1",self.elem.val.len()}
		}
		if self.elem.val.len() != 0 {
			if self.elem.val[0].object.eq(objval) {
				self.elem.val[0].set = setval.clone();
				retv= true;
			}
		}
		Ok(retv)
	}
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ValElem {
	pub notBefore : Asn1Time,
	pub notAfter : Asn1Time,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Val {
	pub elem : Asn1Seq<Asn1X509ValElem>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AlgorElem {
	pub algorithm : Asn1Object,
	pub parameters : Asn1Opt<Asn1Any>,
}

impl Asn1X509AlgorElem {
	pub fn set_algorithm(&mut self, objname :&str) -> Result<String,Box<dyn Error>> {
		let oval = self.algorithm.set_value(objname)?;
		Ok(oval)
	}

	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		let oval = self.algorithm.get_value();
		Ok(oval)
	}

	pub fn get_param(&self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let mut retv :Option<Asn1Any> = None;
		if self.parameters.val.is_some() {
			retv = Some(self.parameters.val.as_ref().unwrap().clone());
		}
		return Ok(retv)
	}


	pub fn set_param_null(&mut self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let retv = self.get_param()?;
		let mut anyv :Asn1Any = Asn1Any::init_asn1();
		anyv.tag = ASN1_NULL_FLAG as u64;
		self.parameters.val = Some(anyv.clone());
		Ok(retv)
	}


	pub fn set_param(&mut self, val :Option<Asn1Any>) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let retv = self.get_param()?;
		if val.is_none() {
			self.parameters.val = None;
		} else {
			self.parameters.val = Some(val.as_ref().unwrap().clone());
		}		
		Ok(retv)
	}
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Algor {
	pub elem : Asn1Seq<Asn1X509AlgorElem>,
}

impl Asn1X509Algor {
	pub fn set_algorithm(&mut self,objname :&str) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].set_algorithm(objname);
	}

	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].get_algorithm();
	}

	pub fn get_param(&self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].get_param();
	}


	pub fn set_param_null(&mut self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].set_param_null();
	}

	pub fn set_param(&mut self, val :Option<Asn1Any>) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].set_param(val);
	}

}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ExtensionElem {
	pub object :Asn1Object,
	pub critical : Asn1Opt<Asn1Boolean>,
	pub value : Asn1OctData,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Extension {
	pub elem :Asn1Seq<Asn1X509ExtensionElem>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509CinfElem {
	pub version : Asn1Opt<Asn1ImpSet<Asn1Integer,0>>,
	pub serial_number :Asn1BigNum,
	pub signature : Asn1X509Algor,
	pub issuer : Asn1X509Name,
	pub validity : Asn1X509Val,
	pub subject :Asn1X509Name,
	pub key : Asn1X509Pubkey,
	pub issuerUID : Asn1Opt<Asn1Imp<Asn1BitString,1>>,
	pub subjectUID : Asn1Opt<Asn1Imp<Asn1BitString,2>>,
	pub extensions : Asn1Opt<Asn1ImpSet<Asn1Seq<Asn1X509Extension>,3>>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Cinf {
	pub elem : Asn1Seq<Asn1X509CinfElem>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Revoked {
	pub serialNumber : Asn1Integer,
	pub revocationDate : Asn1Time,
	pub extensions : Asn1Opt<Asn1Seq<Asn1X509Extension>>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509CrlInfo {
	pub version : Asn1Opt<Asn1Integer>,
	pub sig_alg : Asn1X509Algor,
	pub issuer : Asn1X509Name,
	pub lastUpdate : Asn1Time,
	pub nextUpdate :Asn1Time,
	pub revoked : Asn1Opt<Asn1Seq<Asn1X509Revoked>>,
	pub extensions : Asn1Opt<Asn1Seq<Asn1X509Extension>>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Crl {
	pub crl : Asn1X509CrlInfo,
	pub sig_alg :Asn1X509Algor,
	pub signature : Asn1BitString,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Elem {
	pub certinfo : Asn1X509Cinf,
	pub sig_alg : Asn1X509Algor,
	pub signature : Asn1BitData,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509 {
	pub elem : Asn1Seq<Asn1X509Elem>,
}

impl Asn1X509 {
	pub fn is_self_signed(&self) -> bool {
		self.elem.sure_safe_one("Asn1X509").unwrap();
		let certinfo :&Asn1X509Cinf = &self.elem.val[0].certinfo;
		certinfo.elem.sure_safe_one("Asn1X509 certinfo").unwrap();
		if certinfo.elem.val[0].issuer.eq(&certinfo.elem.val[0].subject) {
			return true;
		}

		return false;
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pbe2ParamElem {
	pub keyfunc : Asn1X509Algor,
	pub encryption : Asn1X509Algor,
}

impl Asn1Pbe2ParamElem {
	pub fn set_keyfunc(&mut self, func :&str) -> Result<String,Box<dyn Error>> {
		return self.keyfunc.set_algorithm(func);
	}

	pub fn set_keyfunc_params(&mut self, params :Option<Asn1Any>) -> Result<Option<Asn1Any>, Box<dyn Error>> {
		return self.keyfunc.set_param(params);
	}

	pub fn get_keyfunc_params(&self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		return self.keyfunc.get_param();
	}

	pub fn set_encrypt(&mut self, encobj :&str) -> Result<String,Box<dyn Error>> {
		return self.encryption.set_algorithm(encobj);
	}


}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pbe2Param {
	pub elem : Asn1Seq<Asn1Pbe2ParamElem>,
}
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pbkdf2ParamElem {
	pub salt : Asn1Any,
	pub iter : Asn1Integer,
	pub keylength :Asn1Opt<Asn1Integer>,
	pub prf : Asn1Opt<Asn1X509Algor>,
}

impl Asn1Pbkdf2ParamElem {
	pub fn get_enc_key(&self,params :&ConfigValue) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv :Vec<u8> ;
		/*now to get */
		if self.prf.val.is_none() {
			ssllib_new_error!{SslX509Error,"no prf setted"}
		}
		let algr :&Asn1X509Algor = self.prf.val.as_ref().unwrap();
		let _ = algr.elem.sure_safe_one("Asn1Pbkdf2ParamElem prf")?;
		let ktype :String = algr.elem.val[0].algorithm.get_value();
		if ktype == OID_HMAC_WITH_SHA256 {
			let passin :Vec<u8> = params.get_array_u8_must(KEY_JSON_PASSIN)?;
			let hsha256 :HmacSha256Digest = HmacSha256Digest::new(self.iter.val as u32,&passin)?;
			retv = hsha256.digest(&(self.salt.content))?;
		} else {
			ssllib_new_error!{SslX509Error,"not support algorithm [{}]", ktype}
		}
		Ok(retv)
	}

	pub fn set_enc_type(&mut self,config :&ConfigValue) -> Result<(),Box<dyn Error>> {		
		let types = config.get_string_must(KEY_JSON_TYPE)?;		
		if types == KEY_HMAC_WITH_SHA256  {
			let v8 :Vec<u8> = config.get_array_u8_must(KEY_JSON_SALT)?;
			self.salt.content = v8.clone();
			self.salt.tag = ASN1_OCT_STRING_FLAG as u64;
			self.iter.set_value(config.get_i64_must(KEY_JSON_TIMES)?);
			self.keylength = Asn1Opt::init_asn1();
			let mut  aglr = Asn1X509Algor::init_asn1();
			let mut algrelm = Asn1X509AlgorElem::init_asn1();
			let _ = algrelm.algorithm.set_value(OID_HMAC_WITH_SHA256)?;
			let mut atype :Asn1Any = Asn1Any::init_asn1();
			atype.tag = ASN1_NULL_FLAG as u64;
			algrelm.parameters = Asn1Opt::init_asn1();
			algrelm.parameters.val = Some(atype.clone());
			aglr.elem.val.push(algrelm);
			self.prf = Asn1Opt::init_asn1();
			self.prf.val = Some(aglr.clone());
		} else {
			ssllib_new_error!{SslX509Error,"not support type [{}]", types}
		}

		Ok(())
	}
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pbkdf2Param {
	pub elem : Asn1Seq<Asn1Pbkdf2ParamElem>,
}

impl Asn1Pbkdf2Param {
	pub fn get_enc_key(&self,params :&ConfigValue) -> Result<Vec<u8>,Box<dyn Error>> {
		let _ = self.elem.sure_safe_one("Asn1Pbkdf2Param")?;
		return self.elem.val[0].get_enc_key(params);
	}

	pub fn set_enc_type(&mut self,params :&ConfigValue) -> Result<(),Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1Pbkdf2Param")?;
		return self.elem.val[0].set_enc_type(params);
	}
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1NetscapePkeyElem {
	pub version :Asn1Integer,
	pub algor : Asn1X509Algor,
	pub privdata :Asn1OctData,
}

impl Asn1NetscapePkeyElem {
	pub fn set_encrypt_keys(&mut self,config :&ConfigValue) -> Result<(),Box<dyn Error>> {
		let types = config.get_string_must(KEY_JSON_TYPE)?;
		if types == KEY_JSON_RSA {
			self.version.set_value(0);
			let _ = self.algor.set_algorithm(OID_RSA_ENCRYPTION)?;
			let _ = self.algor.set_param_null()?;
			self.privdata.data = config.get_array_u8_must(KEY_JSON_DATA)?;
		} else {
			ssllib_new_error!{SslX509Error,"not support type [{}]", types}
		}

		Ok(())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1NetscapePkey {
	pub elem : Asn1Seq<Asn1NetscapePkeyElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509SigElem {
	pub algor : Asn1X509Algor,
	pub digest : Asn1OctData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Sig {
	pub elem : Asn1Seq<Asn1X509SigElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ReqInfoElem {
	pub version : Asn1Integer,
	pub subject : Asn1X509Name,
	pub pubkey : Asn1X509Pubkey,
	pub attributes : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,0>>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ReqInfo {
	pub elem : Asn1Seq<Asn1X509ReqInfoElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ReqElem {
	pub req_info : Asn1X509ReqInfo,
	pub sig_alg : Asn1X509Algor,
	pub signature : Asn1BitData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Req {
	pub elem : Asn1Seq<Asn1X509ReqElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkeyFormElem {
	pub algor : Asn1X509Algor,
	pub data  : Asn1BitData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkeyForm {
	pub elem :Asn1Seq<Asn1RsaPubkeyFormElem>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct Asn1OtherNameElem {
	pub typeid :Asn1Object,
	pub value :Asn1Ndef<Asn1Any,0>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct Asn1OtherName {
	pub elem :Asn1Seq<Asn1OtherNameElem>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct Asn1EdiPartyNameElem {
	pub nameassigner :Asn1Opt<Asn1Ndef<Asn1PrintableString,0>>,
	pub partyname :Asn1Ndef<Asn1PrintableString,1>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct Asn1EdiPartyName {
	pub elem :Asn1Seq<Asn1EdiPartyNameElem>,
}

#[asn1_int_choice(debug=0,selector=stype,othername=0,rfc822name=1,dnsname=2,directoryname=4,uri=6,ipaddress=7,registerid=8)]
#[derive(Clone)]
pub struct Asn1GeneralName {
	pub stype :i32,
	pub othername : Asn1Imp<Asn1OtherName,0>,
	pub rfc822name :Asn1Imp<Asn1IA5String,1>,
	pub dnsname :Asn1Imp<Asn1IA5String,2>,
	pub directoryname : Asn1Imp<Asn1Seq<Asn1X509Name>,4>,
	pub uri : Asn1Imp<Asn1IA5String,6>,
	pub ipaddress :Asn1Imp<Asn1IA5String,7>,
	pub registerid :Asn1Imp<Asn1Object,8>,
}
