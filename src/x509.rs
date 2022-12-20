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
#[allow(unused_imports)]
use crate::{ssllib_buffer_trace,ssllib_format_buffer_log,ssllib_log_trace};
use crate::rsa::*;
use crate::consts::*;
use crate::digest::*;
use crate::impls::*;
use crate::randop::*;
use crate::encde::*;
#[allow(unused_imports)]
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};
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

	pub fn get_keyfunc_algo(&self) -> Result<String,Box<dyn Error>> {
		return self.keyfunc.get_algorithm();
	}

	pub fn set_encrypt(&mut self, encobj :&str) -> Result<String,Box<dyn Error>> {
		return self.encryption.set_algorithm(encobj);
	}

	pub fn get_encrypt_algo(&self) -> Result<String,Box<dyn Error>> {
		return self.encryption.get_algorithm();
	}

	pub fn get_encrypt_params(&self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		return self.encryption.get_param();
	}

	pub fn set_cmd(&mut self, env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut retv :ConfigValue = ConfigValue::new("{}")?;
		let cv = env.get_str(KEY_JSON_TYPE)?;
		if cv == KEY_JSON_PBKDF2 {
			let _ = self.keyfunc.set_algorithm(OID_PBKDF2)?;
			let enctype = env.get_str(KEY_JSON_ENCTYPE)?;
			if enctype == KEY_JSON_AES256CBC {
				let decdata = env.get_u8_array(KEY_JSON_DECDATA)?;
				let ores = env.get_str(KEY_JSON_RANDFILE);
				let mut randfile :Option<String> = None;
				if ores.is_ok() {
					randfile = Some(format!("{}",ores.unwrap()));
					ssllib_log_trace!("set randfile {:?}",randfile);
				}
				let mut randc :RandOps = RandOps::new(randfile)?;
				let ivkey = randc.get_bytes(8 as usize)?;
				let aeskey = randc.get_bytes(32 as usize )?;
				let aes256ccb :Aes256Algo = Aes256Algo::new(&ivkey,&aeskey)?;
				let encdata = aes256ccb.encrypt(&decdata)?;
				let mut anyv :Asn1Any = Asn1Any::init_asn1();
				anyv.content = ivkey.clone();
				ssllib_buffer_trace!(anyv.content.as_ptr(),anyv.content.len(),"ivkey set");
				let _ = self.encryption.set_param(Some(anyv.clone()))?;
				let _ = retv.set_u8_array(KEY_JSON_ENCDATA,&encdata)?;
				let _ = retv.set_u8_array(KEY_JSON_KEY,&aeskey)?;

			} else {
				ssllib_new_error!{SslX509Error,"not support [{}][{}]",KEY_JSON_ENCTYPE,enctype}
			}
		} else {
			ssllib_new_error!{SslX509Error,"not support type [{}]",cv}
		}

		Ok(retv)
	}

	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut config :ConfigValue = ConfigValue::new("{}")?;
		let algr = self.keyfunc.get_algorithm()?;
		if algr == OID_PBKDF2 {
			let _ = config.set_str(KEY_JSON_TYPE,KEY_JSON_PBKDF2)?;
			let pres = self.keyfunc.get_param()?;
			if pres.is_none() {
				ssllib_new_error!{SslX509Error,"no encryption get"}
			}
			let decdata = pres.unwrap().content.clone();
			let mut pbkdf2 :Asn1Pbkdf2ParamElem = Asn1Pbkdf2ParamElem::init_asn1();
			let _ = pbkdf2.decode_asn1(&decdata)?;
			let ncfg = pbkdf2.get_cmd(env)?;
			let ktype = self.encryption.get_algorithm()?;
			if ktype == OID_AES_256_CBC {
				/*now we should give the */
				let _ = config.set_str(KEY_JSON_ENCTYPE,KEY_JSON_AES256CBC)?;
				let params = self.encryption.get_param()?;
				if params.is_some() {
					let anyv :&Asn1Any = params.as_ref().unwrap();
					let encdata = env.get_u8_array(KEY_JSON_ENCDATA)?;
					let ivkey = anyv.content.clone();
					let aeskey = ncfg.get_u8_array(KEY_JSON_KEY)?;
					let aescbcenc = Aes256Algo::new(&ivkey,&aeskey)?;
					let decdata = aescbcenc.decrypt(&encdata)?;
					let _ = config.set_u8_array(KEY_JSON_DECDATA,&decdata)?;
				} else {
					ssllib_new_error!{SslX509Error,"not set params value for encryption"}
				}
			} else {
				ssllib_new_error!{SslX509Error,"not valid encrypt [{}]", ktype}
			}
			let _ = config.set_config(KEY_JSON_PBKDF2,&ncfg)?;
		} else {
			ssllib_new_error!{SslX509Error,"not support algr [{}]", algr}
		}
		Ok(config)
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
	pub fn set_enc_type(&mut self,config :&ConfigValue) -> Result<(),Box<dyn Error>> {		
		let types = config.get_str(KEY_JSON_TYPE)?;		
		if types == KEY_HMAC_WITH_SHA256  {
			let v8 :Vec<u8> = config.get_u8_array(KEY_JSON_SALT)?;
			self.salt.content = v8.clone();
			self.salt.tag = ASN1_OCT_STRING_FLAG as u64;
			self.iter.set_value(config.get_i64(KEY_JSON_TIMES)?);
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

	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut config :ConfigValue = ConfigValue::new("{}").unwrap();
		if self.prf.val.is_none() {
			ssllib_new_error!{SslX509Error,"no prf setted"}
		}
		let algr :&Asn1X509Algor = self.prf.val.as_ref().unwrap();
		let ktype :String = algr.get_algorithm()?;
		if ktype == OID_HMAC_WITH_SHA256 {
			let passin :String = env.get_str(KEY_JSON_PASSIN)?;
			let hsha256 :HmacSha256Digest = HmacSha256Digest::new(self.iter.val as u32,passin.as_bytes())?;
			let retv = hsha256.digest(&(self.salt.content))?;
			let _ = config.set_u8_array(KEY_JSON_KEY,&retv)?;
		} else {
			ssllib_new_error!{SslX509Error,"not support algorithm [{}]", ktype}
		}
		Ok(config)
	}
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pbkdf2Param {
	pub elem : Asn1Seq<Asn1Pbkdf2ParamElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1NetscapePkeyElem {
	pub version :Asn1Integer,
	pub algor : Asn1X509Algor,
	pub privdata :Asn1OctData,
}

impl Asn1NetscapePkeyElem {
	pub fn set_privdata(&mut self,data :&[u8]) -> Result<(),Box<dyn Error>> {
		self.privdata.data = data.to_vec().clone();
		Ok(())
	}

	pub fn set_algorithm(&mut self,env :&ConfigValue) -> Result<(),Box<dyn Error>> {
		let cs = env.get_str(KEY_JSON_TYPE)?;
		if cs == KEY_JSON_RSA {
			let _ = self.algor.set_param_null()?;
			let _= self.algor.set_algorithm(OID_RSA_ENCRYPTION)?;
		} else {
			ssllib_new_error!{SslX509Error,"[{}] [{}]",KEY_JSON_TYPE,cs}
		}
		Ok(())
	}

	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		return self.algor.get_algorithm();
	}

	pub fn get_privdata(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		Ok(self.privdata.data.clone())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1NetscapePkey {
	pub elem : Asn1Seq<Asn1NetscapePkeyElem>,
}

impl Asn1NetscapePkey {
	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].get_algorithm();
	}
	pub fn get_privdata(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].get_privdata();
	}

	pub fn set_algorithm(&mut self, env :&ConfigValue) -> Result<(),Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].set_algorithm(env);
	}
	pub fn set_privdata(&mut self,data :&[u8]) -> Result<(),Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].set_privdata(data);
	}

}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509SigElem {
	pub algor : Asn1X509Algor,
	pub digest : Asn1OctData,
}

#[allow(unused_variables,unused_mut)]
impl Asn1X509SigElem {
	pub fn set_cmd(&mut self, env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let cs = env.get_str(KEY_JSON_TYPE)?;
		let retv :ConfigValue = ConfigValue::new("{}")?;
		if cs == KEY_JSON_PBES2 {
			let mut cfg = env.get_config_must(KEY_JSON_PBES2)?;
			let mut pbes2 :Asn1Pbe2ParamElem = Asn1Pbe2ParamElem::init_asn1();
			let ncfg = pbes2.set_cmd(&cfg)?;
			let _ = self.algor.set_algorithm(OID_PBES2)?;
			let mut anyv :Asn1Any = Asn1Any::init_asn1();
			anyv.content = pbes2.encode_asn1()?;
			ssllib_buffer_trace!(anyv.content.as_ptr(),anyv.content.len()," pbes2 encode");
			self.digest.data = anyv.encode_asn1()?;
			
		} else {
			ssllib_new_error!{SslX509Error, "not support type [{}]", cs}
		}
		Ok(retv)
	}

	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut config :ConfigValue = ConfigValue::new("{}")?;
		let cv :String = self.algor.get_algorithm()?;
		let mut nenv :ConfigValue = env.clone();
		if cv == OID_PBES2 {
			let encdata = self.digest.data.clone();
			let mut  pbes2 :Asn1Pbe2ParamElem = Asn1Pbe2ParamElem::init_asn1();
			let ores = self.algor.get_param()?;
			if ores.is_none() {
				ssllib_new_error!{SslX509Error,"no params set"}
			}
			let anyv :Asn1Any = ores.unwrap();
			let decdata = anyv.content.clone();
			let _ = pbes2.decode_asn1(&decdata)?;
			let _ = nenv.set_u8_array(KEY_JSON_ENCDATA,&self.digest.data)?;
			let cfg = pbes2.get_cmd(&nenv)?;
			let _ = config.set_str(KEY_JSON_TYPE,KEY_JSON_PBES2)?;
			let _ = config.set_config(KEY_JSON_PBES2,&cfg)?;
		} else {
			ssllib_new_error!{SslX509Error,"[{}] packet not support", cv}
		}
		Ok(config)
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Sig {
	pub elem : Asn1Seq<Asn1X509SigElem>,
}

impl Asn1X509Sig {
	pub fn set_cmd(&mut self, config :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Sig")?;
		return self.elem.val[0].set_cmd(config);
	}

	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Sig")?;
		return self.elem.val[0].get_cmd(env);
	}
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
