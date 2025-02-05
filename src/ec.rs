#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
use asn1obj::complex::*;
#[allow(unused_imports)]
use asn1obj::*;

use crate::{ssllib_new_error,ssllib_error_class};
use std::error::Error;
use std::io::{Write};
use ecsimple::keys::{ECPrivateKey,ECPublicKey};
use ecsimple::signature::{ECSignature};
use crate::impls::{Asn1SignOp,Asn1VerifyOp};


ssllib_error_class!{SslEcError}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIALELem {
	pub k1 :Asn1Integer,
	pub k2 :Asn1Integer,
	pub k3 :Asn1Integer,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIAL {
	pub elem :Asn1Seq<X9_62_PENTANOMIALELem>,
}

#[derive(Clone)]
#[asn1_obj_selector(other=default,onBasis="1.2.840.10045.1.2.3.1",tpBasis="1.2.840.10045.1.2.3.2",ppBasis="1.2.840.10045.1.2.3.3")]
pub struct X962Selector  {
	pub val :Asn1Object,
}

#[derive(Clone)]
#[asn1_choice(selector=otype)]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM_CHOICE {
	pub otype : X962Selector,
	pub onBasis : Asn1Null,
	pub tpBasis : Asn1BigNum,
	pub ppBasis : X9_62_PENTANOMIAL,
	pub other :Asn1Any,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM {
	pub m :Asn1Integer,
	pub elemchoice : X9_62_CHARACTERISTIC_TWO_ELEM_CHOICE,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CHARACTERISTIC_TWO {
	pub elem :Asn1Seq<X9_62_CHARACTERISTIC_TWO_ELEM>,
}


#[derive(Clone)]
#[asn1_obj_selector(prime="1.2.840.10045.1.1",char_two="1.2.840.10045.1.2")]
pub struct X964FieldSelector {
	pub val :Asn1Object,
}

#[derive(Clone)]
#[asn1_choice(selector=fieldType)]
pub struct X9_62_FIELDIDElem {
	pub fieldType :X964FieldSelector,
	pub prime : Asn1BigNum,
	pub char_two :X9_62_CHARACTERISTIC_TWO,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_FIELDID {
	pub elem :Asn1Seq<X9_62_FIELDIDElem>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CURVEElem {
	pub a :Asn1OctData,
	pub b :Asn1OctData,
	pub seed :Asn1Opt<Asn1BitDataFlag>,
}


#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CURVE {
	pub elem :Asn1Seq<X9_62_CURVEElem>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPARAMETERSElem {
	pub version : Asn1Integer,
	pub fieldID : X9_62_FIELDID,
	pub curve :X9_62_CURVE,
	pub base :Asn1OctData,
	pub order :Asn1BigNum,
	pub cofactor : Asn1Opt<Asn1BigNum>,

}

#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPARAMETERS {
	pub elem :Asn1Seq<ECPARAMETERSElem>,
}

#[asn1_int_choice(debug=0,selector=itype,named_curve=0,parameters=1,implicitCA=2)]
#[derive(Clone)]
pub struct ECPKPARAMETERS {
	pub itype :i32,
	pub named_curve :Asn1Object,
	pub parameters : ECPARAMETERS,
	pub implicitCA : Asn1Null,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPublicKeyPackElem {
	pub typef :Asn1Object,
	pub parameters :ECPKPARAMETERS,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPublicKeyPack {
	pub elem :Asn1Seq<ECPublicKeyPackElem>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPublicKeyAsn1Elem {
	pub packed :ECPublicKeyPack,
	pub pubdata :Asn1BitDataFlag,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPublicKeyAsn1 {
	pub elem :Asn1Seq<ECPublicKeyAsn1Elem>,
}




#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPrivateKeyAsn1Elem {
	pub version :Asn1Integer,
	pub privatekey :Asn1OctData,
	pub parameters :Asn1Opt<Asn1ImpSet<ECPKPARAMETERS,0>>,
	pub publickey : Asn1Opt<Asn1ImpSet<Asn1BitDataFlag,1>>,
}

impl ECPrivateKeyAsn1Elem {
	pub fn set_private_key(&mut self,key :&[u8]) -> Vec<u8> {
		let retk = self.privatekey.data.clone();
		self.privatekey.data = key.to_vec().clone();
		retk
	}

	pub fn get_private_key(&self) -> Vec<u8> {
		return self.privatekey.data.clone();
	}

	pub fn set_public_key(&mut self,key :&[u8]) -> Option<Vec<u8>> {
		let mut setkey :Asn1ImpSet<Asn1BitDataFlag,1> = Asn1ImpSet::init_asn1();
		let mut retv :Option<Vec<u8>> = None;
		setkey.val = Vec::new();
		let mut v :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
		v.data = key.to_vec().clone();
		setkey.val.push(v);
		if self.publickey.val.is_some() {
			let retimp = self.publickey.val.as_ref().unwrap().clone();
			retv = Some(retimp.val[0].data.clone());
		} 
		self.publickey.val = Some(setkey);
		return retv;
	}

	pub fn get_public_key(&self) -> Option<Vec<u8>> {
		if self.publickey.val.is_none() {
			return None;
		}
		let retimp = self.publickey.val.as_ref().unwrap().clone();
		let retk = Some(retimp.val[0].data.clone());
		retk
	}	

	pub fn set_ec_type_oid(&mut self,oid :&str) -> Result<(),Box<dyn Error>> {
		let mut nobj :Asn1Object = Asn1Object::init_asn1();
		let _ = nobj.set_value(oid)?;
		let mut nopt :Asn1Opt<Asn1ImpSet<ECPKPARAMETERS,0>> = Asn1Opt::init_asn1();
		let mut impset :Asn1ImpSet<ECPKPARAMETERS,0> = Asn1ImpSet::init_asn1();
		let mut params :ECPKPARAMETERS = ECPKPARAMETERS::init_asn1();
		/*it is for named_curve*/
		params.itype = 0;
		params.named_curve = nobj.clone();
		impset.val.push(params);
		nopt.val = Some(impset);
		self.parameters = nopt;
		Ok(())

	}
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPrivateKeyAsn1 {
	pub elem :Asn1Seq<ECPrivateKeyAsn1Elem>,
}

impl ECPrivateKeyAsn1 {
	pub fn set_ec_type_oid(&mut self, oid :&str) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() != 0 && self.elem.val.len()!=1 {
			ssllib_new_error!{SslEcError,"val [{}] != 0 or 1",self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			self.elem = Asn1Seq::init_asn1();
			self.elem.val.push(ECPrivateKeyAsn1Elem::init_asn1());
		}
		return self.elem.val[0].set_ec_type_oid(oid);
	}

	pub fn set_private_key(&mut self,key :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.elem.val.len() != 0 && self.elem.val.len()!=1 {
			ssllib_new_error!{SslEcError,"val [{}] != 0 or 1",self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			self.elem = Asn1Seq::init_asn1();
			self.elem.val.push(ECPrivateKeyAsn1Elem::init_asn1());
		}
		let retk = self.elem.val[0].set_private_key(key);
		Ok(retk)
	}

	pub fn get_private_key(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.elem.val.len() != 0 && self.elem.val.len()!=1 {
			ssllib_new_error!{SslEcError,"val [{}] != 0 or 1",self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			let retk :Vec<u8>= Vec::new();
			return Ok(retk);
		}
		let retk = self.elem.val[0].get_private_key();
		Ok(retk)
	}

	pub fn set_public_key(&mut self,key :&[u8]) -> Result<Option<Vec<u8>>,Box<dyn Error>> {
		if self.elem.val.len() != 0 && self.elem.val.len()!=1 {
			ssllib_new_error!{SslEcError,"val [{}] != 0 or 1",self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			self.elem = Asn1Seq::init_asn1();
			self.elem.val.push(ECPrivateKeyAsn1Elem::init_asn1());
		}
		let retk = self.elem.val[0].set_public_key(key);
		Ok(retk)
	}

	pub fn get_public_key(&self) -> Result<Option<Vec<u8>>,Box<dyn Error>> {
		if self.elem.val.len() != 0 && self.elem.val.len()!=1 {
			ssllib_new_error!{SslEcError,"val [{}] != 0 or 1",self.elem.val.len()}
		}
		if self.elem.val.len() == 0 {
			return Ok(None);
		}
		let retk = self.elem.val[0].get_public_key();
		Ok(retk)
	}
}

pub struct ECSign {
	key :Vec<ECPrivateKey>,
	inited :bool,
}


impl ECSign {
	pub fn new() -> Self {
		Self {
			key :vec![],
			inited : false,
		}
	}
}

impl Asn1SignOp for ECSign {
	fn sign_init(&mut self,key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
		let privkey :ECPrivateKey = ECPrivateKey::from_der(key)?;
		if self.key.len() > 0 {
			self.key[0] = privkey;
		} else {
			self.key.push(privkey);
		}
		self.inited = true;
		Ok(())
	}
	fn sign_exec(&mut self,data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslEcError,"not inited"}
		}
		let sig = self.key[0].sign_base(data)?;
		let code = sig.encode_asn1()?;
		Ok(code)
	}
}

pub struct ECVerify {
	key :Vec<ECPublicKey>,
	inited :bool,
}

impl ECVerify {
	pub fn new() -> Self {
		Self {
			key :vec![],
			inited : false,
		}
	}
}

impl Asn1VerifyOp for ECVerify {
	fn verify_init(&mut self,key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
		let pubkey :ECPublicKey = ECPublicKey::from_der(key)?;
		if self.key.len() > 0 {
			self.key[0] = pubkey;
		} else {
			self.key.push(pubkey);
		}
		self.inited = true;
		Ok(())
	}
	fn verify_exec(&mut self, origdata :&[u8], signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslEcError,"not inited"}
		}
		let sig :ECSignature = ECSignature::decode_asn1(signdata)?;
		let retv = self.key[0].verify_base(&sig,origdata)?;
		Ok(retv)
	}
}
