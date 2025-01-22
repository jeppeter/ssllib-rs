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

#[asn1_int_choice(selector=itype,unicode=0,ascii=1)]
#[derive(Clone)]
pub struct SpcStringElem {
	pub itype :i32,
	pub unicode :Asn1Imp<Asn1BMPString,0>,
	pub ascii :Asn1Imp<Asn1IA5String,1>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcString {
	pub elem :Asn1Seq<SpcStringElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcAttributeTypeAndOptionalValueElem {
	pub itype :Asn1Object,
	pub value :Asn1Opt<Asn1Any>,
}

impl SpcAttributeTypeAndOptionalValueElem {
	pub fn set_value(&mut self, oid :&str,oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		self.itype.set_value(oid)?;
		if oany.is_none() {
			self.value.val = None;
		} else {
			self.value.val = Some(oany.as_ref().unwrap().clone());
		}
		Ok(())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcAttributeTypeAndOptionalValue {
	pub elem :Asn1Seq<SpcAttributeTypeAndOptionalValueElem>,
}



impl SpcAttributeTypeAndOptionalValue {
	fn _make_sure_elem(&mut self) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			self.elem.val.push(SpcAttributeTypeAndOptionalValueElem::init_asn1());
		}
		Ok(())		
	}
	pub fn set_value(&mut self, oid :&str,oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		self._make_sure_elem()?;
		return self.elem.val[0].set_value(oid,oany);
	}
}


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
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct DigestInfoElem {
	pub digestAlgorithm :AlgorithmIdentifier,
	pub digest : Asn1OctData,
}

impl DigestInfoElem {
	pub fn set_algo(&mut self,oid:&str,oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		return self.digestAlgorithm.set_value(oid,oany);
	}

	pub fn set_digest(&mut self,data :&[u8]) -> Result<(),Box<dyn Error>> {
		self.digest.data = data.to_vec().clone();
		Ok(())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct DigestInfo {
	pub elem :Asn1Seq<DigestInfoElem>,
}

impl DigestInfo {
	fn _make_sure_elem(&mut self) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			self.elem.val.push(DigestInfoElem::init_asn1());
		}
		Ok(())		
	}
	pub fn set_algo(&mut self, oid :&str, oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		self._make_sure_elem()?;
		return self.elem.val[0].set_algo(oid,oany);
	}	
	pub fn set_digest(&mut self, data :&[u8]) -> Result<(),Box<dyn Error>> {
		self._make_sure_elem()?;
		return self.elem.val[0].set_digest(data);
	}	
}



#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcIndirectDataContentElem {
	pub data :SpcAttributeTypeAndOptionalValue,
	pub messageDigest :DigestInfo,
}

impl SpcIndirectDataContentElem {
	pub fn set_data(&mut self,oid :&str,oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		return self.data.set_value(oid,oany);
	}

	pub fn set_digest(&mut self,digoid :&str,params :Option<Asn1Any>,data :&[u8]) -> Result<(),Box<dyn Error>> {
		self.messageDigest.set_algo(digoid,params)?;
		return self.messageDigest.set_digest(data);
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcIndirectDataContent {
	pub elem :Asn1Seq<SpcIndirectDataContentElem>,
}

impl SpcIndirectDataContent {
	fn _make_sure_elem(&mut self) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			self.elem.val.push(SpcIndirectDataContentElem::init_asn1());
		}
		Ok(())		
	}
	pub fn set_data(&mut self,oid :&str,oany :Option<Asn1Any>) -> Result<(),Box<dyn Error>> {
		self._make_sure_elem()?;
		return self.elem.val[0].set_data(oid,oany);
	}

	pub fn set_digest(&mut self,digoid :&str,params :Option<Asn1Any>,data :&[u8]) -> Result<(),Box<dyn Error>> {
		self._make_sure_elem()?;
		return self.elem.val[0].set_digest(digoid,params,data);
	}
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct MessageImprintElem {
	pub digestAlgorithm :AlgorithmIdentifier,
	pub digest :Asn1OctData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct MessageImprint {
	pub elem :Asn1Seq<MessageImprintElem>,
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
pub struct SpcSerializedObjectElem {
	pub classId :Asn1OctString,
	pub serializedData :Asn1OctString,	
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcSerializedObject {
	pub elem :Asn1Seq<SpcSerializedObjectElem>,
}

#[asn1_int_choice(selector=itype,url=0,moniker=1,file=2)]
#[derive(Clone)]
pub struct SpcLinkElem {
	pub itype :i32,
	pub url :Asn1Imp<Asn1IA5String,0>,
	pub moniker :Asn1Imp<SpcSerializedObject,1>,
	pub file :Asn1Exp<SpcString,2>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcLink {
	pub elem :Asn1Seq<SpcLinkElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcPeImageDataElem {
	pub flags :Asn1BitData,
	pub file : Asn1Opt<Asn1Exp<SpcLink,0>>,
}

impl SpcPeImageDataElem {
	pub fn add_code(&mut self,code: i32,fstr :&str) -> Result<(),Box<dyn Error>> {
		self.flags.data = vec![];
		if code != 0 {
			self.flags.data.push((code& 0xff)as u8);	
		}
		
		let mut c :Asn1Exp<SpcLink,0> = Asn1Exp::init_asn1();
		if c.val.elem.val.len() == 0 {
			c.val.elem.val.push(SpcLinkElem::init_asn1());
		}
		c.val.elem.val[0].itype = 2;
		if c.val.elem.val[0].file.val.elem.val.len() == 0 {
			c.val.elem.val[0].file.val.elem.val.push(SpcStringElem::init_asn1());
		}
		
		c.val.elem.val[0].file.val.elem.val[0].itype = 0;
		c.val.elem.val[0].file.val.elem.val[0].unicode.val.val = format!("{}",fstr);
		self.file.val = Some(c);
		Ok(())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcPeImageData {
	pub elem :Asn1Seq<SpcPeImageDataElem>,
}

impl SpcPeImageData {
	pub fn add_code(&mut self,code: i32,fstr :&str) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() == 0 {
			self.elem.val.push(SpcPeImageDataElem::init_asn1());
		}
		return self.elem.val[0].add_code(code,fstr);
	}
}