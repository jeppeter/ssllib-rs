#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
use asn1obj::asn1impl::*;
use asn1obj::complex::*;
use asn1obj::base::*;
use asn1obj::strop::{asn1_format_line};
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use std::error::Error;
use std::io::Write;
use extargsparse_worker::{extargs_new_error,extargs_error_class};
use super::pelib::pe_get_digest;
use ssllib::utils::ssllib_get_digest_oid;
use ssllib::ts::{AlgorithmIdentifier};


extargs_error_class!{SpcError}

pub const SPC_RFC3161_OBJID  :&str =           "1.3.6.1.4.1.311.3.3.1";

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

pub const SPC_PE_IMAGE_DATA_OBJID :&str = "1.3.6.1.4.1.311.2.1.15";

pub fn form_sidc_from_pefile(dgstname :&str,pefile :&str,times :u32, initv :&[u8]) -> Result<SpcIndirectDataContent,Box<dyn Error>> {
	let mut sidc :SpcIndirectDataContent = SpcIndirectDataContent::init_asn1();
	let mut spi :SpcPeImageData = SpcPeImageData::init_asn1();
	spi.add_code(0,"<<<Obsolete>>>")?;
	let spicode = spi.encode_asn1()?;
	let mut oany :Asn1Any = Asn1Any::init_asn1();
	oany.decode_asn1(&spicode)?;
	sidc.set_data(SPC_PE_IMAGE_DATA_OBJID,Some(oany))?;
	let dgstcode = pe_get_digest(dgstname,pefile,times,initv)?;
	let ooid = ssllib_get_digest_oid(dgstname);
	if ooid.is_none() {
		extargs_new_error!{SpcError,"not support {} dgst",dgstname}
	}
	let oidname = ooid.unwrap();
	let nulv :Asn1Null = Asn1Null::init_asn1();
	let nullcode = nulv.encode_asn1()?;
	let mut coany :Asn1Any = Asn1Any::init_asn1();
	coany.decode_asn1(&nullcode)?;
	sidc.set_digest(&oidname,Some(coany),&dgstcode)?;
	return Ok(sidc);
}

