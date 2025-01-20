#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::asn1impl::*;
use asn1obj::*;
use asn1obj::strop::{asn1_format_line};
use crate::*;
use crate::logger::*;
use bytes::{BytesMut,BufMut};
use crate::x509::*;

use std::error::Error;
use std::io::{Write};

ssllib_error_class!{SslGenNameError}



#[asn1_sequence()]
#[derive(Clone)]
pub struct OtherNameElem {
	pub type_id :Asn1Object,
	pub value :Asn1Any,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct OtherName {
	pub elem :Asn1ImpA0<Asn1Seq<OtherNameElem>,0>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct DirectoryName {
	pub elem :Asn1ImpA0<Asn1Set<Asn1Seq<Asn1Set<Asn1X509Algor>>>,4>,
}

impl DirectoryName {
	pub fn set_algo(&mut self,oid :&str, oany :&Asn1Any) -> Result<(),Box<dyn Error>> {
		if self.elem.val.val.len() == 0 {
			self.elem.val.val.push(Asn1Seq::init_asn1());
		}

		if self.elem.val.val[0].val.len() == 0 {
			self.elem.val.val[0].val.push(Asn1Set::init_asn1());
		}

		if self.elem.val.val[0].val[0].val.len() == 0 {
			self.elem.val.val[0].val[0].val.push(Asn1X509Algor::init_asn1());
		}


		self.elem.val.val[0].val[0].val[0].set_algorithm(oid)?;
		self.elem.val.val[0].val[0].val[0].set_param(Some(oany.clone()))?;
		Ok(())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct EDIPARTYNAMEElem {
	pub nameAssigner :Asn1ImpA0<Asn1Seq<Asn1OctData>,0>,
	pub partyname :Asn1ImpA0<Asn1Any,1>,
}

impl EDIPARTYNAMEElem {
	pub fn set_names(&mut self,assigname :&str ,oany :&Asn1Any) -> Result<(),Box<dyn Error>> {
		if self.nameAssigner.val.val.len() == 0 {
			self.nameAssigner.val.val.push(Asn1OctData::init_asn1());
		}
		self.nameAssigner.val.val[0].data = assigname.as_bytes().to_vec().clone();

		self.partyname.val = oany.clone();
		Ok(())
	}
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct EDIPARTYNAME {
	pub elem :Asn1ImpA0<Asn1Seq<EDIPARTYNAMEElem>,5>,
}

impl EDIPARTYNAME {
	pub fn set_names(&mut self,assigname :&str ,oany :&Asn1Any) -> Result<(),Box<dyn Error>> {
		if self.elem.val.val.len() == 0 {
			self.elem.val.val.push(EDIPARTYNAMEElem::init_asn1());
		}
		return self.elem.val.val[0].set_names(assigname,oany);
	}
}

#[asn1_int_choice(selector=itype,othername=0,rfc822name=1,dnsname=2,directoryname=4,edipartyname=5)]
#[derive(Clone)]
pub struct Asn1_GENERAL_NAME {
	pub itype :i32,
	pub othername :OtherName,
	pub rfc822name :Asn1Imp<Asn1IA5String,1>,
	pub dnsname :Asn1Imp<Asn1IA5String,2>,
	pub directoryname :DirectoryName,
	pub edipartyname :EDIPARTYNAME,
}


