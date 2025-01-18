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
	pub elem :Asn1ImpA0<Asn1Seq<Asn1Set<Asn1Seq<Asn1X509Elem>>>,4>,
}

impl DirectoryName {
	pub fn set_algo(&mut self,oid :&str, oany :&Asn1Any) -> Result<(),Box<dyn Error>> {
		if self.elem.val.val.len() == 0 {
			self.elem.val.val.push(Asn1Set::init_asn1());
		}
		Ok(())
	}
}

#[asn1_int_choice(selector=itype,othername=0,rfc822name=1,dnsname=2,directoryname=4)]
#[derive(Clone)]
pub struct Asn1_GENERAL_NAME {
	pub itype :i32,
	pub othername :OtherName,
	pub rfc822name :Asn1Imp<Asn1IA5String,1>,
	pub dnsname :Asn1Imp<Asn1IA5String,2>,
	pub directoryname :DirectoryName,
}


