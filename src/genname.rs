#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::asn1impl::*;
use asn1obj::*;
use asn1obj::strop::{asn1_format_line};

use std::error::Error;
use std::io::{Write};




#[asn1_sequence()]
#[derive(Clone)]
pub struct OtherNameElem {
	pub type_id :Asn1Object,
	pub value :Asn1Any,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct OtherName {
	pub elem :Asn1ImpSet<OtherNameElem,0>,
}

#[asn1_int_choice(selector=itype,othername=0)]
#[derive(Clone)]
pub struct Asn1_GENERAL_NAME {
	pub itype :i32,
	pub othername :OtherName,
}
