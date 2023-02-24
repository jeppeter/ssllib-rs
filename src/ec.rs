#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
use asn1obj::complex::*;
#[allow(unused_imports)]
use asn1obj::*;

use std::error::Error;
use std::io::{Write};


#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIAL_ELEM {
	pub k1 : Asn1Integer,
	pub k2 : Asn1Integer,
	pub k3 : Asn1Integer,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIAL {
	pub elem :Asn1Seq<X9_62_PENTANOMIAL_ELEM>,
}