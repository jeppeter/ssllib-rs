#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use asn1obj::*;

use std::error::Error;
use std::io::{Write};


use crate::x509::*;
use crate::pkcs7::*;

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1AuthSafes {
	pub safes :Asn1Seq<Asn1Pkcs7>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pbe2ParamElem {
	pub keyfunc : Asn1X509Algor,
	pub encryption : Asn1X509Algor,
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

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1NetscapePkey {
	pub elem : Asn1Seq<Asn1NetscapePkeyElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12MacDataElem {
	pub dinfo : Asn1X509Sig,
	pub salt : Asn1OctData,
	pub iternum : Asn1Integer,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12MacData {
	pub elem : Asn1Seq<Asn1Pkcs12MacDataElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12Elem {
	pub version : Asn1Integer,
	pub authsafes : Asn1Pkcs7,
	pub mac : Asn1Opt<Asn1Pkcs12MacData>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12 {
	pub elem : Asn1Seq<Asn1Pkcs12Elem>,
}

#[asn1_obj_selector(selector=val,any=default,x509cert="1.2.840.113549.1.9.22.1")]
#[derive(Clone)]
pub struct Asn1Pkcs12BagsSelector {
	pub val : Asn1Object,
}


#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1Pkcs12BagsElem {
	pub valid : Asn1Pkcs12BagsSelector,
	pub x509cert : Asn1ImpSet<Asn1OctData,0>,
	pub any :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12Bags {
	pub elem :Asn1Seq<Asn1Pkcs12BagsElem>,
}

#[asn1_obj_selector(selector=val,any=default,shkeybag="1.2.840.113549.1.12.10.1.2",bag=["1.2.840.113549.1.12.10.1.3"])]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelector {
	pub val : Asn1Object,
}

#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelectElem {
	pub valid : Asn1Pkcs12SafeBagSelector,
	pub shkeybag : Asn1ImpSet<Asn1X509Sig,0>,
	pub bag : Asn1ImpSet<Asn1Pkcs12Bags,0>,
	pub any :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagElem {
	pub selectelem : Asn1Pkcs12SafeBagSelectElem,
	pub attrib : Asn1Opt<Asn1Set<Asn1X509Attribute>>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBag {
	pub elem : Asn1Seq<Asn1Pkcs12SafeBagElem>,
}
