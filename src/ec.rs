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


#[asn1_obj_selector(other=default,onbasis="1.2.840.10045.1.2.3.1",tpbasis="1.2.840.10045.1.2.3.2",ppbasis="1.2.840.10045.1.2.3.3")]
#[derive(Clone)]
pub struct X9_62_CHARACTERISTIC_TWO_SELECTOR {
	pub val :Asn1Object,
}

//#[asn1_choice(selector=selector,debug=enable)]
#[asn1_choice(selector=selector)]
#[derive(Clone)]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM_SEL {
	pub selector :X9_62_CHARACTERISTIC_TWO_SELECTOR,
	pub onbasis :Asn1Null,
	pub tpbasis :Asn1Integer,
	pub ppbasis :X9_62_PENTANOMIAL,
	pub other :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM {
	pub m :Asn1Integer,
	pub selelem : X9_62_CHARACTERISTIC_TWO_ELEM_SEL,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct X9_62_CHARACTERISTIC_TWO {
	pub elem :Asn1Seq<X9_62_CHARACTERISTIC_TWO_ELEM>,
}


#[asn1_obj_selector(other=default,prime="1.2.840.10045.1.1",twofield="1.2.840.10045.1.2")]
#[derive(Clone)]
pub struct X9_62_FIELDID_SELECTOR {
	pub val :Asn1Object,
}

//#[asn1_choice(selector=selector,debug=enable)]
#[asn1_choice(selector=selector)]
#[derive(Clone)]
pub struct  X9_62_FIELDID_ELEM {
	pub selector :X9_62_FIELDID_SELECTOR,
	pub prime :Asn1Integer,
	pub twofield :X9_62_CHARACTERISTIC_TWO,
	pub other :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct X9_62_FIELDID {
	pub elem :Asn1Seq<X9_62_FIELDID_ELEM>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct X9_62_CURVE_ELEM {
	pub a :Asn1OctData,
	pub b :Asn1OctData,
	pub seed :Asn1BitData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct X9_62_CURVE {
	pub elem :Asn1Seq<X9_62_CURVE_ELEM>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct ECPARAMETERS_ELEM {
	pub version :Asn1Integer,
	pub fieldid :X9_62_FIELDID,
	pub curve :X9_62_CURVE,
	pub base :Asn1OctData,
	pub order :Asn1Integer,
	pub cofactor :Asn1Integer,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct ECPARAMETERS {
	pub elem :Asn1Seq<ECPARAMETERS_ELEM>,
}

#[asn1_int_choice(selector=stype,named_curve=0,parameters=1,implicitlyca=2)]
#[derive(Clone)]
pub struct ECPKPARAMETERS_ELEM {
	pub stype :i32,
	pub named_curve :Asn1Object,
	pub parameters :ECPARAMETERS,
	pub implicitlyca :Asn1Null,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct EC_PRIVATEKEY_ELEM {
	pub version :Asn1Integer,
	pub privatekey :Asn1OctData,
	pub parameters :Asn1Opt<Asn1ImpSet<ECPKPARAMETERS_ELEM,0>>,
	pub publickey :Asn1Opt<Asn1ImpSet<Asn1BitData,1>>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct EC_PRIVATEKEY {
	pub elem :Asn1Seq<EC_PRIVATEKEY_ELEM>,
}