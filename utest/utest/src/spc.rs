#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};


#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcAttributeTypeAndOptionalValueElem {
	pub itype :Asn1Object,
	pub value :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcAttributeTypeAndOptionalValue {
	pub elem :Asn1Seq<SpcAttributeTypeAndOptionalValueElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct AlgorithmIdentifierElem {
	pub algorithm :Asn1Object,
	pub parameters :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct AlgorithmIdentifier {
	pub elem :Asn1Seq<AlgorithmIdentifierElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct DigestInfoElem {
	pub digestAlgorithm :AlgorithmIdentifier,
	pub digest : Asn1OctData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct DigestInfo {
	pub elem :Asn1Seq<DigestInfoElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcIndirectDataContentElem {
	pub data :SpcAttributeTypeAndOptionalValue,
	pub messageDigest :DigestInfo,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct SpcIndirectDataContent {
	pub elem :Asn1Seq<SpcIndirectDataContentElem>,
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
	pub ordering :Asn1Bool,
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

#[asn1_int_choice()]
#[derive(Clone)]
pub struct SpcLink {
	pub itype :i32,
	pub url :Asn1I5AString,
	pub moniker :SpcSerializedObject,
}