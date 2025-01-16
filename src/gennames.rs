

pub struct OtherName {
	pub elem :Asn1Seq<OtherNameElem>,
}

#[asn1_int_choice(selector=itype,othername=0,email=1,dns=2,x400=3,dirname=4,ediparty=5,uri=6,ipadd=7,rid=8)]
#[derive(Clone)]
pub struct GENERAL_NAME {
	pub itype :i32,
	pub othername :OtherName,
}
