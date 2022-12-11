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

#[allow(unused_imports)]
use rsa::{RsaPublicKey,RsaPrivateKey,PublicKey};
use rsa::BigUint as rsaBigUint;
use rsa::hash::{Hash};
use rsa::padding::{PaddingScheme};

use crate::impls::*;
use crate::{ssllib_new_error,ssllib_error_class};

ssllib_error_class!{SslAsn1RsaError}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkeyElem {
	pub n :Asn1BigNum,
	pub e :Asn1BigNum,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkey {
	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
}

impl Asn1VerifyOp for Asn1RsaPubkey {
	fn verify(&self, origdata :&[u8],signdata :&[u8], digop :Box<dyn Asn1DigestOp>) -> Result<bool,Box<dyn Error>> {
		let mut retv :bool = false;
		if self.elem.val.len() != 1 {
			ssllib_new_error!{SslAsn1RsaError,"{} != 1 len",self.elem.val.len()}
		}
		let n = rsaBigUint::from_bytes_be(&self.elem.val[0].n.val.to_bytes_be());
		let e = rsaBigUint::from_bytes_be(&self.elem.val[0].e.val.to_bytes_be());
		let pubk = RsaPublicKey::new(n,e)?;
		let digest = digop.digest(origdata)?;
		let ores = pubk.verify(PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),&digest,signdata);
		if ores.is_ok() {
			retv = true;
		} 
		Ok(retv)
	}
}

//#[asn1_obj_selector(selector=val,any=default,rsa="1.2.840.113549.1.1.1",debug=enable)]
#[asn1_obj_selector(selector=val,any=default,rsa="1.2.840.113549.1.1.1")]
#[derive(Clone)]
pub struct Asn1X509PubkeySelector {
	pub val : Asn1Object,
	pub padded : Asn1Any,
}

//#[asn1_choice(selector=valid,debug=enable)]
#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1X509PubkeyElem {
	pub valid : Asn1SeqSelector<Asn1X509PubkeySelector>,
	pub rsa : Asn1BitSeq<Asn1RsaPubkey>,
	pub any : Asn1Any,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Pubkey {
	pub elem :Asn1Seq<Asn1X509PubkeyElem>,
}
