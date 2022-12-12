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
use rsa::{RsaPublicKey,RsaPrivateKey,PublicKey,PublicKeyParts};
use rsa::BigUint as rsaBigUint;
use rsa::hash::{Hash};
use rsa::padding::{PaddingScheme};

use num_bigint::traits::ModInverse;
use num_bigint::{BigUint};


use crate::impls::*;
use crate::fileop::RandFile;

use crate::{ssllib_new_error,ssllib_error_class,ssllib_buffer_trace};
use crate::{ssllib_format_buffer_log};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};

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

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPrivateKeyElem {
	pub version :Asn1Integer,
	pub modulus : Asn1BigNum,
	pub pubexp : Asn1BigNum,
	pub privexp : Asn1BigNum,
	pub prime1 :Asn1BigNum,
	pub prime2 :Asn1BigNum,
	pub exp1 : Asn1BigNum,
	pub exp2 :Asn1BigNum,
	pub coeff : Asn1BigNum,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPrivateKey {
	pub elem : Asn1Seq<Asn1RsaPrivateKeyElem>,
}

impl Asn1SignOp for Asn1RsaPrivateKey {
	fn sign(&self,data :&[u8],digop :Box<dyn Asn1DigestOp>) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv :Vec<u8>;
		if self.elem.val.len() != 1 {
			ssllib_new_error!{SslAsn1RsaError,"{} not valid len",self.elem.val.len()}
		}

		let n = rsaBigUint::from_bytes_be(&self.elem.val[0].modulus.val.to_bytes_be());
		let d = rsaBigUint::from_bytes_be(&self.elem.val[0].pubexp.val.to_bytes_be());
		let e = rsaBigUint::from_bytes_be(&self.elem.val[0].privexp.val.to_bytes_be());
		let mut primes :Vec<rsaBigUint> = Vec::new();
		primes.push(rsaBigUint::from_bytes_be(&self.elem.val[0].prime1.val.to_bytes_be()));
		primes.push(rsaBigUint::from_bytes_be(&self.elem.val[0].prime2.val.to_bytes_be()));
		let po = RsaPrivateKey::from_components(n,d,e,primes);
		let digest = digop.digest(data)?;
		retv = po.sign(PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),&digest)?;
		ssllib_buffer_trace!(retv.as_ptr(),retv.len(),"sign value");
		Ok(retv)
	}
}

impl Asn1VerifyOp for Asn1RsaPrivateKey {
	fn verify(&self, origdata :&[u8],signdata :&[u8], digop :Box<dyn Asn1DigestOp>) -> Result<bool,Box<dyn Error>> {
		let mut retv :bool = false;
		if self.elem.val.len() != 1 {
			ssllib_new_error!{SslAsn1RsaError,"{} != 1 len",self.elem.val.len()}
		}
		let n = rsaBigUint::from_bytes_be(&self.elem.val[0].modulus.val.to_bytes_be());
		let d = rsaBigUint::from_bytes_be(&self.elem.val[0].pubexp.val.to_bytes_be());
		let e = rsaBigUint::from_bytes_be(&self.elem.val[0].privexp.val.to_bytes_be());
		let mut primes :Vec<rsaBigUint> = Vec::new();
		primes.push(rsaBigUint::from_bytes_be(&self.elem.val[0].prime1.val.to_bytes_be()));
		primes.push(rsaBigUint::from_bytes_be(&self.elem.val[0].prime2.val.to_bytes_be()));
		let po = RsaPrivateKey::from_components(n,d,e,primes);
		let pubk = po.to_public_key();
		let digest = digop.digest(origdata)?;
		let ores = pubk.verify(PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),&digest,signdata);
		if ores.is_ok() {
			retv = true;
		} 
		Ok(retv)
	}	
}

impl Asn1RsaPrivateKey {
	pub fn generate(bitsize :usize, randfile :Option<String>) -> Result<Asn1RsaPrivateKey,Box<dyn Error>> {
		let key :RsaPrivateKey;
		let mut retv :Asn1RsaPrivateKey = Asn1RsaPrivateKey::init_asn1();
		if randfile.is_none() {
			let mut gencore  = rand::thread_rng();
			key = RsaPrivateKey::new(&mut gencore,bitsize)?;
		} else {
			let fname = randfile.as_ref().unwrap();
			let mut rf = RandFile::new(fname)?;
			key = RsaPrivateKey::new(&mut rf,bitsize)?;
		}

		/*now to get the random number*/
		retv.elem.val = Vec::new();
		retv.elem.val.push(Asn1RsaPrivateKeyElem::init_asn1());
		/*for the version is 2*/
		retv.elem.val[0].version.set_value(2 as i64);
		retv.elem.val[0].modulus.set_value(&(key.n().to_bytes_be()));
		retv.elem.val[0].pubexp.set_value(&(key.e().to_bytes_be()));
		retv.elem.val[0].privexp.set_value(&(key.d().to_bytes_be()));
		let primes = key.primes();
		retv.elem.val[0].prime1.set_value(&(primes[0].to_bytes_be()));
		retv.elem.val[0].prime2.set_value(&(primes[1].to_bytes_be()));
		let p :BigUint = BigUint::from_bytes_be(&(primes[0].to_bytes_be()));
		let q :BigUint = BigUint::from_bytes_be(&(primes[1].to_bytes_be()));
		let r1 :BigUint = p.clone() - 1 as u32;
		let r2 :BigUint = q.clone() - 1 as u32;
		let e :BigUint = BigUint::from_bytes_be(&(key.e().to_bytes_be()));
		let dbase = r1.clone() * r2.clone();
		let d2 = e.clone().mod_inverse(&dbase).unwrap();
		let d = d2.to_biguint().unwrap();
		let exp1 = d.clone() % r1.clone();
		let exp2 = d.clone() % r2.clone();

		retv.elem.val[0].exp1.set_value(&(exp1.to_bytes_be()));
		retv.elem.val[0].exp2.set_value(&(exp2.to_bytes_be()));
		let co2 = q.clone().mod_inverse(&p).unwrap();
		let co = co2.to_biguint().unwrap();
		retv.elem.val[0].coeff.set_value(&(co.to_bytes_be()));
		Ok(retv)
	}
}