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
//use std::cell::RefCell;
//use std::sync::Arc;
use std::io::{Write};

#[allow(unused_imports)]
use rsa::{RsaPublicKey,RsaPrivateKey,PublicKey,PublicKeyParts};
use rsa::BigUint as rsaBigUint;
use rsa::hash::{Hash};
use rsa::padding::{PaddingScheme};

use num_bigint_dig::traits::ModInverse;
use num_bigint::{BigUint};
use num_bigint_dig::BigUint as DigBigUint;


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
	#[asn1_gen(initfn=pubkey_vfy_init_default)]
	pub inited :bool,
	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
}

fn pubkey_vfy_init_default() -> bool {
	false
}

impl Asn1VerifyOp for Asn1RsaPubkey {
	fn verify_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
		self.inited = true;
		Ok(())
	}

	fn verify_exec(&mut self, origdata :&[u8], signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
		if !self.inited {
			ssllib_new_error!{SslAsn1RsaError,"not inited verify"}
		}

		if self.elem.val.len() == 0 {
			ssllib_new_error!{SslAsn1RsaError,"no elem"}
		}
		let n = rsaBigUint::from_bytes_be(&self.elem.val[0].n.val.to_bytes_be());
		let e = rsaBigUint::from_bytes_be(&self.elem.val[0].e.val.to_bytes_be());
		let pubk = RsaPublicKey::new(n,e)?;
		let mut retv :bool = false;
		let ores = pubk.verify(PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),origdata,signdata);
		if ores.is_ok() {
			retv = true;
		} 
		Ok(retv)
	}
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
	#[asn1_gen(initfn=privkey_sign_init_default)]
	pub signinited :bool,
	#[asn1_gen(initfn=privkey_vfy_init_default)]
	pub vfyinited :bool,
	pub elem : Asn1Seq<Asn1RsaPrivateKeyElem>,
}

fn privkey_sign_init_default() -> bool {
	false
}

fn privkey_vfy_init_default() -> bool {
	false
}

macro_rules!  expand_priv_sign_op {
	($ctype:path,$hashtype:expr,$clsname:expr) => {
		impl Asn1SignOp for $ctype {
			fn sign_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
				self.signinited = true;
				Ok(())
			}
			fn sign_exec(&mut self,data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
				let retv :Vec<u8>;
				if !self.signinited {
					ssllib_new_error!{SslAsn1RsaError,"{} not inited sign",$clsname}
				}
				let n = rsaBigUint::from_bytes_be(&self.privkey.modulus.val.to_bytes_be());
				let d = rsaBigUint::from_bytes_be(&self.privkey.pubexp.val.to_bytes_be());
				let e = rsaBigUint::from_bytes_be(&self.privkey.privexp.val.to_bytes_be());
				let mut primes :Vec<rsaBigUint> = Vec::new();
				primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime1.val.to_bytes_be()));
				primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime2.val.to_bytes_be()));
				let po = RsaPrivateKey::from_components(n,d,e,primes);
				retv = po.sign(PaddingScheme::new_pkcs1v15_sign(Some($hashtype)),data)?;
				ssllib_buffer_trace!(retv.as_ptr(),retv.len(),"{} sign value",$clsname);
				Ok(retv)
			}
		}
	};
}

macro_rules!  expand_priv_vfy_op {
	($ctype:path,$hashtype:expr,$clsname:expr) => {
		impl Asn1VerifyOp for $ctype {
			fn verify_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
				self.vfyinited = true;
				Ok(())
			}

			fn verify_exec(&mut self, origdata :&[u8], signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
				let mut retv :bool = false;
				if !self.vfyinited {
					ssllib_new_error!{SslAsn1RsaError,"{} not inited vfy",$clsname}
				}
				let n = rsaBigUint::from_bytes_be(&self.privkey.modulus.val.to_bytes_be());
				let d = rsaBigUint::from_bytes_be(&self.privkey.pubexp.val.to_bytes_be());
				let e = rsaBigUint::from_bytes_be(&self.privkey.privexp.val.to_bytes_be());
				let mut primes :Vec<rsaBigUint> = Vec::new();
				primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime1.val.to_bytes_be()));
				primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime2.val.to_bytes_be()));
				let po = RsaPrivateKey::from_components(n,d,e,primes);
				let pubk = po.to_public_key();
				let ores = pubk.verify(PaddingScheme::new_pkcs1v15_sign(Some($hashtype)),origdata,signdata);
				if ores.is_ok() {
					retv = true;
				} 
				Ok(retv)
			}
		}
	};
}


macro_rules! decl_rsa_priv {
	($name :ident,$hashtype:expr,$clsname:expr) => {
		pub struct $name {
			privkey :Asn1RsaPrivateKeyElem,
			signinited : bool,
			vfyinited : bool,
		}

		impl $name {
			pub fn new_from_asn1_priv(privkey :&Asn1RsaPrivateKey) -> Result<Self,Box<dyn Error>> {
				privkey.elem.check_safe_one("Asn1RsaPrivateKeyElem")?;
				let retv :Self = Self {
					signinited : false,
					vfyinited : false,
					privkey :privkey.elem.val[0].clone(),
				};
				Ok(retv)
			}			
		}

		expand_priv_sign_op!{$name,$hashtype,$clsname}
		expand_priv_vfy_op!{$name,$hashtype,$clsname}
	}
}


decl_rsa_priv!{RsaMD5priv,Hash::MD5,"RsaMD5priv"}
decl_rsa_priv!{RsaSHA1priv,Hash::SHA1,"RsaSHA1priv"}
decl_rsa_priv!{RsaSHA224priv,Hash::SHA2_224,"RsaSHA224priv"}
decl_rsa_priv!{RsaSHA256priv,Hash::SHA2_256,"RsaSHA256priv"}
decl_rsa_priv!{RsaSHA384priv,Hash::SHA2_384,"RsaSHA384priv"}
decl_rsa_priv!{RsaSHA512priv,Hash::SHA2_512,"RsaSHA512priv"}

macro_rules! decl_pub_vfy {
	($name:ident,$hashtype:expr,$clsname:expr) => {
		impl Asn1VerifyOp for $name {
			fn verify_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
				self.vfyinited = true;
				Ok(())
			}

			fn verify_exec(&mut self, origdata :&[u8], signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
				let mut retv :bool = false;
				if !self.vfyinited {
					ssllib_new_error!{SslAsn1RsaError,"{} not inited vfy",$clsname}
				}
				let nb = rsaBigUint::from_bytes_be(&self.pubkey.n.val.to_bytes_be());
				let eb = rsaBigUint::from_bytes_be(&self.pubkey.e.val.to_bytes_be());

				let pubk = RsaPublicKey::new(nb,eb)?;
				let ores = pubk.verify(PaddingScheme::new_pkcs1v15_sign(Some($hashtype)),origdata,signdata);
				if ores.is_ok() {
					retv = true;
				} 
				Ok(retv)
			}
		}
	}
}

macro_rules! decl_rsa_pub {
	($name:ident,$hashtype:expr,$clsname:expr) => {
		pub struct $name {
			pubkey :Asn1RsaPubkeyElem,
			vfyinited :bool,
		}

		impl $name {
			pub fn new_from_priv(privkey :&Asn1RsaPrivateKey) -> Result<Self,Box<dyn Error>> {
				let mut pubkey :Asn1RsaPubkeyElem = Asn1RsaPubkeyElem::init_asn1();
				privkey.elem.check_safe_one("Asn1RsaPrivateKeyElem")?;
				let n = rsaBigUint::from_bytes_be(&privkey.elem.val[0].modulus.val.to_bytes_be());
				let d = rsaBigUint::from_bytes_be(&privkey.elem.val[0].pubexp.val.to_bytes_be());
				let e = rsaBigUint::from_bytes_be(&privkey.elem.val[0].privexp.val.to_bytes_be());
				let mut primes :Vec<rsaBigUint> = Vec::new();
				primes.push(rsaBigUint::from_bytes_be(&privkey.elem.val[0].prime1.val.to_bytes_be()));
				primes.push(rsaBigUint::from_bytes_be(&privkey.elem.val[0].prime2.val.to_bytes_be()));
				let po = RsaPrivateKey::from_components(n,d,e,primes);
				let nb :rsaBigUint = po.n().clone();
				let eb :rsaBigUint = po.e().clone();
				pubkey.n.val = BigUint::from_bytes_be(&nb.to_bytes_be());
				pubkey.e.val = BigUint::from_bytes_be(&eb.to_bytes_be());
				let retv :Self = Self {
					pubkey :pubkey.clone(),
					vfyinited : false,
				};
				Ok(retv)
			}

			pub fn new_from_pub(pubkey :&Asn1RsaPubkey) -> Result<Self,Box<dyn Error>> {
				pubkey.elem.check_safe_one("Asn1RsaPubkeyElem")?;
				let retv :Self = Self {
					pubkey : pubkey.elem.val[0].clone(),
					vfyinited : false,
				};
				Ok(retv)
			}
		}


		decl_pub_vfy!{$name,$hashtype,$clsname}
	}
}


decl_rsa_pub!{RsaMD5pub,Hash::MD5,"RsaMD5pub"}
decl_rsa_pub!{RsaSHA1pub,Hash::SHA1,"RsaSHA1pub"}
decl_rsa_pub!{RsaSHA224pub,Hash::SHA2_224,"RsaSHA224pub"}
decl_rsa_pub!{RsaSHA256pub,Hash::SHA2_256,"RsaSHA256pub"}
decl_rsa_pub!{RsaSHA384pub,Hash::SHA2_384,"RsaSHA384pub"}
decl_rsa_pub!{RsaSHA512pub,Hash::SHA2_512,"RsaSHA512pub"}




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
		let p :DigBigUint = DigBigUint::from_bytes_be(&(primes[0].to_bytes_be()));
		let q :DigBigUint = DigBigUint::from_bytes_be(&(primes[1].to_bytes_be()));
		let r1 :DigBigUint = p.clone() - 1 as u32;
		let r2 :DigBigUint = q.clone() - 1 as u32;
		let e :DigBigUint = DigBigUint::from_bytes_be(&(key.e().to_bytes_be()));
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