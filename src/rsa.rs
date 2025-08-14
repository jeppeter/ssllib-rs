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
use rsa::{RsaPublicKey,RsaPrivateKey};
use rsa::pkcs1v15::{SigningKey, VerifyingKey,Signature};
use rsa::traits::{SignatureScheme,PublicKeyParts,PrivateKeyParts};
use rsa::signature::{SignatureEncoding,Verifier,RandomizedSigner};
use rsa::BigUint as rsaBigUint;

use num_bigint_dig::traits::ModInverse;
use num_bigint::{BigUint};
use num_bigint_dig::BigUint as DigBigUint;

//use sha2::{Digest};


use crate::impls::*;
use crate::fileop::RandFile;

use crate::{ssllib_new_error,ssllib_error_class,ssllib_buffer_trace,ssllib_log_trace};
use crate::{ssllib_format_buffer_log};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};

use digest::{Digest};


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

impl Asn1RsaPrivateKeyElem {
	pub fn export_public(&self) -> Result<Asn1RsaPubkeyElem,Box<dyn Error>> {
		let mut retv :Asn1RsaPubkeyElem = Asn1RsaPubkeyElem::init_asn1();
		let n = rsaBigUint::from_bytes_be(&self.modulus.val.to_bytes_be());
		let d = rsaBigUint::from_bytes_be(&self.pubexp.val.to_bytes_be());
		let e = rsaBigUint::from_bytes_be(&self.privexp.val.to_bytes_be());
		let mut primes :Vec<rsaBigUint> = Vec::new();
		primes.push(rsaBigUint::from_bytes_be(&self.prime1.val.to_bytes_be()));
		primes.push(rsaBigUint::from_bytes_be(&self.prime2.val.to_bytes_be()));
		let ores = RsaPrivateKey::from_components(n,d,e,primes);
		if ores.is_err() {
			ssllib_new_error!{SslAsn1RsaError,"{} not valid RsaPrivateKey","Asn1RsaPubkeyElem"}
		}
		let po = ores.unwrap();
		let pubk = po.to_public_key();

		retv.n.val = BigUint::from_bytes_be(&pubk.n().to_bytes_be());
		retv.e.val = BigUint::from_bytes_be(&pubk.e().to_bytes_be());
		Ok(retv)
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPrivateKey {
	pub elem : Asn1Seq<Asn1RsaPrivateKeyElem>,
}

impl Asn1RsaPrivateKey {
	pub fn export_public(&self) -> Result<Asn1RsaPubkey,Box<dyn Error>> {
		self.elem.check_safe_one("Asn1RsaPrivateKeyElem")?;
		let mut retv :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
		retv.elem.val.push(self.elem.val[0].export_public()?);
		Ok(retv)
	}
}

macro_rules!  expand_priv_sign_op {
	($ctype:path,$hashtype:path,$clsname:expr) => {
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
				let ores = RsaPrivateKey::from_components(n,d,e,primes);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} not valid RsaPrivateKey",$clsname}
				}
				let po = ores.unwrap();
				let signkey :SigningKey<$hashtype> = SigningKey::<$hashtype>::new(po);
				let mut rng = rand::thread_rng();
				let sig :Signature = signkey.sign_with_rng(&mut rng,data);
				retv = sig.to_bytes().to_vec();
				ssllib_buffer_trace!(retv.as_ptr(),retv.len(),"{} sign value",$clsname);
				Ok(retv)
			}
		}
	};
}

macro_rules!  expand_priv_vfy_op {
	($ctype:path,$hashtype:path,$clsname:expr) => {
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
				let ores = RsaPrivateKey::from_components(n,d,e,primes);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} not valid RsaPrivateKey",$clsname}
				}
				let po = ores.unwrap();
				let pubk = po.to_public_key();
				let vfykey = VerifyingKey::<$hashtype>::new(pubk);
				let ores = Signature::try_from(signdata);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} not sign data valid {:?}",$clsname, ores.err().unwrap()}
				}
				let sig :Signature = ores.unwrap();
				let ores = vfykey.verify(origdata,&sig);
				if ores.is_ok() {
					retv = true;
				} 
				Ok(retv)
			}
		}
	};
}


macro_rules! decl_rsa_priv {
	($name :ident,$hashtype:path,$clsname:expr) => {
		pub struct $name {
			privkey :Asn1RsaPrivateKeyElem,
			signinited : bool,
			vfyinited : bool,
		}

		impl $name {
			pub fn new_from_priv(privkey :&Asn1RsaPrivateKey) -> Result<Self,Box<dyn Error>> {
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


decl_rsa_priv!{RsaMD5priv,md5::Md5,"RsaMD5priv"}
decl_rsa_priv!{RsaSHA1priv,sha1::Sha1,"RsaSHA1priv"}
decl_rsa_priv!{RsaSHA224priv,sha2::Sha224,"RsaSHA224priv"}
decl_rsa_priv!{RsaSHA256priv,sha2::Sha256,"RsaSHA256priv"}
decl_rsa_priv!{RsaSHA384priv,sha2::Sha384,"RsaSHA384priv"}
decl_rsa_priv!{RsaSHA512priv,sha2::Sha512,"RsaSHA512priv"}

macro_rules! decl_pub_vfy {
	($name:ident,$hashtype:path,$clsname:expr) => {
		impl Asn1VerifyOp for $name {
			fn verify_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
				self.vfyinited = true;
				Ok(())
			}

			fn verify_exec(&mut self, origdata :&[u8], signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
				let  retv :bool;
				if !self.vfyinited {
					ssllib_new_error!{SslAsn1RsaError,"{} not inited vfy",$clsname}
				}
				let nb = rsaBigUint::from_bytes_be(&self.pubkey.n.val.to_bytes_be());
				let eb = rsaBigUint::from_bytes_be(&self.pubkey.e.val.to_bytes_be());

				let pubk = RsaPublicKey::new(nb,eb)?;
				let vfykey = VerifyingKey::<$hashtype>::new(pubk);
				let ores = Signature::try_from(signdata);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} not valid signature {:?}",$clsname,ores.err().unwrap()}
				}
				let sig :Signature = ores.unwrap();
				let ores = vfykey.verify(origdata,&sig);
				if ores.is_ok() {
					retv = true;
				}  else {
					ssllib_new_error!{SslAsn1RsaError,"{} verify error {:?}", $clsname,ores.err().unwrap()}
				}
				Ok(retv)
			}
		}
	}
}

macro_rules! decl_rsa_pub {
	($name:ident,$hashtype:path,$clsname:expr) => {
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
				let ores = RsaPrivateKey::from_components(n,d,e,primes);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} not valid rsa private {:?}",$clsname,ores.err().unwrap()}
				}
				let po = ores.unwrap();
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


decl_rsa_pub!{RsaMD5pub,md5::Md5,"RsaMD5pub"}
decl_rsa_pub!{RsaSHA1pub,sha1::Sha1,"RsaSHA1pub"}
decl_rsa_pub!{RsaSHA224pub,sha2::Sha224,"RsaSHA224pub"}
decl_rsa_pub!{RsaSHA256pub,sha2::Sha256,"RsaSHA256pub"}
decl_rsa_pub!{RsaSHA384pub,sha2::Sha384,"RsaSHA384pub"}
decl_rsa_pub!{RsaSHA512pub,sha2::Sha512,"RsaSHA512pub"}

pub struct RsaPSSSHA256priv {
	privkey :Asn1RsaPrivateKeyElem,
	signinited : bool,
	vfyinited : bool,
	saltlen : usize,
}

impl RsaPSSSHA256priv {
	pub fn new(privkey :&Asn1RsaPrivateKey,len :usize) -> Result<Self,Box<dyn Error>> {
		privkey.elem.check_safe_one("Asn1RsaPrivateKeyElem")?;
		let mut saltlen :usize = len;
		if saltlen == 0xff {
			saltlen = 32;
		} else if saltlen == 0 {
			let n = rsaBigUint::from_bytes_be(&privkey.elem.val[0].modulus.val.to_bytes_be());
			let d = rsaBigUint::from_bytes_be(&privkey.elem.val[0].pubexp.val.to_bytes_be());
			let e = rsaBigUint::from_bytes_be(&privkey.elem.val[0].privexp.val.to_bytes_be());
			let mut primes :Vec<rsaBigUint> = Vec::new();
			primes.push(rsaBigUint::from_bytes_be(&privkey.elem.val[0].prime1.val.to_bytes_be()));
			primes.push(rsaBigUint::from_bytes_be(&privkey.elem.val[0].prime2.val.to_bytes_be()));
			let ores = RsaPrivateKey::from_components(n,d,e,primes);
			if ores.is_err() {
				ssllib_new_error!{SslAsn1RsaError,"{} not valid RsaPrivateKey","RsaPSSSHA256priv"}
			}
			let po = ores.unwrap();
			let pubk = po.to_public_key();
			let nbytes :Vec<u8> = pubk.n().to_bytes_be().clone();
			saltlen = ((nbytes.len() * 8 - 1 + 7) >> 3) - 2 - 32;
		}
		ssllib_log_trace!("saltlen {}",saltlen);
		let retv :Self = Self {
			privkey : privkey.elem.val[0].clone(),
			signinited : false,
			vfyinited : false,
			saltlen : saltlen,
		};
		Ok(retv)
	}
}

impl Asn1SignOp for RsaPSSSHA256priv {
	fn sign_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
		self.signinited = true;
		Ok(())
	}
	fn sign_exec(&mut self,data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv :Vec<u8>;
		if !self.signinited {
			ssllib_new_error!{SslAsn1RsaError,"{} not inited sign","RsaPSSSHA256priv"}
		}
		let n = rsaBigUint::from_bytes_be(&self.privkey.modulus.val.to_bytes_be());
		let d = rsaBigUint::from_bytes_be(&self.privkey.pubexp.val.to_bytes_be());
		let e = rsaBigUint::from_bytes_be(&self.privkey.privexp.val.to_bytes_be());
		let mut primes :Vec<rsaBigUint> = Vec::new();
		primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime1.val.to_bytes_be()));
		primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime2.val.to_bytes_be()));
		let ores = RsaPrivateKey::from_components(n,d,e,primes);
		if ores.is_err() {
			ssllib_new_error!{SslAsn1RsaError,"{} not valid RsaPrivateKey","RsaPSSSHA256priv"}
		}
		let po = ores.unwrap();
		//let psskey :rsa::pss::Pss = rsa::pss::Pss::new_blinded_with_salt::<sha2::Sha256>(self.saltlen);
		let psskey :rsa::pss::Pss = rsa::pss::Pss::new_with_salt::<sha2::Sha256>(self.saltlen);
		//let mut hasher = sha2::Sha256::new();
		//hasher.update(data);
		//let hashdata = hasher.finalize().to_vec();
		let hashdata = data.to_vec().clone();
		let mut gencore  = rand::thread_rng();
		let putn = Some(&mut gencore);
		let ores = psskey.sign::<rand::rngs::ThreadRng>(putn,&po,&hashdata);
		if ores.is_err() {
			ssllib_new_error!{SslAsn1RsaError,"{} sign error {:?}","RsaPSSSHA256priv", ores.err().unwrap()}
		}
		retv= ores.unwrap();
		ssllib_buffer_trace!(retv.as_ptr(),retv.len(),"{} sign value","RsaPSSSHA256priv");
		Ok(retv)
	}
}

impl Asn1VerifyOp for RsaPSSSHA256priv {
	fn verify_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
		self.vfyinited = true;
		Ok(())
	}
	fn verify_exec(&mut self,origdata:&[u8],signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
		let retv :bool;
		if !self.vfyinited {
			ssllib_new_error!{SslAsn1RsaError,"{} not inited verify","RsaPSSSHA256priv"}
		}
		let n = rsaBigUint::from_bytes_be(&self.privkey.modulus.val.to_bytes_be());
		let d = rsaBigUint::from_bytes_be(&self.privkey.pubexp.val.to_bytes_be());
		let e = rsaBigUint::from_bytes_be(&self.privkey.privexp.val.to_bytes_be());
		let mut primes :Vec<rsaBigUint> = Vec::new();
		primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime1.val.to_bytes_be()));
		primes.push(rsaBigUint::from_bytes_be(&self.privkey.prime2.val.to_bytes_be()));
		let ores = RsaPrivateKey::from_components(n,d,e,primes);
		if ores.is_err() {
			ssllib_new_error!{SslAsn1RsaError,"{} not valid RsaPrivateKey","RsaPSSSHA256priv"}
		}
		let po = ores.unwrap();
		let pubk = po.to_public_key();
		//let psskey :rsa::pss::Pss = rsa::pss::Pss::new_blinded_with_salt::<sha2::Sha256>(self.saltlen);
		let psskey :rsa::pss::Pss = rsa::pss::Pss::new_with_salt::<sha2::Sha256>(self.saltlen);
		//let mut hasher = sha2::Sha256::new();
		//hasher.update(origdata);
		//let hashdata = hasher.finalize().to_vec();
		let hashdata = origdata.to_vec().clone();
		ssllib_log_trace!("signdata.len {} pubkey.size {}", signdata.len(), pubk.size());
		let ores =  psskey.verify(&pubk,&hashdata,signdata);
		if ores.is_err() {
			ssllib_new_error!{SslAsn1RsaError,"{} verify failed {:?}","RsaPSSSHA256priv",ores.err().unwrap()}
		}
		retv = true;
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