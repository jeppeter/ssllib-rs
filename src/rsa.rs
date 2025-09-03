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

use md5::{Md5};
use sha1::{Sha1};
use sha2::{Sha224,Sha256,Sha384,Sha512};


use crate::impls::*;
use crate::fileop::RandFile;
use crate::consts::*;
use crate::x509::{Asn1X509Algor,Asn1X509Pubkey,Asn1X509AlgorElem,Asn1X509PubkeyElem};

use crate::{ssllib_new_error,ssllib_error_class,ssllib_buffer_trace,ssllib_log_trace};
use crate::{ssllib_format_buffer_log};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};

use digest::{Digest};


ssllib_error_class!{SslAsn1RsaError}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPssAlgoElem {
	pub algo :Asn1ImpSet<Asn1X509Algor,0>,
	pub pattern :Asn1ImpSet<Asn1X509Algor,1>,
	pub size :Asn1ImpSet<Asn1Integer,2>,
}

pub struct Asn1RsaPssAlgo {
	pub elem :Asn1Seq<Asn1RsaPssAlgoElem>,
}


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

#[asn1_sequence()]
#[derive(Clone)]
pub struct RsaPssSigInfoElem {
	pub algo :Asn1Opt<Asn1ImpSet<Asn1X509Algor,0>>,
	pub cmplx :Asn1Opt<Asn1ImpSet<Asn1X509Algor,1>>,
	pub saltlen :Asn1Opt<Asn1ImpSet<Asn1Integer,2>>,
	pub trailer :Asn1Opt<Asn1ImpSet<Asn1Integer,3>>,
}

#[asn1_sequence()]
pub struct RsaPssSigInfo {
	pub elem :Asn1Seq<RsaPssSigInfoElem>,
}

macro_rules!  expand_priv_sign_op {
	($ctype:path,$hashtype:ident,$clsname:expr) => {
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
				ssllib_buffer_trace!(data.as_ptr(),data.len(),"{} indata sign",$clsname);
				ssllib_buffer_trace!(retv.as_ptr(),retv.len(),"{} signdata sign",$clsname);
				Ok(retv)
			}
		}
	};
}

macro_rules!  expand_priv_vfy_op {
	($ctype:path,$hashtype:ident,$clsname:expr) => {
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
				ssllib_buffer_trace!(origdata.as_ptr(),origdata.len(),"{} indata vfy",$clsname);
				ssllib_buffer_trace!(signdata.as_ptr(),signdata.len(),"{} signdata vfy",$clsname);
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
	($name :ident,$hashtype:ident,$oid:ident) => {
		pub struct $name {
			privkey :Asn1RsaPrivateKeyElem,
			signinited : bool,
			vfyinited : bool,
			sigature_oid :String,
		}

		impl $name {
			pub fn new_from_priv(privkey :&Asn1RsaPrivateKey) -> Result<Self,Box<dyn Error>> {
				privkey.elem.check_safe_one("Asn1RsaPrivateKeyElem")?;
				let retv :Self = Self {
					signinited : false,
					vfyinited : false,
					privkey :privkey.elem.val[0].clone(),
					sigature_oid : format!("{}",$oid),
				};
				Ok(retv)
			}			
		}

		impl X509PrivateKey for $name {
			fn export_pubkey(&self) -> Result<Asn1X509Pubkey,Box<dyn Error>> {
				let mut retv :Asn1X509Pubkey = Asn1X509Pubkey::init_asn1();
				let mut algo :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut retelem :Asn1X509PubkeyElem = Asn1X509PubkeyElem::init_asn1();
				algo.set_algorithm(OID_RSA_ENCRYPTION)?;
				algo.set_param_null()?;
				retelem.algor.elem.val.push(algo);

				let pubkelem :Asn1RsaPubkeyElem = self.privkey.export_public()?;
				let mut pubk :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
				pubk.elem.val.push(pubkelem);
				retelem.public_key.data = pubk.encode_asn1()?;
				/*now to set for the pub data*/

				retv.elem.val.push(retelem);
				Ok(retv)
			}

			fn export_signature_algo(&self) -> Result<Asn1X509Algor,Box<dyn Error>> {
				let mut retelem :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				retelem.set_algorithm(&self.sigature_oid)?;
				retelem.set_param_null()?;
				let mut retv :Asn1X509Algor = Asn1X509Algor::init_asn1();
				retv.elem.val.push(retelem);
				Ok(retv)
			}
		}


		expand_priv_sign_op!{$name,$hashtype,stringify!($name)}
		expand_priv_vfy_op!{$name,$hashtype,stringify!($name)}
	}
}


decl_rsa_priv!{RsaMD5priv,Md5,OID_MD5_WITH_RSA_ENCRYPTION}
decl_rsa_priv!{RsaSHA1priv,Sha1,OID_SHA1_WITH_RSA_ENCRYPTION}
decl_rsa_priv!{RsaSHA224priv,Sha224,OID_SHA224_WITH_RSA_ENCRYPTION}
decl_rsa_priv!{RsaSHA256priv,Sha256,OID_SHA256_WITH_RSA_ENCRYPTION}
decl_rsa_priv!{RsaSHA384priv,Sha384,OID_SHA384_WITH_RSA_ENCRYPTION}
decl_rsa_priv!{RsaSHA512priv,Sha512,OID_SHA512_WITH_RSA_ENCRYPTION}

macro_rules! decl_pub_vfy {
	($name:ident,$hashtype:ident,$clsname:expr) => {
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
				ssllib_buffer_trace!(origdata.as_ptr(),origdata.len(),"{} indata vfy",$clsname);
				ssllib_buffer_trace!(signdata.as_ptr(),signdata.len(),"{} signdata vfy",$clsname);
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
	($name:ident,$hashtype:ident,$oid:ident) => {
		pub struct $name {
			pubkey :Asn1RsaPubkeyElem,
			vfyinited :bool,
			signature_oid :String,
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
					ssllib_new_error!{SslAsn1RsaError,"{} not valid rsa private {:?}",stringify!($name),ores.err().unwrap()}
				}
				let po = ores.unwrap();
				let nb :rsaBigUint = po.n().clone();
				let eb :rsaBigUint = po.e().clone();
				pubkey.n.val = BigUint::from_bytes_be(&nb.to_bytes_be());
				pubkey.e.val = BigUint::from_bytes_be(&eb.to_bytes_be());
				let retv :Self = Self {
					pubkey :pubkey.clone(),
					vfyinited : false,
					signature_oid: format!("{}",$oid),
				};
				Ok(retv)
			}

			pub fn new_from_pub(pubkey :&Asn1RsaPubkey) -> Result<Self,Box<dyn Error>> {
				pubkey.elem.check_safe_one("Asn1RsaPubkeyElem")?;
				let retv :Self = Self {
					pubkey : pubkey.elem.val[0].clone(),
					vfyinited : false,
					signature_oid : format!("{}",$oid),
				};
				Ok(retv)
			}
		}

		impl X509PublicKey for $name {
			fn export_pubkey(&self) -> Result<Asn1X509Pubkey,Box<dyn Error>> {
				let mut retv :Asn1X509Pubkey = Asn1X509Pubkey::init_asn1();
				let mut algo :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut retelem :Asn1X509PubkeyElem = Asn1X509PubkeyElem::init_asn1();
				algo.set_algorithm(OID_RSA_ENCRYPTION)?;
				algo.set_param_null()?;
				retelem.algor.elem.val.push(algo);

				let mut pubk :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
				pubk.elem.val.push(self.pubkey.clone());
				retelem.public_key.data = pubk.encode_asn1()?;
				/*now to set for the pub data*/

				retv.elem.val.push(retelem);
				Ok(retv)
			}

			fn export_signature_algo(&self) -> Result<Asn1X509Algor,Box<dyn Error>> {
				let mut retelem :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				retelem.set_algorithm(&self.signature_oid)?;
				retelem.set_param_null()?;
				let mut retv :Asn1X509Algor = Asn1X509Algor::init_asn1();
				retv.elem.val.push(retelem);
				Ok(retv)
			}

		}


		decl_pub_vfy!{$name,$hashtype,stringify!($name)}
	}
}


decl_rsa_pub!{RsaMD5pub,Md5,OID_MD5_WITH_RSA_ENCRYPTION}
decl_rsa_pub!{RsaSHA1pub,Sha1,OID_SHA1_WITH_RSA_ENCRYPTION}
decl_rsa_pub!{RsaSHA224pub,Sha224,OID_SHA224_WITH_RSA_ENCRYPTION}
decl_rsa_pub!{RsaSHA256pub,Sha256,OID_SHA256_WITH_RSA_ENCRYPTION}
decl_rsa_pub!{RsaSHA384pub,Sha384,OID_SHA384_WITH_RSA_ENCRYPTION}
decl_rsa_pub!{RsaSHA512pub,Sha512,OID_SHA512_WITH_RSA_ENCRYPTION}

fn get_max_bits(cb :&[u8]) -> usize {
	let mut retv :usize = cb.len() * 8;
	let mut idx :usize = 0;
	let mut jdx :usize;

	while idx < cb.len() {
		if cb[idx] != 0 {
			jdx = 7;
			loop {
				if (cb[idx] & (1 << jdx)) != 0 {
					break;
				}
				if jdx == 0 {
					break;
				}
				retv -= 1;
				jdx -= 1;
			}
			break;
		}
		idx += 1;
		retv -= 8;
	}

	return retv;
}

macro_rules! expand_rsa_pss_struct {
	($name:ident) => {
		pub struct $name {
			privkey :Asn1RsaPrivateKeyElem,
			signinited : bool,
			vfyinited : bool,
			saltlen : usize,
			signature_oid:String,
		}

	}
}

macro_rules! expand_rsa_pss_impl {
	($name:ident,$clsname:expr,$hashtype:ident,$oid:ident) => {
		impl $name {
			pub fn new(privkey :&Asn1RsaPrivateKey,len :usize) -> Result<Self,Box<dyn Error>> {
				privkey.elem.check_safe_one("Asn1RsaPrivateKeyElem")?;
				let mut saltlen :usize = len;
				if saltlen == PSS_LENGTH_TO_HASHSIZE {
					saltlen = $hashtype::output_size();
				} else if saltlen == PSS_LENGTH_TO_AUTOSIZE {
					let n = rsaBigUint::from_bytes_be(&privkey.elem.val[0].modulus.val.to_bytes_be());
					let d = rsaBigUint::from_bytes_be(&privkey.elem.val[0].pubexp.val.to_bytes_be());
					let e = rsaBigUint::from_bytes_be(&privkey.elem.val[0].privexp.val.to_bytes_be());
					let mut primes :Vec<rsaBigUint> = Vec::new();
					primes.push(rsaBigUint::from_bytes_be(&privkey.elem.val[0].prime1.val.to_bytes_be()));
					primes.push(rsaBigUint::from_bytes_be(&privkey.elem.val[0].prime2.val.to_bytes_be()));
					let ores = RsaPrivateKey::from_components(n,d,e,primes);
					if ores.is_err() {
						ssllib_new_error!{SslAsn1RsaError,"{} not valid RsaPrivateKey",$clsname}
					}
					let po = ores.unwrap();
					let pubk = po.to_public_key();
					let nbytes :Vec<u8> = pubk.n().to_bytes_be().clone();
					saltlen = ((get_max_bits(&nbytes) - 1 + 7) >> 3) - 2 - $hashtype::output_size();
				}
				ssllib_log_trace!("saltlen {}",saltlen);
				let retv :Self = Self {
					privkey : privkey.elem.val[0].clone(),
					signinited : false,
					vfyinited : false,
					saltlen : saltlen,
					signature_oid : format!("{}",$oid),
				};
				Ok(retv)
			}
		}

		impl X509PrivateKey for $name {
			fn export_pubkey(&self) -> Result<Asn1X509Pubkey,Box<dyn Error>> {
				let mut retv :Asn1X509Pubkey = Asn1X509Pubkey::init_asn1();
				let mut algo :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut retelem :Asn1X509PubkeyElem = Asn1X509PubkeyElem::init_asn1();
				algo.set_algorithm(OID_RSA_ENCRYPTION)?;
				algo.set_param_null()?;
				retelem.algor.elem.val.push(algo);

				let pubkelem :Asn1RsaPubkeyElem = self.privkey.export_public()?;
				let mut pubk :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
				pubk.elem.val.push(pubkelem);
				retelem.public_key.data = pubk.encode_asn1()?;
				/*now to set for the pub data*/

				retv.elem.val.push(retelem);
				Ok(retv)
			}

			fn export_signature_algo(&self) -> Result<Asn1X509Algor,Box<dyn Error>> {
				let mut retv :Asn1X509Algor = Asn1X509Algor::init_asn1();
				let mut pssinfo :RsaPssSigInfo = RsaPssSigInfo::init_asn1();
				let mut psselem :RsaPssSigInfoElem = RsaPssSigInfoElem::init_asn1();
				let mut algo :Asn1X509Algor = Asn1X509Algor::init_asn1();
				let mut algoelem :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut naglo :Asn1X509Algor = Asn1X509Algor::init_asn1();
				let mut nalgoelem :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut cany :Asn1Any = Asn1Any::init_asn1();
				let mut code :Vec<u8>;
				algoelem.set_algorithm(&self.signature_oid)?;
				algoelem.set_param_null()?;
				algo.elem.val.push(algoelem.clone());
				let mut impsetalgo :Asn1ImpSet<Asn1X509Algor,0> = Asn1ImpSet::init_asn1();
				impsetalgo.val.push(algo.clone());
				psselem.algo.val = Some(impsetalgo);

				algoelem = Asn1X509AlgorElem::init_asn1();
				algo = Asn1X509Algor::init_asn1();
				algoelem.set_algorithm(OID_RSA_MGF1)?;
				nalgoelem.set_algorithm(&self.signature_oid)?;
				nalgoelem.set_param_null()?;
				naglo.elem.val.push(nalgoelem.clone());
				code = naglo.encode_asn1()?;
				cany.decode_asn1(&code)?;
				algoelem.set_param(Some(cany.clone()))?;
				algo.elem.val.push(algoelem.clone());
				let mut impsetcmplx :Asn1ImpSet<Asn1X509Algor,1> = Asn1ImpSet::init_asn1();
				impsetcmplx.val.push(algo.clone());
				psselem.cmplx.val = Some(impsetcmplx);

				let mut xinter :Asn1Integer = Asn1Integer::init_asn1();
				xinter.val = $hashtype::output_size() as i64;
				let mut impsetsize :Asn1ImpSet<Asn1Integer,2> = Asn1ImpSet::init_asn1();
				impsetsize.val.push(xinter.clone());
				psselem.saltlen.val = Some(impsetsize);

				pssinfo.elem.val.push(psselem);

				algoelem = Asn1X509AlgorElem::init_asn1();
				algoelem.set_algorithm(OID_RSA_PSS)?;
				code = pssinfo.encode_asn1()?;
				cany.decode_asn1(&code)?;
				algoelem.set_param(Some(cany.clone()))?;
				retv.elem.val.push(algoelem.clone());
				Ok(retv)
			}

		}

	}
}

macro_rules! expand_rsa_pss_sign {
	($name:ident,$hashtype:ident,$clsname:expr) => {
		impl Asn1SignOp for $name {
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
				let psskey :rsa::pss::Pss = rsa::pss::Pss::new_blinded_with_salt::<$hashtype>(self.saltlen);
				//let psskey :rsa::pss::Pss = rsa::pss::Pss::new_with_salt::<sha2::Sha256>(self.saltlen);
				let mut hasher = $hashtype::new();
				hasher.update(data);
				let hashdata = hasher.finalize().to_vec();
				//let hashdata = data.to_vec().clone();
				let mut gencore  = rand::thread_rng();
				let putn = Some(&mut gencore);
				ssllib_buffer_trace!(data.as_ptr(),data.len(),"{} indata sign",$clsname);
				ssllib_buffer_trace!(hashdata.as_ptr(),hashdata.len(),"{} hashdata sign",$clsname);
				let ores = psskey.sign::<rand::rngs::ThreadRng>(putn,&po,&hashdata);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} sign error {:?}",$clsname, ores.err().unwrap()}
				}
				retv= ores.unwrap();
				ssllib_buffer_trace!(retv.as_ptr(),retv.len(),"{} signdata sign",$clsname);
				Ok(retv)
			}
		}		
	}
}

macro_rules! expand_rsa_pss_verify {
	($name :ident,$hashtype:ident,$clsname:expr) => {
		impl Asn1VerifyOp for $name {
			fn verify_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
				self.vfyinited = true;
				Ok(())
			}
			fn verify_exec(&mut self,origdata:&[u8],signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
				let retv :bool;
				if !self.vfyinited {
					ssllib_new_error!{SslAsn1RsaError,"{} not inited verify",$clsname}
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
				let psskey :rsa::pss::Pss = rsa::pss::Pss::new_blinded_with_salt::<$hashtype>(self.saltlen);
				//let psskey :rsa::pss::Pss = rsa::pss::Pss::new_with_salt::<sha2::Sha256>(self.saltlen);
				let mut hasher = $hashtype::new();
				hasher.update(origdata);
				let hashdata = hasher.finalize().to_vec();
				//let hashdata = origdata.to_vec().clone();
				ssllib_buffer_trace!(origdata.as_ptr(),origdata.len(),"{} indata vfy",$clsname);
				ssllib_buffer_trace!(signdata.as_ptr(),signdata.len(),"{} signdata vfy",$clsname);
				ssllib_buffer_trace!(hashdata.as_ptr(),hashdata.len(),"{} hashdata vfy",$clsname);
				let ores =  psskey.verify(&pubk,&hashdata,signdata);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} verify failed {:?}",$clsname,ores.err().unwrap()}
				}
				retv = true;
				Ok(retv)
			}
		}		
	}
}


macro_rules! expand_rsa_pss_priv {
	($name :ident, $hashtype :ident,$oid:ident) => {

		expand_rsa_pss_struct!{$name}
		expand_rsa_pss_impl!{$name,stringify!($name),$hashtype,$oid}
		expand_rsa_pss_sign!{$name,$hashtype,stringify!($name)}
		expand_rsa_pss_verify!{$name,$hashtype,stringify!($name)}

	}
}

expand_rsa_pss_priv!{RsaPSSMD5priv,Md5,OID_MD5_DIGEST}
expand_rsa_pss_priv!{RsaPSSSHA1priv,Sha1,OID_SHA1_DIGEST}
expand_rsa_pss_priv!{RsaPSSSHA224priv,Sha224,OID_SHA224_DIGEST}
expand_rsa_pss_priv!{RsaPSSSHA256priv,Sha256,OID_SHA256_DIGEST}
expand_rsa_pss_priv!{RsaPSSSHA384priv,Sha384,OID_SHA384_DIGEST}
expand_rsa_pss_priv!{RsaPSSSHA512priv,Sha512,OID_SHA512_DIGEST}


macro_rules! expand_rsa_pss_pub_struct {
	($name :ident) => {
		pub struct $name {
			pubkey :Asn1RsaPubkeyElem,
			vfyinited :bool,
			saltlen :usize,
			signature_oid:String,
		}
	}
}

macro_rules! expand_rsa_pss_pub_impl {
	($name :ident,$hashtype:ident,$oid:ident) => {
		impl $name {
			pub fn new_from_priv(privkey :&Asn1RsaPrivateKey,len :usize) -> Result<Self,Box<dyn Error>> {
				let pubkey :Asn1RsaPubkey = privkey.export_public()?;
				return Self::new_from_pub(&pubkey,len);
			}

			pub fn new_from_pub(pubkey :&Asn1RsaPubkey,len :usize) -> Result<Self,Box<dyn Error>> {
				pubkey.elem.check_safe_one("Asn1RsaPubkeyElem")?;
				let mut saltlen :usize = len;
				if saltlen == PSS_LENGTH_TO_HASHSIZE {
					saltlen = $hashtype::output_size();
				} else if saltlen == PSS_LENGTH_TO_AUTOSIZE {
					let nb = rsaBigUint::from_bytes_be(&pubkey.elem.val[0].n.val.to_bytes_be());
					let eb = rsaBigUint::from_bytes_be(&pubkey.elem.val[0].e.val.to_bytes_be());

					let pubk = RsaPublicKey::new(nb,eb)?;
					let nbytes :Vec<u8> = pubk.n().to_bytes_be().clone();
					saltlen = ((get_max_bits(&nbytes) - 1 + 7) >> 3) - 2 - $hashtype::output_size();
				}
				ssllib_log_trace!("saltlen {}",saltlen);
				let retv :Self = Self {
					pubkey : pubkey.elem.val[0].clone(),
					vfyinited : false,
					saltlen : saltlen,
					signature_oid : format!("{}",$oid),
				};
				Ok(retv)
			}
		}

		impl X509PublicKey for $name {
			fn export_pubkey(&self) -> Result<Asn1X509Pubkey,Box<dyn Error>> {
				let mut retv :Asn1X509Pubkey = Asn1X509Pubkey::init_asn1();
				let mut algo :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut retelem :Asn1X509PubkeyElem = Asn1X509PubkeyElem::init_asn1();
				algo.set_algorithm(OID_RSA_ENCRYPTION)?;
				algo.set_param_null()?;
				retelem.algor.elem.val.push(algo);

				let mut pubk :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
				pubk.elem.val.push(self.pubkey.clone());
				retelem.public_key.data = pubk.encode_asn1()?;
				/*now to set for the pub data*/

				retv.elem.val.push(retelem);
				Ok(retv)
			}

			fn export_signature_algo(&self) -> Result<Asn1X509Algor,Box<dyn Error>> {
				let mut retv :Asn1X509Algor = Asn1X509Algor::init_asn1();
				let mut pssinfo :RsaPssSigInfo = RsaPssSigInfo::init_asn1();
				let mut psselem :RsaPssSigInfoElem = RsaPssSigInfoElem::init_asn1();
				let mut algo :Asn1X509Algor = Asn1X509Algor::init_asn1();
				let mut algoelem :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut naglo :Asn1X509Algor = Asn1X509Algor::init_asn1();
				let mut nalgoelem :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
				let mut cany :Asn1Any = Asn1Any::init_asn1();
				let mut code :Vec<u8>;
				algoelem.set_algorithm(&self.signature_oid)?;
				algoelem.set_param_null()?;
				algo.elem.val.push(algoelem.clone());
				let mut impsetalgo :Asn1ImpSet<Asn1X509Algor,0> = Asn1ImpSet::init_asn1();
				impsetalgo.val.push(algo.clone());
				psselem.algo.val = Some(impsetalgo);

				algoelem = Asn1X509AlgorElem::init_asn1();
				algo = Asn1X509Algor::init_asn1();
				algoelem.set_algorithm(OID_RSA_MGF1)?;
				nalgoelem.set_algorithm(&self.signature_oid)?;
				nalgoelem.set_param_null()?;
				naglo.elem.val.push(nalgoelem.clone());
				code = naglo.encode_asn1()?;
				cany.decode_asn1(&code)?;
				algoelem.set_param(Some(cany.clone()))?;
				algo.elem.val.push(algoelem.clone());
				let mut impsetcmplx :Asn1ImpSet<Asn1X509Algor,1> = Asn1ImpSet::init_asn1();
				impsetcmplx.val.push(algo.clone());
				psselem.cmplx.val = Some(impsetcmplx);

				let mut xinter :Asn1Integer = Asn1Integer::init_asn1();
				xinter.val = $hashtype::output_size() as i64;
				let mut impsetsize :Asn1ImpSet<Asn1Integer,2> = Asn1ImpSet::init_asn1();
				impsetsize.val.push(xinter.clone());
				psselem.saltlen.val = Some(impsetsize);

				pssinfo.elem.val.push(psselem);

				algoelem = Asn1X509AlgorElem::init_asn1();
				algoelem.set_algorithm(OID_RSA_PSS)?;
				code = pssinfo.encode_asn1()?;
				cany.decode_asn1(&code)?;
				algoelem.set_param(Some(cany.clone()))?;
				retv.elem.val.push(algoelem.clone());
				Ok(retv)
			}

		}


	}
}

macro_rules! expand_rsa_pss_pub_verify {
	($name:ident,$hashtype:ident) => {
		impl Asn1VerifyOp for $name {
			fn verify_init(&mut self,_key :&[u8],_initv :&[u8]) -> Result<(),Box<dyn Error>> {
				self.vfyinited = true;
				Ok(())
			}
			fn verify_exec(&mut self,origdata:&[u8],signdata :&[u8]) -> Result<bool,Box<dyn Error>> {
				let retv :bool;
				if !self.vfyinited {
					ssllib_new_error!{SslAsn1RsaError,"{} not inited verify",stringify!($name)}
				}
				let nb = rsaBigUint::from_bytes_be(&self.pubkey.n.val.to_bytes_be());
				let eb = rsaBigUint::from_bytes_be(&self.pubkey.e.val.to_bytes_be());

				let pubk = RsaPublicKey::new(nb,eb)?;
				let psskey :rsa::pss::Pss = rsa::pss::Pss::new_blinded_with_salt::<$hashtype>(self.saltlen);
				let mut hasher = $hashtype::new();
				hasher.update(origdata);
				let hashdata = hasher.finalize().to_vec();
				ssllib_buffer_trace!(origdata.as_ptr(),origdata.len(),"{} indata vfy",stringify!($name));
				ssllib_buffer_trace!(hashdata.as_ptr(),hashdata.len(),"{} hashdata vfy",stringify!($name));
				ssllib_buffer_trace!(signdata.as_ptr(),signdata.len(),"{} signdata vfy",stringify!($name));
				let ores =  psskey.verify(&pubk,&hashdata,signdata);
				if ores.is_err() {
					ssllib_new_error!{SslAsn1RsaError,"{} verify failed {:?}",stringify!($name),ores.err().unwrap()}
				}
				retv = true;
				Ok(retv)
			}
		}		
	}
}


macro_rules! expand_rsa_pss_pub {
	($name:ident,$hashtype:ident,$oid:ident) => {
		expand_rsa_pss_pub_struct!{$name}
		expand_rsa_pss_pub_impl!{$name,$hashtype,$oid}
		expand_rsa_pss_pub_verify!{$name,$hashtype}
	}
}

expand_rsa_pss_pub!{RsaPSSMD5pub,Md5,OID_MD5_DIGEST}
expand_rsa_pss_pub!{RsaPSSSHA1pub,Sha1,OID_SHA1_DIGEST}
expand_rsa_pss_pub!{RsaPSSSHA224pub,Sha224,OID_SHA224_DIGEST}
expand_rsa_pss_pub!{RsaPSSSHA256pub,Sha256,OID_SHA256_DIGEST}
expand_rsa_pss_pub!{RsaPSSSHA384pub,Sha384,OID_SHA384_DIGEST}
expand_rsa_pss_pub!{RsaPSSSHA512pub,Sha512,OID_SHA512_DIGEST}

pub fn get_rsa_x509_privkey(privkey :&Asn1RsaPrivateKey,digesttype :&str,usaltsize :usize) -> Result<Box<dyn X509PrivateKey>,Box<dyn Error>> {
	if digesttype == RSA_DIGEST_MD5 {
		return Ok(Box::new(RsaMD5priv::new_from_priv(privkey)?));
	} else if digesttype == RSA_DIGEST_SHA1 {
		return Ok(Box::new(RsaSHA1priv::new_from_priv(privkey)?));
	} else if digesttype == RSA_DIGEST_SHA224 {
		return Ok(Box::new(RsaSHA224priv::new_from_priv(privkey)?));
	} else if digesttype == RSA_DIGEST_SHA256 {
		return Ok(Box::new(RsaSHA256priv::new_from_priv(privkey)?));
	} else if digesttype == RSA_DIGEST_SHA384 {
		return Ok(Box::new(RsaSHA384priv::new_from_priv(privkey)?));
	} else if digesttype == RSA_DIGEST_SHA512 {
		return Ok(Box::new(RsaSHA512priv::new_from_priv(privkey)?));
	} else if digesttype == RSA_PSS_DIGEST_MD5 {
		return Ok(Box::new(RsaPSSMD5priv::new(privkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA1 {
		return Ok(Box::new(RsaPSSSHA1priv::new(privkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA224 {
		return Ok(Box::new(RsaPSSSHA224priv::new(privkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA256 {
		return Ok(Box::new(RsaPSSSHA256priv::new(privkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA384 {
		return Ok(Box::new(RsaPSSSHA384priv::new(privkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA512 {
		return Ok(Box::new(RsaPSSSHA512priv::new(privkey,usaltsize)?));
	}
	ssllib_new_error!{SslAsn1RsaError,"can not find key for digest type {}",digesttype}
}

pub fn get_rsa_x509_pubkey(pubkey :&Asn1RsaPubkey,digesttype :&str,usaltsize :usize) -> Result<Box<dyn X509PublicKey>,Box<dyn Error>> {
	if digesttype == RSA_DIGEST_MD5 {
		return Ok(Box::new(RsaMD5pub::new_from_pub(pubkey)?));
	} else if digesttype == RSA_DIGEST_SHA1 {
		return Ok(Box::new(RsaSHA1pub::new_from_pub(pubkey)?));
	} else if digesttype == RSA_DIGEST_SHA224 {
		return Ok(Box::new(RsaSHA224pub::new_from_pub(pubkey)?));
	} else if digesttype == RSA_DIGEST_SHA256 {
		return Ok(Box::new(RsaSHA256pub::new_from_pub(pubkey)?));
	} else if digesttype == RSA_DIGEST_SHA384 {
		return Ok(Box::new(RsaSHA384pub::new_from_pub(pubkey)?));
	} else if digesttype == RSA_DIGEST_SHA512 {
		return Ok(Box::new(RsaSHA512pub::new_from_pub(pubkey)?));
	} else if digesttype == RSA_PSS_DIGEST_MD5 {
		return Ok(Box::new(RsaPSSMD5pub::new_from_pub(pubkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA1 {
		return Ok(Box::new(RsaPSSSHA1pub::new_from_pub(pubkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA224 {
		return Ok(Box::new(RsaPSSSHA224pub::new_from_pub(pubkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA256 {
		return Ok(Box::new(RsaPSSSHA256pub::new_from_pub(pubkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA384 {
		return Ok(Box::new(RsaPSSSHA384pub::new_from_pub(pubkey,usaltsize)?));
	} else if digesttype == RSA_PSS_DIGEST_SHA512 {
		return Ok(Box::new(RsaPSSSHA512pub::new_from_pub(pubkey,usaltsize)?));
	}
	ssllib_new_error!{SslAsn1RsaError,"can not find key for digest type {}",digesttype}
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