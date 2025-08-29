#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use asn1obj::*;
use asn1obj::consts::*;

use std::error::Error;
use std::io::{Write};

use num_bigint::{BigInt,Sign};
use num_traits::{zero};

use crate::{ssllib_new_error,ssllib_error_class};
#[allow(unused_imports)]
use crate::{ssllib_buffer_trace,ssllib_buffer_error,ssllib_format_buffer_log,ssllib_log_trace};
//use crate::rsa::*;
use crate::consts::*;
use crate::digest::*;
use crate::impls::*;
use crate::randop::*;
use crate::encde::*;
#[allow(unused_imports)]
use chrono::{Utc,Datelike,DateTime};
#[allow(unused_imports)]
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};
use crate::config::ConfigValue;
use crate::x509build::*;
use ecsimple::keys::{ECPrivateKey,ECPublicKey};
use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;
use crate::serde_obj::*;



ssllib_error_class!{SslX509Error}




#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509PubkeyElem {
	pub algor : Asn1X509Algor,
	pub public_key :Asn1BitDataFlag,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Pubkey {
	pub elem :Asn1Seq<Asn1X509PubkeyElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509NameElement {
	pub obj : Asn1Object,
	pub name :Asn1PrintableString,
}

impl Asn1X509NameElement {
	pub fn format_name(&self) -> String {
		let rets :String;
		rets = format!("{}:{}",self.obj.get_value(),self.name.val);
		return rets;
	}
}


#[asn1_sequence()]
#[derive(Clone,Serialize,Deserialize)]
pub struct Asn1X509NameAnyElement {
	#[serde(serialize_with = "asn1_object_serialize", deserialize_with = "asn1_object_deserialize")]
	pub obj :Asn1Object,
	#[serde(serialize_with = "asn1_any_serialize" , deserialize_with = "asn1_any_deserialize")]
	pub value :Asn1Any,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509NameEntry {
	pub names : Asn1Set<Asn1Seq<Asn1X509NameElement>>,
}


impl Asn1X509NameEntry {
	pub fn get_names(&self) -> Vec<String>{
		let mut retn :Vec<String> = Vec::new();
		for v in self.names.val.iter() {
			for bv in v.val.iter() {
				retn.push(bv.format_name());
			}
		}
		return retn;
	}
}


macro_rules! ent_to_pkixname {
	($ent :expr,$pkix:expr) => {
		if $ent.names.val.len() > 0 {
			let mut _idx :usize = 0;
			let mut _jdx :usize;
			while _idx < $ent.names.val.len() {
				if $ent.names.val[_idx].val.len() > 0 {
					_jdx = 0;
					while _jdx < $ent.names.val[_idx].val.len() {
						let _curname:Asn1X509NameElement =$ent.names.val[_idx].val[_jdx].clone();
						let _coid :String = _curname.obj.get_value();

						if _coid == OID_COUNTRY {
							append_name(&mut ($pkix.country), &_curname)?;
						} else if _coid == OID_PROVINCE {
							append_name(&mut ($pkix.province), &_curname)?;
						} else if _coid == OID_STREET_ADDRESS {
							append_name(&mut ($pkix.street_address),&_curname)?;
						} else if _coid == OID_POSTAL_CODE {
							append_name(&mut ($pkix.postal_code), &_curname)?;
						} else if _coid == OID_ORGANIZATION {
							append_name(&mut ($pkix.organization), &_curname)?;
						} else if _coid == OID_ORGANIZATIONAL_UNIT {
							append_name(&mut ($pkix.organizational_unit),&_curname)?;
						} else if _coid == OID_SERIAL_NUMBER {
							append_name(&mut ($pkix.serial_number),&_curname)?;
						} else if _coid == OID_COMMON_NAME {
							append_name(&mut ($pkix.common_name), &_curname)?;
						} else if _coid == OID_LOCALITY {
							append_name(&mut ($pkix.locality), &_curname)?;
						} else {
							append_extranames(&mut ($pkix.extra_names), &_curname)?;
						}

						_jdx += 1;
					}
				}

				_idx += 1;
			}
		}
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Name {
	pub entries : Asn1Seq<Asn1X509NameEntry>,
}

impl Asn1X509Name {
	pub fn to_pkixname(&self) -> Result<PkixName,Box<dyn Error>> {
		let mut retv :PkixName = PkixName::new();
		let mut idx :usize = 0;

		while idx < self.entries.val.len() {
			let ent :Asn1X509NameEntry = self.entries.val[idx].clone();
			ent_to_pkixname!(ent,retv);
			idx += 1;
		}

		Ok(retv)
	}
}

impl  PartialEq for Asn1X509Name {

	fn ne(&self,other :&Self) -> bool {
		let snames :Vec<String>;
		let onames :Vec<String>;
		let mut bmatched :bool;

		if self.entries.val.len() == 0 && other.entries.val.len() == 0 {
			return false;
		} else if self.entries.val.len() == 0 {
			return true;
		} else if other.entries.val.len() == 0 {
			return true;
		} else {
			snames = self.entries.val[0].get_names();
			onames = other.entries.val[0].get_names();
			if snames.len() == 0 && onames.len() == 0 {
				return false;
			} else if snames.len() == 0 {
				return true;
			} else if onames.len() == 0 {
				return true;
			}
			for i in 0..snames.len() {
				bmatched = false;
				for j in 0..onames.len() {
					if snames[i].eq(&(onames[j])) {
						bmatched = true;
						break;
					}
				}

				if !bmatched {
					return true;
				}
			}

			for j in 0..onames.len() {
				bmatched = false;
				for i in 0..snames.len() {
					if onames[j].eq(&snames[i]) {
						bmatched = true;
						break;
					}
				}
				if !bmatched {
					return true;
				}
			}
		}
		return false;
	}

	fn eq(&self, other :&Self) -> bool {
		if self.ne(other) {
			return false;
		}
		return true;
	}

}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AttributeElem {
	pub object :Asn1Object,
	pub set :Asn1Set<Asn1Any>,
}




impl Asn1X509AttributeElem {
	pub fn set_attr(&mut self, objval :&str, code :&[u8]) -> Result<(),Box<dyn Error>> {
		self.object.set_value(objval)?;
		let mut oany :Asn1Any = Asn1Any::init_asn1();
		oany.decode_asn1(code)?;
		if self.set.val.len() < 1 {
			self.set.val.push(oany);
		} else {
			self.set.val[0] = oany.clone();
		}
		Ok(())
	}

	pub fn extract_req_infos(&self,reqcfg :&mut X509RequestBuildConfig) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		let oid = self.object.get_value();
		if oid == OID_X509_REQ_EXTENSIONS {
			let mut idx :usize = 0;
			ssllib_log_trace!("set.val.len {}",self.set.val.len());
			while idx < self.set.val.len() {
				let mut algo :Asn1X509Algor = Asn1X509Algor::init_asn1();
				ssllib_buffer_trace!(self.set.val[idx].content.as_ptr(),self.set.val[idx].content.len(),"self.set.val[{}].content",idx);
				let mut stepidx :usize = 0;
				while stepidx < self.set.val[idx].content.len() {
					let ores = algo.decode_asn1(&self.set.val[idx].content[stepidx..]);
					if ores.is_ok() {
						stepidx += ores.unwrap();
						let nores = algo.get_algorithm();
						if nores.is_ok() {
							let noid = nores.unwrap();
							ssllib_log_trace!("[{}] oid [{}]",stepidx,noid);
							if noid == OID_EXTENSION_SUBJECT_ALTNAME {
								let cores = algo.get_param();
								if cores.is_ok() {
									let vp :Option<Asn1Any> = cores.unwrap();
									if vp.is_some() {
										let ncode :Vec<u8> = vp.as_ref().unwrap().content.clone();
										let mut cany :Asn1Seq<Asn1Any> = Asn1Seq::init_asn1();
										let mut nidx :usize = 0;

										ssllib_buffer_trace!(ncode.as_ptr(),ncode.len(),"ncode buffer");
										while nidx < ncode.len() {
											let oores = cany.decode_asn1(&ncode[nidx..]);
											if oores.is_ok()  {
												nidx += oores.unwrap();
												ssllib_log_trace!("nidx step {}",nidx);
												let mut jdx :usize = 0;
												ssllib_log_trace!("cany.len {}",cany.val.len());
												while jdx < cany.val.len() {
													ssllib_log_trace!("[{}].tag 0x{:x}", jdx, cany.val[jdx].tag);
													if cany.val[jdx].tag == TAG_EMAILS_ADDRESSES {
														let ccode = cany.val[jdx].encode_asn1()?;
														ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} ccode",jdx);
														let mut cstr :Asn1Imp<Asn1PrintableString,EMAIL_ADDRESS_IMPSET_TAG> = Asn1Imp::init_asn1();
														let nores = cstr.decode_asn1(&ccode);
														if nores.is_ok() {
															ssllib_log_trace!("email_addresses {}",cstr.val.val);
															reqcfg.email_addresses.push(format!("{}",cstr.val.val));
															retv += 1;
														} else {
															ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} Asn1ImpSet error",jdx);
														}
													} else if cany.val[jdx].tag == TAG_DNS_NAMES {
														let ccode = cany.val[jdx].encode_asn1()?;
														ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} ccode",jdx);
														let mut cstr :Asn1Imp<Asn1PrintableString,DNS_NAMES_IMPSET_TAG> = Asn1Imp::init_asn1();
														let nores = cstr.decode_asn1(&ccode);
														if nores.is_ok() {
															ssllib_log_trace!("dns_names {}",cstr.val.val);
															reqcfg.dns_names.push(format!("{}",cstr.val.val));
															retv += 1;
														} else {
															ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} Asn1ImpSet error",jdx);
														}
													} else if cany.val[jdx].tag == TAG_URIS {
														let ccode = cany.val[jdx].encode_asn1()?;
														ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} ccode",jdx);
														let mut cstr :Asn1Imp<Asn1PrintableString,URIS_IMPSET_TAG> = Asn1Imp::init_asn1();
														let nores = cstr.decode_asn1(&ccode);
														if nores.is_ok() {
															ssllib_log_trace!("uris {}",cstr.val.val);
															reqcfg.uris.push(format!("{}",cstr.val.val));
															retv += 1;
														} else {
															ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} Asn1ImpSet error",jdx);
														}
													} else if cany.val[jdx].tag == TAG_IP_ADDRESSES {
														let ccode = cany.val[jdx].encode_asn1()?;
														ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} ccode",jdx);
														let mut cstr :Asn1Imp<Asn1OctData,IP_ADDRESSES_IMPSET_TAG> = Asn1Imp::init_asn1();
														let nores = cstr.decode_asn1(&ccode);
														if nores.is_ok() {
															if cstr.val.data.len() == 4 || cstr.val.data.len() == 16 {
																if cstr.val.data.len() == 4 {
																	let cip4 :Vec<u8> = cstr.val.data.clone();
																	let ipv4addr :std::net::Ipv4Addr = std::net::Ipv4Addr::new(cip4[0],cip4[1],cip4[2],cip4[3]);
																	ssllib_log_trace!("ip_addresses {}",ipv4addr.to_string());
																	reqcfg.ip_addresses.push(format!("{}",ipv4addr.to_string()));
																	retv += 1;
																} else if cstr.val.data.len() == 16 {
																	let mut cip6 :[u16;8] = [0;8];
																	let mut cidx :usize = 0;
																	let mut didx :usize = 0;																
																	while cidx < cstr.val.data.len() {
																		cip6[didx] = cstr.val.data[cidx+1] as u16;
																		cip6[didx] |= (cstr.val.data[cidx] as u16) << 8;
																		didx += 1;
																		cidx += 2;
																	}
																	ssllib_buffer_trace!(cstr.val.data.as_ptr(),cstr.val.data.len(),"{} ip_addresses",jdx);
																	ssllib_buffer_trace!(cip6.as_ptr(),cip6.len(),"{} ip_addresses",jdx);
																	let ipv6addr :std::net::Ipv6Addr = std::net::Ipv6Addr::new(cip6[0],cip6[1],cip6[2],cip6[3],cip6[4],cip6[5],cip6[6],cip6[7]);
																	ssllib_log_trace!("ip_addresses {}",ipv6addr.to_string());
																	reqcfg.ip_addresses.push(format!("{}",ipv6addr.to_string()));
																	retv += 1;
																}															
															} else {
																ssllib_log_trace!("not valid ip_addresses len {}",cstr.val.data.len());
															}

														} else {
															ssllib_buffer_trace!(ccode.as_ptr(),ccode.len(),"{} Asn1ImpSet error",jdx);
														}
													} 
													jdx += 1;
												}
											} else {
												ssllib_buffer_trace!(ncode[nidx..].as_ptr(),ncode[nidx..].len(),"can not decode");
												nidx = ncode.len();
											}	
										}
									}
								}
							}
						}
					} else {
						let mut pkext :Asn1Seq<PkixExtension> = Asn1Seq::init_asn1();
						let ores = pkext.decode_asn1(&self.set.val[idx].content[stepidx..]);
						if ores.is_ok() {
							stepidx += ores.unwrap();
							let mut pkidx :usize = 0;
							while pkidx < pkext.val.len() {
								ssllib_log_trace!("push {} extra_extensions",pkidx);
								retv += 1;
								reqcfg.extra_extensions.push(pkext.val[pkidx].clone());
								pkidx += 1;
							}
						} else {
							ssllib_log_trace!("can not parse on {}" ,stepidx);
							stepidx = self.set.val[idx].content.len();
						}
					}

				}
				idx += 1;
			}
		}
		Ok(retv)		

	}

}
//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Attribute {
	pub elem : Asn1Seq<Asn1X509AttributeElem>,
}

impl Asn1X509Attribute {
	pub fn set_value_with_object(&mut self,objval :&Asn1Object,setval :&Asn1Any) -> Result<bool,Box<dyn Error>> {
		let mut retv :bool = false;
		if self.elem.val.len() != 0 && self.elem.val.len()!=1 {
			ssllib_new_error!{SslX509Error,"val [{}] != 0 or 1",self.elem.val.len()}
		}
		if self.elem.val.len() != 0 {
			if self.elem.val[0].object.eq(objval) {
				self.elem.val[0].set.val = vec![];
				self.elem.val[0].set.val.push(setval.clone());
				retv= true;
			}
		}
		Ok(retv)
	}

	pub fn new_create_attr(objval :&str,code :&[u8]) -> Result<Asn1X509Attribute, Box<dyn Error>> {
		let mut retv :Asn1X509Attribute = Asn1X509Attribute::init_asn1();
		retv.elem.make_safe_one("Asn1X509AttributeElem")?;
		retv.elem.val[0].set_attr(objval,code)?;
		Ok(retv)
	}

	pub fn extract_req_infos(&self,reqcfg :&mut X509RequestBuildConfig) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		let mut idx :usize = 0;
		if self.elem.val.len() < 1 {
			return Ok(retv);
		}
		while idx <self.elem.val.len() {
			retv += self.elem.val[idx].extract_req_infos(reqcfg)?;
			idx += 1;
		}

		Ok(retv)
	}
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ValElem {
	pub notBefore : Asn1Time,
	pub notAfter : Asn1Time,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Val {
	pub elem : Asn1Seq<Asn1X509ValElem>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AlgorElem {
	pub algorithm : Asn1Object,
	pub parameters : Asn1Opt<Asn1Any>,
}

impl Asn1X509AlgorElem {
	pub fn set_algorithm(&mut self, objname :&str) -> Result<String,Box<dyn Error>> {
		let oval = self.algorithm.set_value(objname)?;
		Ok(oval)
	}

	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		let oval = self.algorithm.get_value();
		Ok(oval)
	}

	pub fn get_param(&self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let mut retv :Option<Asn1Any> = None;
		if self.parameters.val.is_some() {
			retv = Some(self.parameters.val.as_ref().unwrap().clone());
		}
		return Ok(retv)
	}


	pub fn set_param_null(&mut self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let retv = self.get_param()?;
		let mut anyv :Asn1Any = Asn1Any::init_asn1();
		anyv.tag = ASN1_NULL_FLAG as u64;
		self.parameters.val = Some(anyv.clone());
		Ok(retv)
	}


	pub fn set_param(&mut self, val :Option<Asn1Any>) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let retv = self.get_param()?;
		if val.is_none() {
			self.parameters.val = None;
		} else {
			self.parameters.val = Some(val.as_ref().unwrap().clone());
		}		
		Ok(retv)
	}

	pub fn set_algorithm_null(&mut self, objname :&str) -> Result<String,Box<dyn Error>> {
		let oval = self.algorithm.set_value(objname)?;
		let nullo :Asn1Null = Asn1Null::init_asn1();
		let mut anyo :Asn1Any = Asn1Any::init_asn1();
		let code = nullo.encode_asn1()?;
		let _ = anyo.decode_asn1(&code)?;
		self.parameters.val = Some(anyo);
		Ok(oval)
	}
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Algor {
	pub elem : Asn1Seq<Asn1X509AlgorElem>,
}

impl Asn1X509Algor {
	pub fn set_algorithm(&mut self,objname :&str) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].set_algorithm(objname);
	}

	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].get_algorithm();
	}

	pub fn get_param(&self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].get_param();
	}


	pub fn set_param_null(&mut self) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].set_param_null();
	}

	pub fn set_param(&mut self, val :Option<Asn1Any>) -> Result<Option<Asn1Any>,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].set_param(val);
	}

	pub fn set_algorithm_null(&mut self, val :&str) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Algor")?;
		return self.elem.val[0].set_algorithm_null(val);
	}

}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AuxCertElem {
	pub trust : Asn1Opt<Asn1Seq<Asn1Object>>,
	pub reject : Asn1Opt<Asn1Exp<Asn1Seq<Asn1Object>,0>>,
	pub alias :Asn1Opt<Asn1PrintableString>,
	pub keyid :Asn1Opt<Asn1OctData>,
	pub other :Asn1Opt<Asn1Exp<Asn1Seq<Asn1X509Algor>,1>>,
}

impl Asn1X509AuxCertElem {
	pub fn append_trust(&mut self,objs :&str) -> Result<(),Box<dyn Error>> {
		let mut inobj :Asn1Object = Asn1Object::init_asn1();
		let _ = inobj.set_value(objs)?;
		if self.trust.val.is_some() {
			let cp :&mut Asn1Seq<Asn1Object> = self.trust.val.as_mut().unwrap();
			cp.val.push(inobj);
		} else {
			let mut seq :Asn1Seq<Asn1Object> = Asn1Seq::init_asn1();
			seq.val.push(inobj);
			self.trust.val = Some(seq);
		}
		Ok(())
	}

	pub fn append_reject(&mut self, objs :&str) -> Result<(),Box<dyn Error>> {
		let mut inobj :Asn1Object = Asn1Object::init_asn1();
		let _ = inobj.set_value(objs)?;
		if self.reject.val.is_some() {
			let cp :&mut Asn1Exp<Asn1Seq<Asn1Object>,0> = self.reject.val.as_mut().unwrap();
			assert!(cp.val.val.len() == 1);
			cp.val.val.push(inobj);
		} else {
			let mut seq :Asn1Seq<Asn1Object> = Asn1Seq::init_asn1();
			seq.val.push(inobj);
			let mut exp :Asn1Exp<Asn1Seq<Asn1Object>,0> = Asn1Exp::init_asn1();
			exp.val = seq;
			self.reject.val = Some(exp);
		}
		Ok(())
	}

	pub fn set_alias(&mut self, alias :&str) -> Result<(),Box<dyn Error>> {
		let mut prn :Asn1PrintableString = Asn1PrintableString::init_asn1();
		prn.val = format!("{}",alias);
		self.alias.val = Some(prn);
		Ok(())
	}

	pub fn set_keyid(&mut self, keyid :&[u8]) -> Result<(),Box<dyn Error>> {
		if self.keyid.val.is_some() {
			let k :&mut Asn1OctData = self.keyid.val.as_mut().unwrap();
			k.data = keyid.to_vec().clone();
		} else {
			let mut od :Asn1OctData = Asn1OctData::init_asn1();
			od.data = keyid.to_vec().clone();
			self.keyid.val = Some(od);
		}
		Ok(())
	}

	pub fn append_other(&mut self, x :&Asn1X509Algor) -> Result<(),Box<dyn Error>> {
		if self.other.val.is_some() {
			let cp :&mut Asn1Exp<Asn1Seq<Asn1X509Algor>,1> = self.other.val.as_mut().unwrap();
			assert!(cp.val.val.len() == 1);
			cp.val.val.push(x.clone());
		} else {
			let mut seq :Asn1Seq<Asn1X509Algor> = Asn1Seq::init_asn1();
			seq.val.push(x.clone());
			let mut exp :Asn1Exp<Asn1Seq<Asn1X509Algor>,1> = Asn1Exp::init_asn1();
			exp.val = seq;
			self.other.val = Some(exp);
		}
		Ok(())
	}

}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AuxCert {
	pub elem :Asn1Seq<Asn1X509AuxCertElem>,	
}

impl Asn1X509AuxCert {
	pub fn append_trust(&mut self,objs :&str) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("Asn1X509AuxCert")?;
		return self.elem.val[0].append_trust(objs);
	}

	pub fn append_reject(&mut self, objs :&str) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("Asn1X509AuxCert")?;
		return self.elem.val[0].append_reject(objs);
	}

	pub fn set_alias(&mut self, alias :&str) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("Asn1X509AuxCert")?;
		return self.elem.val[0].set_alias(alias);
	}

	pub fn set_keyid(&mut self, keyid :&[u8]) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("Asn1X509AuxCert")?;
		return self.elem.val[0].set_keyid(keyid);		
	}

	pub fn append_other(&mut self, x :&Asn1X509Algor) -> Result<(),Box<dyn Error>> {
		self.elem.make_safe_one("Asn1X509AuxCert")?;
		return self.elem.val[0].append_other(x);
	}
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ExtensionElem {
	pub object :Asn1Object,
	pub critical : Asn1Opt<Asn1Boolean>,
	pub value : Asn1OctData,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Extension {
	pub elem :Asn1Seq<Asn1X509ExtensionElem>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509CinfElem {
	pub version : Asn1Opt<Asn1ImpSet<Asn1Integer,0>>,
	pub serial_number :Asn1BigNum,
	pub signature : Asn1X509Algor,
	pub issuer : Asn1X509Name,
	pub validity : Asn1X509Val,
	pub subject :Asn1X509Name,
	pub key : Asn1X509Pubkey,
	pub issuerUID : Asn1Opt<Asn1Imp<Asn1BitString,1>>,
	pub subjectUID : Asn1Opt<Asn1Imp<Asn1BitString,2>>,
	pub extensions : Asn1Opt<Asn1ImpSet<Asn1Seq<Asn1X509Extension>,3>>,
}

impl Asn1X509CinfElem {
	pub fn match_priv_data(&self,signtype :&str,pktype :&str,privdata:&[u8]) -> Result<bool, Box<dyn Error>> {
		let mut retv :bool = false;
		if pktype == PKCS8_PRIVATE_KEY_TYPE {
			if signtype ==  OID_EC_PUBLICKEY_ENCRYPTION {
				let _ = self.key.elem.check_safe_one("Asn1X509Pubkey")?;
				let ddata = self.key.encode_asn1()?;
				ssllib_buffer_trace!(ddata.as_ptr(),ddata.len(),"encode key");
				let ecpub :ECPublicKey = ECPublicKey::from_der(&ddata)?;
				let privkey :ECPrivateKey = ECPrivateKey::from_der(privdata)?;
				let cmppub :ECPublicKey = privkey.export_pubkey();
				if cmppub == ecpub {
					retv = true;
				}

			}
		}
		return Ok(retv);
	}

	pub fn get_verifier(&self) -> Result<Box<dyn Asn1VerifyOp>,Box<dyn Error>> {
		self.signature.elem.check_safe_one("Asn1X509AlgorElem")?;
		self.key.elem.check_safe_one("Asn1X509PubkeyElem")?;
		return get_x509_verifier_from_asn1(&self.signature.elem.val[0],&self.key.elem.val[0]);
	}
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Cinf {
	pub elem : Asn1Seq<Asn1X509CinfElem>,
}

impl Asn1X509Cinf {
	pub fn match_priv_data(&self,signtype :&str,pktype :&str,privdata:&[u8]) -> Result<bool, Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Cinf")?;
		return self.elem.val[0].match_priv_data(signtype,pktype,privdata);
	}

	pub fn get_verifier(&self) -> Result<Box<dyn Asn1VerifyOp>,Box<dyn Error>> {
		self.elem.check_safe_one("Asn1X509CinfElem")?;
		return self.elem.val[0].get_verifier();
	}
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Revoked {
	pub serialNumber : Asn1Integer,
	pub revocationDate : Asn1Time,
	pub extensions : Asn1Opt<Asn1Seq<Asn1X509Extension>>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509CrlInfo {
	pub version : Asn1Opt<Asn1Integer>,
	pub sig_alg : Asn1X509Algor,
	pub issuer : Asn1X509Name,
	pub lastUpdate : Asn1Time,
	pub nextUpdate :Asn1Time,
	pub revoked : Asn1Opt<Asn1Seq<Asn1X509Revoked>>,
	pub extensions : Asn1Opt<Asn1Seq<Asn1X509Extension>>,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Crl {
	pub crl : Asn1X509CrlInfo,
	pub sig_alg :Asn1X509Algor,
	pub signature : Asn1BitDataFlag,
}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Elem {
	pub cert_info : Asn1X509Cinf,
	pub sig_alg : Asn1X509Algor,
	pub signature : Asn1BitDataFlag,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1BasicConstraintsElem {
	pub isca :Asn1Boolean,
	pub maxlen :Asn1Opt<Asn1Integer>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1BasicConstraints {
	pub elem :Asn1Seq<Asn1BasicConstraintsElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1PermsExcludesElem {
	pub perms :Asn1Opt<Asn1ImpSet<Asn1Seq<Asn1Any>,0>>,
	pub excludes :Asn1Opt<Asn1ImpSet<Asn1Seq<Asn1Any>,1>>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1PermsExcludes {
	pub elem :Asn1Seq<Asn1PermsExcludesElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1AuthorityObjElem {
	pub obj :Asn1Object,
	pub value :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1AuthorityObj {
	pub elem : Asn1Seq<Asn1Seq<Asn1AuthorityObjElem>>,
}




impl Asn1X509Elem {
	pub fn match_priv_data(&self,signtype :&str,pktype :&str,privdata:&[u8]) -> Result<bool, Box<dyn Error>> {
		if pktype == PKCS8_PRIVATE_KEY_TYPE {
			if signtype == OID_EC_PUBLICKEY_ENCRYPTION {				
				/*now check for the certinfo*/
				let _ = self.cert_info.elem.check_safe_one("Asn1X509Cinf")?;
				return self.cert_info.elem.val[0].match_priv_data(signtype,pktype,privdata);
			}
		}
		return Ok(false);
	}

	pub fn self_verify(&self) -> Result<bool, Box<dyn Error>> {
		let retv :bool;
		let mut vfyop :Box<dyn Asn1VerifyOp>;

		/*now first to check for the get the value*/
		vfyop = self.cert_info.get_verifier()?;
		let origdata = self.cert_info.encode_asn1()?;
		let signeddata = self.signature.data.clone();
		retv = vfyop.verify_exec(&origdata,&signeddata)?;
		Ok(retv)
	}

	fn _get_key_usage(&self, extensions :&Asn1Seq<Asn1X509Extension>) -> Result<Vec<KeyUsage>,Box<dyn Error>> {
		let mut retv :Vec<KeyUsage> = vec![];
		let mut idx :usize = 0;
		let mut jdx :usize;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_KEY_USAGE {
						/*now we should get the value*/
						let mut obitdata :Asn1BitData = Asn1BitData::init_asn1();
						let code = curext.value.data.clone();
						obitdata.decode_asn1(&code)?;
						if obitdata.data.len() > 1 {
							if (obitdata.data[1] & KEY_USAGE_DECIPHER_ONLY) != 0 {
								retv.push(KeyUsage::KeyUsageDecipherOnly);
							}
						}

						if obitdata.data.len() > 0 {
							if (obitdata.data[0] & KEY_USAGE_DIGITAL_SIGNATURE) != 0 {
								retv.push(KeyUsage::KeyUsageDigitalSignature);
							}

							if (obitdata.data[0] & KEY_USAGE_CONTENT_COMMITMENT) != 0 {
								retv.push(KeyUsage::KeyUsageContentCommitment);
							}
							if (obitdata.data[0] & KEY_USAGE_KEY_ENCIPHERMENT) != 0 {
								retv.push(KeyUsage::KeyUsageKeyEncipherment);
							}
							if (obitdata.data[0] & KEY_USAGE_DATA_ENCIPHERMENT) != 0 {
								retv.push(KeyUsage::KeyUsageDataEncipherment);
							}
							if (obitdata.data[0] & KEY_USAGE_KEY_AGREEMENT) != 0 {
								retv.push(KeyUsage::KeyUsageKeyAgreement);
							}
							if (obitdata.data[0] & KEY_USAGE_CERT_SIGN) != 0 {
								retv.push(KeyUsage::KeyUsageCertSign);
							}
							if (obitdata.data[0] & KEY_USAGE_CRL_SIGN) != 0 {
								retv.push(KeyUsage::KeyUsageCRLSign);
							}
							if (obitdata.data[0] & KEY_USAGE_ENCIPHER_ONLY) != 0 {
								retv.push(KeyUsage::KeyUsageEncipherOnly);
							}
						}
					}

					jdx += 1;
				}
			}

			idx += 1;
		}


		Ok(retv)
	}

	fn _get_constraints_valid(&self,retv :&mut X509BuildConfig, extensions :&Asn1Seq<Asn1X509Extension>) -> Result<(),Box<dyn Error>> {
		let mut idx :usize = 0;
		let mut jdx :usize;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_CONSTRAINTS_VALID {
						/*now we should get the value*/
						let mut cons :Asn1BasicConstraints = Asn1BasicConstraints::init_asn1();
						let code = curext.value.data.clone();
						cons.decode_asn1(&code)?;
						if cons.elem.val.len() < 1 {
							ssllib_new_error!{SslX509Error,"Basic Constrains not valid"}
						}

						retv.is_ca = cons.elem.val[0].isca.val;
						if cons.elem.val[0].maxlen.val.is_some() {
							retv.max_path_len = cons.elem.val[0].maxlen.val.as_ref().unwrap().val;							
							if retv.max_path_len == 0 {
								retv.max_path_zero = true;
							} else {
								retv.max_path_zero = false;
							}
						} else {
							retv.max_path_len = -1;
							retv.max_path_zero = false;
						}
						
						retv.basic_constraints_valid = true;					
					}

					jdx += 1;
				}
			}

			idx += 1;
		}

		Ok(())
	}

	fn _get_subject_key_id(&self, extensions :&Asn1Seq<Asn1X509Extension>) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = vec![];
		let mut idx :usize = 0;
		let mut jdx :usize;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_SUBJECT_KEY_ID {
						/*now we should get the value*/
						let mut odata :Asn1OctData = Asn1OctData::init_asn1();
						let code = curext.value.data.clone();
						odata.decode_asn1(&code)?;
						retv.extend(odata.data.clone());
					}

					jdx += 1;
				}
			}

			idx += 1;
		}

		Ok(retv)
	}

	fn _get_uris(&self, retv :&mut X509BuildConfig, extensions :&Asn1Seq<Asn1X509Extension>) -> Result<(),Box<dyn Error>> {
		let mut idx :usize = 0;
		let mut jdx :usize;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_URIS {
						/*now we should get the value*/
						let mut oanys :Asn1Seq<Asn1Any> = Asn1Seq::init_asn1();
						let code = curext.value.data.clone();
						oanys.decode_asn1(&code)?;

						let mut kdx :usize = 0;
						let mut data :Vec<u8>;
						while kdx < oanys.val.len() {
							if oanys.val[kdx].tag == TAG_DNS_NAMES {
								/*this is dns*/
								data = oanys.val[kdx].content.clone();
								retv.dns_names.push(format!("{}",String::from_utf8_lossy(&data)));
							} else if oanys.val[kdx].tag == TAG_EMAILS_ADDRESSES {
								data = oanys.val[kdx].content.clone();
								retv.email_addresses.push(format!("{}",String::from_utf8_lossy(&data)));
							} else if oanys.val[kdx].tag == TAG_IP_ADDRESSES {
								data = oanys.val[kdx].content.clone();
								if data.len() == 4 {
									let ipv4 :std::net::Ipv4Addr = std::net::Ipv4Addr::new(data[0],data[1],data[2],data[3]);
									retv.ip_addresses.push(format!("{}",ipv4.to_string()));
								} else if data.len() == 0x10 {
									let mut ndata :[u8;16] = [0;16];
									let mut ldx :usize = 0;
									while ldx < 16 {
										ndata[ldx] = data[ldx];
										ldx += 1;
									}
									let ipv6 :std::net::Ipv6Addr = std::net::Ipv6Addr::from(ndata);
									retv.ip_addresses.push(format!("{}",ipv6.to_string()));
								} else {
									ssllib_new_error!{SslX509Error,"not valid ip address len {}", data.len()}
								}
							} else if oanys.val[kdx].tag == TAG_URIS {
								data = oanys.val[kdx].content.clone();
								retv.uris.push(format!("{}",String::from_utf8_lossy(&data)));
							}

							kdx += 1;
						}
					}
					jdx += 1;
				}
			}

			idx += 1;
		}

		Ok(())
	}

	fn _get_perm_exs(&self, retv :&mut X509BuildConfig, extensions :&Asn1Seq<Asn1X509Extension>) -> Result<(),Box<dyn Error>> {
		let mut idx :usize = 0;
		let mut jdx :usize;

		let mut data :Vec<u8>;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_PERM_EX {
						ssllib_log_trace!("OID_PERM_EX {}", OID_PERM_EX);
						/*now we should get the value*/
						let mut permexs :Asn1PermsExcludes = Asn1PermsExcludes::init_asn1();
						let code = curext.value.data.clone();
						ssllib_buffer_trace!(code.as_ptr(),code.len(), "code extract");
						permexs.decode_asn1(&code)?;
						if permexs.elem.val.len() > 0 {
							let mut ldx :usize = 0;
							while ldx < permexs.elem.val.len() {
								ssllib_log_trace!("ldx[{}] len {}", ldx,permexs.elem.val.len());
								if permexs.elem.val[ldx].perms.val.is_some() {
									let impperms :Asn1ImpSet<Asn1Seq<Asn1Any>,0> = permexs.elem.val[ldx].perms.val.as_ref().unwrap().clone();
									ssllib_log_trace!("impperms.len {}",impperms.val.len());
									if impperms.val.len() > 0 {
										let mut ccidx :usize = 0;
										while ccidx < impperms.val.len() {
											let seqperms :Asn1Seq<Asn1Any> = impperms.val[ccidx].clone();
											let mut oidx :usize = 0;
											while oidx < seqperms.val.len()  {
												let curany :Asn1Any = seqperms.val[oidx].clone();
												ssllib_log_trace!("oidx[{}].{} tag 0x{:x}",oidx,seqperms.val.len(), curany.tag);		
												if curany.tag == TAG_DNS_NAMES {
													data = curany.content.clone();
													retv.perm_dns_names.push(format!("{}",String::from_utf8_lossy(&data)));
												} else if curany.tag == TAG_IP_ADDRESSES {
													data = curany.content.clone();
													if data.len() == (4 * 2) {
														let mut s :String = "".to_string();
														let mut adx :usize = 0;
														while adx < 4 {
															if adx > 0 {
																s.push_str(".");
															}
															s.push_str(&format!("{}",data[adx]));
															adx += 1;
														}

														let mut bits :usize = 0;
														let mut bdx :i32;
														let mut stopc :bool = false;
														adx = 0;
														while adx < 4 {
															bdx = 7 ;
															while bdx >= 0 {
																if (data[4+adx] & (1 << bdx) as u8) == 0 {
																	stopc = true;
																	break;
																}
																bits += 1;
																bdx -= 1;
															}

															if stopc {
																break;
															}
															adx += 1;
														}

														s.push_str(&format!("/{}", bits));
														retv.perm_ip_ranges.push(format!("{}",s));
													} else if data.len() == (0x10 * 2) {
														let mut ndata :[u8;16] = [0;16];
														let mut adx :usize = 0;
														while adx < 16 {
															ndata[adx] = data[adx];
															adx += 1;
														}
														let ipv6 :std::net::Ipv6Addr = std::net::Ipv6Addr::from(ndata);
														let mut outs :String = format!("{}",ipv6.to_string());
														let mut bits :usize = 0;
														let mut bdx :i32;
														let mut stopc :bool = false;
														adx = 0;
														while adx < 16 {
															bdx = 7;
															while bdx >= 0 {
																if (data[16 + adx] & ((1 << bdx) as u8)) == 0 {
																	stopc = true;
																	break;
																}
																bits += 1;
																bdx -= 1;
															}
															if stopc {
																break;
															}
															adx += 1;
														}
														outs.push_str(&format!("/{}",bits));
														retv.perm_ip_ranges.push(format!("{}",outs));

													} else {
														ssllib_new_error!{SslX509Error,"ip addresses tag not valid len {}", data.len()}
													}
												} else if curany.tag == TAG_EMAILS_ADDRESSES {
													data = curany.content.clone();
													retv.perm_email_addresses.push(format!("{}",String::from_utf8_lossy(&data)));
												} else if curany.tag == TAG_URIS {
													data = curany.content.clone();
													retv.perm_uris.push(format!("{}",String::from_utf8_lossy(&data)));
												}

												oidx += 1;
											}
											ccidx += 1;
										}
									}
								}

								if permexs.elem.val[ldx].excludes.val.is_some() {
									let impexs :Asn1ImpSet<Asn1Seq<Asn1Any>,1> = permexs.elem.val[ldx].excludes.val.as_ref().unwrap().clone();
									ssllib_log_trace!("impexs.len {}",impexs.val.len());
									if impexs.val.len() > 0 {
										let mut ccidx :usize = 0;
										while ccidx < impexs.val.len() {
											let seqexs :Asn1Seq<Asn1Any> = impexs.val[ccidx].clone();
											let mut oidx :usize = 0;
											while oidx < seqexs.val.len()  {
												let curany :Asn1Any = seqexs.val[oidx].clone();
												ssllib_log_trace!("oidx[{}].{} tag 0x{:x}",oidx,seqexs.val.len(), curany.tag);		
												if curany.tag == TAG_DNS_NAMES {
													data = curany.content.clone();
													retv.ex_dns_names.push(format!("{}",String::from_utf8_lossy(&data)));
												} else if curany.tag == TAG_IP_ADDRESSES {
													data = curany.content.clone();
													if data.len() == (4 * 2) {
														let mut s :String = "".to_string();
														let mut adx :usize = 0;
														while adx < 4 {
															if adx > 0 {
																s.push_str(".");
															}
															s.push_str(&format!("{}",data[adx]));
															adx += 1;
														}

														let mut bits :usize = 0;
														let mut bdx :i32;
														let mut stopc :bool = false;
														adx = 0;
														while adx < 4 {
															bdx = 7 ;
															while bdx >= 0 {
																if (data[4+adx] & (1 << bdx) as u8) == 0 {
																	stopc = true;
																	break;
																}
																bits += 1;
																bdx -= 1;
															}

															if stopc {
																break;
															}
															adx += 1;
														}

														s.push_str(&format!("/{}", bits));
														retv.ex_ip_ranges.push(format!("{}",s));
													} else if data.len() == (0x10 * 2) {
														let mut ndata :[u8;16] = [0;16];
														let mut adx :usize = 0;
														while adx < 16 {
															ndata[adx] = data[adx];
															adx += 1;
														}
														let ipv6 :std::net::Ipv6Addr = std::net::Ipv6Addr::from(ndata);
														let mut outs :String = format!("{}",ipv6.to_string());
														let mut bits :usize = 0;
														let mut bdx :i32;
														let mut stopc :bool = false;
														adx = 0;
														while adx < 16 {
															bdx = 7;
															while bdx >= 0 {
																if (data[16 + adx] & ((1 << bdx) as u8)) == 0 {
																	stopc = true;
																	break;
																}
																bits += 1;
																bdx -= 1;
															}
															if stopc {
																break;
															}
															adx += 1;
														}
														outs.push_str(&format!("/{}",bits));
														retv.ex_ip_ranges.push(format!("{}",outs));
													} else {
														ssllib_new_error!{SslX509Error,"ip addresses tag not valid len {}", data.len()}
													}
												} else if curany.tag == TAG_EMAILS_ADDRESSES {
													data = curany.content.clone();
													retv.ex_email_addresses.push(format!("{}",String::from_utf8_lossy(&data)));
												} else if curany.tag == TAG_URIS {
													data = curany.content.clone();
													retv.ex_uris.push(format!("{}",String::from_utf8_lossy(&data)));
												}
												oidx += 1;
											}
											ccidx += 1;
										}
									}
								}
								ldx += 1;
							}
						}
					}
					jdx += 1;
				}
			}
			idx += 1;
		}

		Ok(())
	}

	fn _get_ext_key_usage(&self,retv :&mut X509BuildConfig,extensions :&Asn1Seq<Asn1X509Extension>) -> Result<(),Box<dyn Error>> {
		let mut idx :usize = 0;
		let mut jdx :usize;

		let mut data :Vec<u8>;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_EXT_KEY_USAGE {
						let mut objs :Asn1Seq<Asn1Object> = Asn1Seq::init_asn1();
						data = curext.value.data.clone();
						objs.decode_asn1(&data)?;
						let mut kdx :usize = 0;
						while kdx < objs.val.len() {
							let curoid = objs.val[kdx].get_value();
							if curoid == OID_EXT_KEY_USAGE_ANY {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageAny);
							} else if curoid == OID_EXT_KEY_USAGE_SERVER_AUTH {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageServerAuth);
							} else if curoid == OID_EXT_KEY_USAGE_CLIENT_AUTH {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageClientAuth);
							} else if curoid == OID_EXT_KEY_USAGE_CODE_SIGNING {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageCodeSigning);
							} else if curoid == OID_EXT_KEY_USAGE_EMAIL_PROTECTION {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageEmailProtection);
							} else if curoid == OID_EXT_KEY_USAGE_IP_SEC_END_SYSTEM {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageIPSECEndSystem);
							} else if curoid == OID_EXT_KEY_USAGE_IP_SEC_TUNNEL {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageIPSECTunnel);
							} else if curoid == OID_EXT_KEY_USAGE_IP_SEC_USER {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageIPSECUser);
							} else if curoid == OID_EXT_KEY_USAGE_TIME_STAMPING {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageTimeStamping);
							} else if curoid == OID_EXT_KEY_USAGE_OCSP_SIGNING {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageOCSPSigning);
							} else if curoid == OID_EXT_KEY_USAGE_MICROSOFT_SERVER_GATED_CRYPTO {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageMicrosoftServerGatedCrypto);
							} else if curoid == OID_EXT_KEY_USAGE_NETSCAPE_SERVER_GATED_CRYPTO {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageNetscapeServerGatedCrypto);
							} else if curoid == OID_EXT_KEY_USAGE_MICROSOFT_COMMERCIAL_CODE_SIGNING {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageMicrosoftCommercialCodeSigning);
							} else if curoid == OID_EXT_KEY_USAGE_MICROSOFT_KERNEL_CODE_SIGNING {
								retv.ext_key_usage.push(ExtKeyUsage::ExtKeyUsageMicrosoftKernelCodeSigning);
							} else {
								retv.unknown_ext_key_usage.push(format!("{}",curoid));
							}

							kdx += 1;
						}

					}
					jdx += 1;
				}
			}
			idx += 1;		
		}
		Ok(())
	}


	fn _get_policies(&self,retv :&mut X509BuildConfig,extensions :&Asn1Seq<Asn1X509Extension>) -> Result<(),Box<dyn Error>> {
		let mut idx :usize = 0;
		let mut jdx :usize;

		let mut data :Vec<u8>;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_POLICIES {
						let mut objs :Asn1Seq<Asn1Seq<Asn1Object>> = Asn1Seq::init_asn1();
						data = curext.value.data.clone();
						ssllib_buffer_trace!(data.as_ptr(),data.len(),"data");
						objs.decode_asn1(&data)?;
						let mut adx :usize = 0;
						let mut bdx :usize;
						while adx < objs.val.len() {
							bdx = 0;
							while bdx < objs.val[adx].val.len() {
								let curoid = objs.val[adx].val[bdx].get_value();
								retv.policies.push(format!("{}",curoid));
								bdx += 1;
							}
							adx += 1;
						}

					}
					jdx += 1;
				}
			}
			idx += 1;		
		}
		Ok(())
	}

	fn _get_authority_key_id(&self,retv :&mut X509BuildConfig,extensions :&Asn1Seq<Asn1X509Extension>) -> Result<(),Box<dyn Error>> {
		let mut idx :usize = 0;
		let mut jdx :usize;

		let mut data :Vec<u8>;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_AUTHORITY_KEY_ID {
						let mut objs :Asn1Seq<Asn1Any> = Asn1Seq::init_asn1();
						data = curext.value.data.clone();
						objs.decode_asn1(&data)?;
						if objs.val.len() != 1 {
							ssllib_new_error!{SslX509Error,"len {} != 1", objs.val.len()}
						}
						if objs.val[0].tag != 0x80 {
							ssllib_new_error!{SslX509Error,"tag for authority_key_id 0x{:x}", objs.val[0].tag}
						}

						retv.authority_key_id = objs.val[0].content.clone();
					}
					jdx += 1;
				}
			}
			idx += 1;		
		}
		Ok(())
	}

	fn _get_ocsp_servers_and_issuer_certificate_urls(&self,retv :&mut X509BuildConfig,extensions :&Asn1Seq<Asn1X509Extension>) -> Result<(),Box<dyn Error>> {
		let mut idx :usize = 0;
		let mut jdx :usize;

		let mut data :Vec<u8>;

		while idx < extensions.val.len() {
			if extensions.val[idx].elem.val.len() > 0 {
				jdx = 0;
				while jdx < extensions.val[idx].elem.val.len() {
					let curext :&Asn1X509ExtensionElem = &(extensions.val[idx].elem.val[jdx]);
					let oid :String = curext.object.get_value();
					if oid == OID_AUTHORITY_INFO_ACCESS {
						let mut auth :Asn1AuthorityObj = Asn1AuthorityObj::init_asn1();
						data = curext.value.data.clone();
						ssllib_buffer_trace!(data.as_ptr(),data.len(),"data");
						auth.decode_asn1(&data)?;
						let mut abx :usize;
						let mut bdx :usize;
						abx = 0;
						while abx < auth.elem.val.len() {
							bdx = 0;
							while bdx < auth.elem.val[abx].val.len() {
								let curoid = auth.elem.val[abx].val[bdx].obj.get_value();


								if curoid == OID_AUTHORITY_INFO_ACCESS_OCSP {
									let oany = auth.elem.val[abx].val[bdx].value.clone();
									if oany.tag == TAG_URIS {
										data = oany.content.clone();
										retv.ocsp_servers.push(format!("{}",String::from_utf8_lossy(&data)));
									} else {
										ssllib_new_error!{SslX509Error,"tag 0x{:x} not TAG_URIS 0x{:x}", oany.tag, TAG_URIS}
									}
								} else if curoid == OID_AUTHORITY_INFO_ACCESS_ISSUER {
									let oany = auth.elem.val[abx].val[bdx].value.clone();
									if oany.tag == TAG_URIS {
										data = oany.content.clone();
										retv.issuer_certificate_urls.push(format!("{}",String::from_utf8_lossy(&data)));
									} else {
										ssllib_new_error!{SslX509Error,"tag 0x{:x} not TAG_URIS 0x{:x}", oany.tag, TAG_URIS}
									}
								} else {
									ssllib_log_trace!("[{}] not support", curoid);
								}
								bdx += 1;
							}
							abx += 1;
						}
					}
					jdx += 1;
				}
			}
			idx += 1;		
		}
		Ok(())
	}


	pub fn to_export_build(&self) -> Result<X509BuildConfig,Box<dyn Error>> {
		let mut build :X509BuildConfig = X509BuildConfig::new();
		let cbytes :Vec<u8>;
		let mut befores :String;
		let mut afters :String;
		let formats :&str = "%Y-%m-%d %H:%M:%S%z";

		if self.cert_info.elem.val.len() == 0 {
			ssllib_new_error!{SslX509Error,"no elem cert_info"}
		}

		if self.cert_info.elem.val[0].version.val.is_some() {
			let verimpset :&Asn1ImpSet<Asn1Integer,0> = self.cert_info.elem.val[0].version.val.as_ref().unwrap();
			if verimpset.val.len() > 0 {
				build.version = verimpset.val[0].val as i64;
				if build.version < 0 {
					ssllib_new_error!{SslX509Error,"version {} < 0" ,build.version}
				}

				build.version += 1;
				if build.version > 3 {
					ssllib_new_error!{SslX509Error,"version {} > 3" ,build.version}
				}
			}
		}

		cbytes = self.cert_info.elem.val[0].serial_number.val.to_bytes_be();
		build.serial_number = BigInt::from_bytes_be(Sign::Plus,&cbytes);
		ssllib_log_trace!("serial_number 0x{:x}", build.serial_number);

		/*now to get the siganature*/
		if !self.cert_info.elem.val[0].signature.equal_asn1(&self.sig_alg) {
			let mut code :Vec<u8>;
			code = self.cert_info.elem.val[0].signature.encode_asn1()?;
			ssllib_buffer_error!(code.as_ptr(), code.len(),"signature");
			code = self.sig_alg.encode_asn1()?;
			ssllib_buffer_error!(code.as_ptr(), code.len(),"sig_alg");
			ssllib_new_error!{SslX509Error,"not matched signature algorithm to sig_alg"}
		}

		/*now to get the signature*/
		let oid :String = self.sig_alg.get_algorithm()?;
		build.signature_algorithm = get_sig_algorithm_from_oid(&oid)?;

		/*to issuer*/
		build.issuer = self.cert_info.elem.val[0].issuer.to_pkixname()?;
		build.subject = self.cert_info.elem.val[0].subject.to_pkixname()?;
		if self.cert_info.elem.val[0].validity.elem.val.len() < 1 {
			ssllib_new_error!{SslX509Error,"validity < 1"}
		}

		befores = self.cert_info.elem.val[0].validity.elem.val[0].notBefore.get_value_str();
		afters = self.cert_info.elem.val[0].validity.elem.val[0].notAfter.get_value_str();

		befores.push_str("+00:00");
		afters.push_str("+00:00");

		build.not_before = DateTime::parse_from_str(&befores,formats)?.into();
		build.not_after = DateTime::parse_from_str(&afters,formats)?.into();

		let mut extensions :Asn1Seq<Asn1X509Extension> = Asn1Seq::init_asn1();

		if self.cert_info.elem.val[0].extensions.val.is_some() {
			let c :Asn1ImpSet<Asn1Seq<Asn1X509Extension>,3> = self.cert_info.elem.val[0].extensions.val.as_ref().unwrap().clone();
			if c.val.len() > 0 {
				extensions = c.val[0].clone();
			}
		}


		build.key_usage = self._get_key_usage(&extensions)?;
		self._get_constraints_valid(&mut build,&extensions)?;
		build.subject_key_id = self._get_subject_key_id(&extensions)?;
		self._get_uris(&mut build,&extensions)?;
		self._get_perm_exs(&mut build,&extensions)?;
		self._get_ext_key_usage(&mut build,&extensions)?;
		self._get_policies(&mut build,&extensions)?;
		self._get_authority_key_id(&mut build,&extensions)?;
		self._get_ocsp_servers_and_issuer_certificate_urls(&mut build,&extensions)?;

		Ok(build)
	}
}


//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509 {
	pub elem : Asn1Seq<Asn1X509Elem>,
	pub aux : Asn1Opt<Asn1X509AuxCert>,
}

impl Asn1X509 {
	pub fn match_priv_data(&self,signtype :&str,pktype :&str,privdata:&[u8]) -> Result<bool, Box<dyn Error>> {
		let  _ = self.elem.check_safe_one("Asn1X509")?;
		return self.elem.val[0].match_priv_data(signtype,pktype,privdata);
	}

	pub fn is_self_signed(&self) -> bool {
		self.elem.sure_safe_one("Asn1X509").unwrap();
		let cert_info :&Asn1X509Cinf = &self.elem.val[0].cert_info;
		cert_info.elem.sure_safe_one("Asn1X509 cert_info").unwrap();
		if cert_info.elem.val[0].issuer.eq(&cert_info.elem.val[0].subject) {
			let ores = self.self_verify();
			if ores.is_ok() {
				return ores.unwrap();
			}
		}


		return false;
	}

	pub fn get_x509_name0(&self) -> Option<Asn1X509Name> {
		let mut retv :Option<Asn1X509Name> = None;
		if self.elem.val.len() > 0 {
			if self.elem.val[0].cert_info.elem.val.len() > 0 {
				retv = Some(self.elem.val[0].cert_info.elem.val[0].issuer.clone());
			}
		}
		retv
	}

	pub fn get_serial_number0(&self) -> Option<Asn1BigNum> {
		let mut retv :Option<Asn1BigNum> = None;
		if self.elem.val.len() > 0 {
			if self.elem.val[0].cert_info.elem.val.len() > 0 {
				retv = Some(self.elem.val[0].cert_info.elem.val[0].serial_number.clone());
			}
		}
		retv
	}

	pub fn append_trust(&mut self,objs :&str) -> Result<(),Box<dyn Error>> {
		if self.aux.val.is_none() {
			self.aux.val = Some(Asn1X509AuxCert::init_asn1());
		}
		return self.aux.val.as_mut().unwrap().append_trust(objs);
	}

	pub fn append_reject(&mut self, objs :&str) -> Result<(),Box<dyn Error>> {
		if self.aux.val.is_none() {
			self.aux.val = Some(Asn1X509AuxCert::init_asn1());
		}
		return self.aux.val.as_mut().unwrap().append_reject(objs);
	}

	pub fn set_alias(&mut self, alias :&str) -> Result<(),Box<dyn Error>> {
		if self.aux.val.is_none() {
			self.aux.val = Some(Asn1X509AuxCert::init_asn1());
		}
		return self.aux.val.as_mut().unwrap().set_alias(alias);
	}
	
	pub fn set_keyid(&mut self, keyid :&[u8]) -> Result<(),Box<dyn Error>> {
		if self.aux.val.is_none() {
			self.aux.val = Some(Asn1X509AuxCert::init_asn1());
		}
		return self.aux.val.as_mut().unwrap().set_keyid(keyid);
	}

	pub fn append_other(&mut self, x :&Asn1X509Algor) -> Result<(),Box<dyn Error>> {
		if self.aux.val.is_none() {
			self.aux.val = Some(Asn1X509AuxCert::init_asn1());
		}
		return self.aux.val.as_mut().unwrap().append_other(x);
	}

	pub fn to_export_build(&self) -> Result<X509BuildConfig,Box<dyn Error>> {
		let build :X509BuildConfig;
		if self.elem.val.len() == 0 {
			ssllib_new_error!{SslX509Error,"no element"}
		}

		build = self.elem.val[0].to_export_build()?;
		Ok(build)
	}

	pub fn self_verify(&self) -> Result<bool, Box<dyn Error>> {
		let retv :bool;
		self.elem.check_safe_one("Asn1X509Elem")?;
		retv = self.elem.val[0].self_verify()?;
		Ok(retv)
	}


	pub fn verify_opt(&self, opt :&mut X509VerifyOption) -> Result<bool, Box<dyn Error>> {
		/*now to get verify*/
		let mut retv :bool = false;
		let roots :Vec<Asn1X509> = opt.get_root_certs()?;
		if roots.len() != 0 {		
			retv = true;
		}

		Ok(retv)
	}

}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pbe2ParamElem {
	pub keyfunc : Asn1X509Algor,
	pub encryption : Asn1X509Algor,
}

impl Asn1Pbe2ParamElem {
	fn set_encrypt(&mut self, env :&ConfigValue,rcfg :&ConfigValue) -> Result<Box<dyn Asn1EncryptOp>,Box<dyn Error>> {
		let enctype :String = env.get_str(KEY_JSON_ENCTYPE)?;
		if enctype == KEY_JSON_AES256CBC {
			let _ = self.encryption.set_algorithm(OID_AES_256_CBC)?;
			let ores = env.get_str(KEY_JSON_RANDFILE);
			let mut randfile :Option<String> = None;
			if ores.is_ok() {
				randfile = Some(format!("{}",ores.unwrap()));
				ssllib_log_trace!("set randfile {:?}",randfile);
			}
			let mut randc :RandOps = RandOps::new(randfile)?;
			let ivkey = randc.get_bytes(16 as usize)?;
			let aeskey = rcfg.get_u8_array(KEY_JSON_KEY)?;
			let mut aes256ccb :Aes256CbcAlgo = Aes256CbcAlgo::new()?;
			let _ = aes256ccb.init_encrypt(&aeskey,&ivkey)?;
			let mut anyv :Asn1Any = Asn1Any::init_asn1();
			anyv.content = ivkey.clone();
			anyv.tag = ASN1_OCT_STRING_FLAG as u64;
			ssllib_buffer_trace!(anyv.content.as_ptr(),anyv.content.len(),"ivkey set");
			let _ = self.encryption.set_param(Some(anyv.clone()))?;
			return Ok(Box::new(aes256ccb));
		} else if enctype == KEY_JSON_AES256CFB {
			let _ = self.encryption.set_algorithm(OID_AES_256_CFB)?;
			let ores = env.get_str(KEY_JSON_RANDFILE);
			let mut randfile :Option<String> = None;
			if ores.is_ok() {
				randfile = Some(format!("{}",ores.unwrap()));
				ssllib_log_trace!("set randfile {:?}",randfile);
			}
			let mut randc :RandOps = RandOps::new(randfile)?;
			let ivkey = randc.get_bytes(16 as usize)?;
			let aeskey = rcfg.get_u8_array(KEY_JSON_KEY)?;
			ssllib_log_trace!(" ");
			let mut aes256cfb :Aes256CfbAlgo = Aes256CfbAlgo::new()?;
			let _ = aes256cfb.init_encrypt(&aeskey,&ivkey)?;
			let mut anyv :Asn1Any = Asn1Any::init_asn1();
			anyv.content = ivkey.clone();
			anyv.tag = ASN1_OCT_STRING_FLAG as u64;
			ssllib_buffer_trace!(anyv.content.as_ptr(),anyv.content.len(),"ivkey set");
			let _ = self.encryption.set_param(Some(anyv.clone()))?;
			return Ok(Box::new(aes256cfb));
		}
		ssllib_new_error!{SslX509Error,"not support [{}][{}]",KEY_JSON_ENCTYPE,enctype}
	}


	pub fn set_cmd(&mut self, env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut retv :ConfigValue = ConfigValue::new("{}")?;
		ssllib_log_trace!(" ");
		let cv = env.get_str(KEY_JSON_TYPE)?;
		ssllib_log_trace!("type [{}]",cv);
		if cv == KEY_JSON_PBKDF2 {
			let _ = self.keyfunc.set_algorithm(OID_PBKDF2)?;
			let mut anyv :Asn1Any = Asn1Any::init_asn1();
			let pcfg = env.get_config_must(KEY_JSON_PBKDF2)?;
			let mut pbkdf2 :Asn1Pbkdf2ParamElem = Asn1Pbkdf2ParamElem::init_asn1();
			ssllib_log_trace!(" ");
			let rcfg :ConfigValue = pbkdf2.set_cmd(&pcfg)?;
			ssllib_log_trace!(" ");
			anyv.content = pbkdf2.encode_asn1()?;
			let _ = self.keyfunc.set_param(Some(anyv.clone()))?;
			let mut ncfg :ConfigValue = ConfigValue::new("{}").unwrap();
			let passin :String = env.get_str(KEY_JSON_PASSIN)?;
			let _ = ncfg.set_str(KEY_JSON_PASSIN,&passin)?;
			let ores = env.get_str(KEY_JSON_RANDFILE);
			if ores.is_ok() {
				let _ = ncfg.set_str(KEY_JSON_RANDFILE,&format!("{}",ores.unwrap()))?;
			}
			let mut enfn :Box<dyn Asn1EncryptOp> = self.set_encrypt(env,&rcfg)?;
			let decdata = env.get_u8_array(KEY_JSON_DECDATA)?;
			let mut encdata = enfn.encrypt_update(&decdata)?;
			encdata.extend(enfn.encrypt_final()?);
			let _ = retv.set_u8_array(KEY_JSON_ENCDATA,&encdata)?;
		} else {
			ssllib_new_error!{SslX509Error,"not support type [{}]",cv}
		}

		Ok(retv)
	}

	fn get_decrypt(&self,_env :&ConfigValue, ncfg :&ConfigValue, config :&mut ConfigValue) -> Result<Box<dyn Asn1DecryptOp>,Box<dyn Error>> {
		let ktype = self.encryption.get_algorithm()?;
		if ktype == OID_AES_256_CBC {
			/*now we should give the */
			let _ = config.set_str(KEY_JSON_ENCTYPE,KEY_JSON_AES256CBC)?;
			let params = self.encryption.get_param()?;
			if params.is_some() {
				let anyv :&Asn1Any = params.as_ref().unwrap();
				let ivkey = anyv.content.clone();
				let aeskey = ncfg.get_u8_array(KEY_JSON_KEY)?;
				let mut aescbcenc = Aes256CbcAlgo::new()?;
				let _ = aescbcenc.init_decrypt(&aeskey,&ivkey)?;
				return Ok(Box::new(aescbcenc));
			} else {
				ssllib_new_error!{SslX509Error,"not set params value for encryption"}
			}
		} else if ktype == OID_AES_256_CFB {
			let _ = config.set_str(KEY_JSON_ENCTYPE,KEY_JSON_AES256CFB)?;
			let params = self.encryption.get_param()?;
			if params.is_some() {
				let anyv :&Asn1Any = params.as_ref().unwrap();
				let ivkey = anyv.content.clone();
				let aeskey = ncfg.get_u8_array(KEY_JSON_KEY)?;
				let mut aescfbenc = Aes256CfbAlgo::new()?;
				let _ = aescfbenc.init_decrypt(&aeskey,&ivkey)?;
				return Ok(Box::new(aescfbenc));
			} else {
				ssllib_new_error!{SslX509Error,"not set params value for encryption"}
			}
		}
		ssllib_new_error!{SslX509Error,"not valid encrypt [{}]", ktype}
	}

	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut config :ConfigValue = ConfigValue::new("{}")?;
		let algr = self.keyfunc.get_algorithm()?;
		if algr == OID_PBKDF2 {
			let _ = config.set_str(KEY_JSON_TYPE,KEY_JSON_PBKDF2)?;
			let pres = self.keyfunc.get_param()?;
			if pres.is_none() {
				ssllib_new_error!{SslX509Error,"no encryption get"}
			}
			let decdata = pres.unwrap().content.clone();			
			let mut pbkdf2 :Asn1Pbkdf2ParamElem = Asn1Pbkdf2ParamElem::init_asn1();
			let _ = pbkdf2.decode_asn1(&decdata)?;
			let ncfg = pbkdf2.get_cmd(env)?;
			let mut bdec :Box<dyn Asn1DecryptOp> = self.get_decrypt(env,&ncfg,&mut config)?;
			let encdata = env.get_u8_array(KEY_JSON_ENCDATA)?;
			let mut decdata = bdec.decrypt_update(&encdata)?;
			decdata.extend(bdec.decrypt_final()?);
			ssllib_buffer_trace!(decdata.as_ptr(),decdata.len(),"decdata");
			let _ = config.set_u8_array(KEY_JSON_DECDATA,&decdata)?;
			let _ = config.set_config(KEY_JSON_PBKDF2,&ncfg)?;
		} else {
			ssllib_new_error!{SslX509Error,"not support algr [{}]", algr}
		}
		Ok(config)
	}
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

impl Asn1Pbkdf2ParamElem {
	pub fn set_cmd(&mut self, env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut ncfg :ConfigValue = ConfigValue::new("{}").unwrap();
		let dtype = env.get_str(KEY_JSON_DIGESTTYPE)?;
		if dtype == KEY_HMAC_WITH_SHA256 {
			let mut oid :Asn1X509Algor = Asn1X509Algor::init_asn1();
			let _ = oid.set_algorithm(OID_HMAC_WITH_SHA256)?;
			self.prf.val = Some(oid.clone());
			let iter :i64 = env.get_i64(KEY_JSON_TIMES)?;
			let passin :String = env.get_str(KEY_JSON_PASSIN)?;
			let _ = self.iter.set_value(iter);
			let mut hsha256 :HmacSha256Digest = HmacSha256Digest::new()?;
			let _ = hsha256.init_digest(self.iter.val as u32, passin.as_bytes())?;
			let mut randops :RandOps ;
			let ores = env.get_str(KEY_JSON_RANDFILE);
			if ores.is_ok() {
				randops = RandOps::new(Some(format!("{}",ores.unwrap()))).unwrap();
			} else {
				randops = RandOps::new(None).unwrap();
			}
			let salt :Vec<u8> = randops.get_bytes(8 as usize)?;
			self.salt.content = salt.clone();
			let _ = hsha256.digest_update(&salt)?;
			let retv = hsha256.digest_final()?;
			let _ = ncfg.set_u8_array(KEY_JSON_KEY,&retv)?;
		} else {
			ssllib_new_error!{SslX509Error,"not support type [{}]",dtype}
		}
		Ok(ncfg)
	}

	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut config :ConfigValue = ConfigValue::new("{}").unwrap();
		if self.prf.val.is_none() {
			ssllib_new_error!{SslX509Error,"no prf setted"}
		}
		let algr :&Asn1X509Algor = self.prf.val.as_ref().unwrap();
		let ktype :String = algr.get_algorithm()?;
		if ktype == OID_HMAC_WITH_SHA256 {
			let passin :String = env.get_str(KEY_JSON_PASSIN)?;
			let mut hsha256 :HmacSha256Digest = HmacSha256Digest::new()?;
			let _ = hsha256.init_digest(self.iter.val as u32,passin.as_bytes())?;
			let _ = hsha256.digest_update(&(self.salt.content))?;
			let retv = hsha256.digest_final()?;
			let _ = config.set_u8_array(KEY_JSON_KEY,&retv)?;
		} else {
			ssllib_new_error!{SslX509Error,"not support algorithm [{}]", ktype}
		}
		Ok(config)
	}
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

impl Asn1NetscapePkeyElem {
	pub fn set_privdata(&mut self,data :&[u8]) -> Result<(),Box<dyn Error>> {
		self.privdata.data = data.to_vec().clone();
		Ok(())
	}

	pub fn set_algorithm(&mut self,env :&ConfigValue) -> Result<(),Box<dyn Error>> {
		ssllib_log_trace!(" ");
		let cs = env.get_str(KEY_JSON_TYPE)?;
		if cs == KEY_JSON_RSA {
			let _ = self.algor.set_param_null()?;
			let _= self.algor.set_algorithm(OID_RSA_ENCRYPTION)?;
		} else {
			ssllib_new_error!{SslX509Error,"[{}] [{}]",KEY_JSON_TYPE,cs}
		}
		Ok(())
	}

	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		return self.algor.get_algorithm();
	}

	pub fn get_privdata(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		Ok(self.privdata.data.clone())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1NetscapePkey {
	pub elem : Asn1Seq<Asn1NetscapePkeyElem>,
}

impl Asn1NetscapePkey {
	pub fn get_algorithm(&self) -> Result<String,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].get_algorithm();
	}
	pub fn get_privdata(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].get_privdata();
	}

	pub fn set_algorithm(&mut self, env :&ConfigValue) -> Result<(),Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].set_algorithm(env);
	}
	pub fn set_privdata(&mut self,data :&[u8]) -> Result<(),Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1NetscapePkey")?;
		return self.elem.val[0].set_privdata(data);
	}

}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509SigElem {
	pub algor : Asn1X509Algor,
	pub digest : Asn1OctData,
}

#[allow(unused_variables,unused_mut)]
impl Asn1X509SigElem {
	pub fn set_cmd(&mut self, env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		ssllib_log_trace!(" ");
		let cs = env.get_str(KEY_JSON_TYPE)?;
		let retv :ConfigValue = ConfigValue::new("{}")?;
		if cs == KEY_JSON_PBES2 {
			ssllib_log_trace!(" ");
			let mut cfg = env.get_config_must(KEY_JSON_PBES2)?;
			let mut pbes2 :Asn1Pbe2ParamElem = Asn1Pbe2ParamElem::init_asn1();
			ssllib_log_trace!(" ");
			let ncfg = pbes2.set_cmd(&cfg)?;
			let _ = self.algor.set_algorithm(OID_PBES2)?;
			let mut anyv :Asn1Any = Asn1Any::init_asn1();
			anyv.content = pbes2.encode_asn1()?;
			let _ = self.algor.set_param(Some(anyv.clone()))?;
			self.digest.data = ncfg.get_u8_array(KEY_JSON_ENCDATA)?;
			ssllib_buffer_trace!(self.digest.data.as_ptr(),self.digest.data.len(), "digest data");
		} else {
			ssllib_new_error!{SslX509Error, "not support type [{}]", cs}
		}
		Ok(retv)
	}


	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut config :ConfigValue = ConfigValue::new("{}")?;
		let cv :String = self.algor.get_algorithm()?;
		let mut nenv :ConfigValue = env.clone();
		if cv == OID_PBES2 {
			let mut  pbes2 :Asn1Pbe2ParamElem = Asn1Pbe2ParamElem::init_asn1();
			let ores = self.algor.get_param()?;
			if ores.is_none() {
				ssllib_new_error!{SslX509Error,"no params set"}
			}
			let anyv :Asn1Any = ores.unwrap();
			let decdata = anyv.content.clone();
			ssllib_log_trace!(" ");
			let _ = pbes2.decode_asn1(&decdata)?;
			ssllib_log_trace!(" ");
			let _ = nenv.set_u8_array(KEY_JSON_ENCDATA,&self.digest.data)?;
			let cfg = pbes2.get_cmd(&nenv)?;
			let _ = config.set_str(KEY_JSON_TYPE,KEY_JSON_PBES2)?;
			let _ = config.set_config(KEY_JSON_PBES2,&cfg)?;
		} else {
			ssllib_new_error!{SslX509Error,"[{}] packet not support", cv}
		}
		Ok(config)
	}

	pub fn get_algor(&self) -> Result<&Asn1X509Algor,Box<dyn Error>> {
		Ok(&self.algor)
	}

	pub fn get_encrypt_data(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		Ok(self.digest.data.clone())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Sig {
	pub elem : Asn1Seq<Asn1X509SigElem>,
}

impl Asn1X509Sig {
	pub fn set_cmd(&mut self, config :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let _ = self.elem.make_safe_one("Asn1X509Sig")?;
		return self.elem.val[0].set_cmd(config);
	}

	pub fn get_cmd(&self,env :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Sig")?;
		return self.elem.val[0].get_cmd(env);
	}

	pub fn get_algor(&self) -> Result<&Asn1X509Algor,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Sig")?;
		return self.elem.val[0].get_algor();
	}

	pub fn get_encrypt_data(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let _ = self.elem.check_safe_one("Asn1X509Sig")?;
		return self.elem.val[0].get_encrypt_data();
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1ReqInfos {
	pub elem :Asn1Seq<Asn1Any>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ReqInfoElem {
	pub version : Asn1Integer,
	pub subject : Asn1X509Name,
	pub pubkey : Asn1X509Pubkey,
	pub attributes : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,0>>,
}

impl Asn1X509ReqInfoElem {
	pub fn get_x509_req_config(&self,reqcfg :&mut X509RequestBuildConfig) -> Result<(),Box<dyn Error>> {
		self.pubkey.elem.check_safe_one("Asn1X509PubkeyElem")?;
		reqcfg.subject = self.subject.to_pkixname()?;
		/*now to give the attributes for*/
		if self.attributes.val.is_some() {
			let cattrs :&Asn1ImpSet<Asn1X509Attribute,0> = self.attributes.val.as_ref().unwrap();
			if cattrs.val.len() > 0 {
				let mut idx :usize = 0;
				while idx < cattrs.val.len() {
					let attr :&Asn1X509Attribute = &(cattrs.val[idx]);
					attr.extract_req_infos(reqcfg)?;
					idx += 1;
				}
			}
		}
		Ok(())
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ReqInfo {
	pub elem : Asn1Seq<Asn1X509ReqInfoElem>,
}

impl Asn1X509ReqInfo {
	pub fn get_x509_req_config(&self,reqcfg :&mut X509RequestBuildConfig) -> Result<(),Box<dyn Error>> {
		self.elem.check_safe_one("Asn1X509ReqInfoElem")?;
		return self.elem.val[0].get_x509_req_config(reqcfg);
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509ReqElem {
	pub req_info : Asn1X509ReqInfo,
	pub sig_alg : Asn1X509Algor,
	pub signature : Asn1BitDataFlag,
}

impl Asn1X509ReqElem {
	pub fn self_verify(&self) -> Result<bool,Box<dyn Error>> {
		self.req_info.elem.check_safe_one("Asn1X509ReqInfoElem")?;
		self.sig_alg.elem.check_safe_one("Asn1X509AlgorElem")?;
		self.req_info.elem.val[0].pubkey.elem.check_safe_one("Asn1X509PubkeyElem")?;
		let mut vfyop :Box<dyn Asn1VerifyOp> = get_x509_verifier_from_asn1(&self.sig_alg.elem.val[0],&self.req_info.elem.val[0].pubkey.elem.val[0])?;
		let origdata = self.req_info.encode_asn1()?;
		let signdata = self.signature.data.clone();
		return vfyop.verify_exec(&origdata,&signdata);
	}

	pub fn get_x509_req_config(&self,reqcfg :&mut X509RequestBuildConfig) -> Result<(),Box<dyn Error>> {
		return self.req_info.get_x509_req_config(reqcfg);
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Req {
	pub elem : Asn1Seq<Asn1X509ReqElem>,
}

impl Asn1X509Req {
	pub fn self_verify(&self) -> Result<bool, Box<dyn Error>> {
		self.elem.check_safe_one("Asn1X509ReqElem")?;
		return self.elem.val[0].self_verify();
	}

	pub fn get_x509_req_config(&self,reqcfg :&mut X509RequestBuildConfig) -> Result<(),Box<dyn Error>> {
		self.elem.check_safe_one("Asn1X509ReqElem")?;
		return self.elem.val[0].get_x509_req_config(reqcfg);
	}

	pub fn to_export_build(&self) -> Result<X509RequestBuildConfig,Box<dyn Error>> {
		let mut retv :X509RequestBuildConfig = X509RequestBuildConfig::new();
		let _ = self.get_x509_req_config(&mut retv)?;
		Ok(retv)
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkeyFormElem {
	pub algor : Asn1X509Algor,
	pub data  : Asn1BitData,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkeyForm {
	pub elem :Asn1Seq<Asn1RsaPubkeyFormElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1OtherNameElem {
	pub typeid :Asn1Object,
	pub value :Asn1Ndef<Asn1Any,0>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1OtherName {
	pub elem :Asn1Seq<Asn1OtherNameElem>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1EdiPartyNameElem {
	pub nameassigner :Asn1Opt<Asn1Ndef<Asn1PrintableString,0>>,
	pub partyname :Asn1Ndef<Asn1PrintableString,1>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1EdiPartyName {
	pub elem :Asn1Seq<Asn1EdiPartyNameElem>,
}

#[asn1_int_choice(selector=stype,othername=0,rfc822name=1,dnsname=2,directoryname=4,uri=6,ipaddress=7,registerid=8)]
#[derive(Clone)]
pub struct Asn1GeneralName {
	pub stype :i32,
	pub othername : Asn1Imp<Asn1OtherName,0>,
	pub rfc822name :Asn1Imp<Asn1IA5String,1>,
	pub dnsname :Asn1Imp<Asn1IA5String,2>,
	pub directoryname : Asn1Imp<Asn1Seq<Asn1X509Name>,4>,
	pub uri : Asn1Imp<Asn1IA5String,6>,
	pub ipaddress :Asn1Imp<Asn1IA5String,7>,
	pub registerid :Asn1Imp<Asn1Object,8>,
}


pub (crate) fn add_asn1set_with_x509(xs :&mut Vec<Asn1X509>, cert :&Asn1X509, duplicated :bool,selfsignedallow :bool) -> Result<(),Box<dyn Error>> {

	if !duplicated {
		for i in 0..xs.len() {
			if xs[i].equal_asn1(cert) {
				/*that is the same ,so we do this*/
				return Ok(());
			}
		}
	}
	if !selfsignedallow {
		if cert.is_self_signed() {
			ssllib_new_error!{SslX509Error,"self signed cert"}
		}
	}
	xs.push(cert.clone());
	Ok(())
}

pub fn get_algor_pbkdf2_private_data(x509algorbytes :&[u8],encdata :&[u8],passin :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let mut algor :Asn1X509Algor = Asn1X509Algor::init_asn1();
	let _ = algor.decode_asn1(x509algorbytes)?;
	let types = algor.elem.val[0].algorithm.get_value();
	if types == OID_PBES2 {
		let params :&Asn1Any = algor.elem.val[0].parameters.val.as_ref().unwrap();
		let decdata :Vec<u8> = params.content.clone();
		let mut pbe2 : Asn1Pbe2ParamElem = Asn1Pbe2ParamElem::init_asn1();
		let _ = pbe2.decode_asn1(&decdata)?;
		let pbe2types = pbe2.keyfunc.elem.val[0].algorithm.get_value();
		if pbe2types == OID_PBKDF2 {
			let params :&Asn1Any = pbe2.keyfunc.elem.val[0].parameters.val.as_ref().unwrap();
			let decdata :Vec<u8> = params.content.clone();
			let mut pbkdf2 :Asn1Pbkdf2ParamElem = Asn1Pbkdf2ParamElem::init_asn1();
			let _ = pbkdf2.decode_asn1(&decdata)?;
			let aeskey :Vec<u8> = get_hmac_sha256_key(passin,&pbkdf2.salt.content,pbkdf2.iter.val as usize);
			let types = pbe2.encryption.elem.val[0].algorithm.get_value();
			let odecrypt = get_decryptor_by_oid(&types);
			if odecrypt.is_none() {
				ssllib_new_error!{SslX509Error,"not supported types [{}]",types}
			}
			let params :Asn1Any = pbe2.encryption.elem.val[0].parameters.val.as_ref().unwrap().clone();
			let ivkey :Vec<u8> = params.content.clone();
			let decrypt = odecrypt.unwrap();
			let _ = decrypt.borrow_mut().init_decrypt(&aeskey,&ivkey)?;
			let mut decdata :Vec<u8> = decrypt.borrow_mut().decrypt_update(encdata)?;
			decdata.extend(decrypt.borrow_mut().decrypt_final()?);
			return Ok(decdata);
		}
		ssllib_new_error!{SslX509Error,"not support OID_PBES2 types [{}]",pbe2types}
	}
	ssllib_new_error!{SslX509Error,"can not support types [{}]", types}
}




// pub (crate) fn get_encrypt_type_from_pkcs8(x509sigbytes :&[u8],passin :&[u8]) -> Result<(String,Vec<u8>),Box<dyn Error>> {
// 	let mut x509sig = Asn1X509Sig::init_asn1();
// 	let _= x509sig.decode_asn1(x509sigbytes)?;
// 	let algordata = x509sig.elem.val[0].algor.encode_asn1()?;
// 	let encdata = x509sig.elem.val[0].digest.data.clone();
// 	let decdata = get_algor_pbkdf2_private_data(&algordata,&encdata,passin)?;
// 	let mut netpkey :Asn1NetscapePkey = Asn1NetscapePkey::init_asn1();
// 	let _ = netpkey.decode_asn1(&decdata)?;
// 	let types = netpkey.elem.val[0].algor.elem.val[0].algorithm.get_value();
// 	let odata = netpkey.encode_asn1()?;
// 	return Ok((types,odata));
// }


#[derive(Debug)]
#[derive(Clone)]
pub enum PublicKeyAlgorithm {
	UnknownPublicKeyAlgorithm,
	RSA,
	DSA,
	ECDSA,
	Ed25519,
} 

impl PartialEq for PublicKeyAlgorithm {
	fn eq(&self, other :&Self) -> bool {
		let mut retval :bool = false;
		match self {
			PublicKeyAlgorithm::UnknownPublicKeyAlgorithm => {
				match other {
					PublicKeyAlgorithm::UnknownPublicKeyAlgorithm => {
						retval = true;
					},
					_ => {},
				}
			},
			PublicKeyAlgorithm::RSA => {
				match other {
					PublicKeyAlgorithm::RSA => {
						retval = true;
					},
					_ => {},
				}
			},
			PublicKeyAlgorithm::DSA => {
				match other {
					PublicKeyAlgorithm::DSA => {
						retval = true;
					},
					_ => {},
				}
			},
			PublicKeyAlgorithm::ECDSA => {
				match other {
					PublicKeyAlgorithm::ECDSA => {
						retval = true;
					},
					_ => {},
				}
			},
			PublicKeyAlgorithm::Ed25519 => {
				match other {
					PublicKeyAlgorithm::Ed25519 => {
						retval = true;
					},
					_ => {},
				}
			},
		}
		return retval;
	}

	fn ne(&self, other :&Self) -> bool {
		return !self.eq(other);
	}
}

#[allow(dead_code)]
struct signatureAlgorithmStruct  {
	algo :SignatureAlgorithm,
	name :String,
	oid :String,
	params :Vec<u8>,
	keyalgo :PublicKeyAlgorithm,
}

impl signatureAlgorithmStruct {
	fn new(algo :SignatureAlgorithm,name :&str,oid :&str,params :&[u8],keyalgo :PublicKeyAlgorithm) -> Self {
		Self {
			algo : algo,
			name : format!("{}",name),
			oid : format!("{}",oid),
			params : params.to_vec().clone(),
			keyalgo : keyalgo,
		}
	}
}

#[asn1_sequence()]
struct pss_encode_elem {
	kaglo1 : Asn1ImpSet<Asn1X509Algor,0>,
	kaglo2 :Asn1ImpSet<Asn1X509Algor,1>,
	size : Asn1ImpSet<Asn1Integer,2>,
}

#[asn1_sequence()]
struct pss_encode {
	elem :Asn1Seq<pss_encode_elem>,
}

fn create_signature_algorithm() -> Vec<signatureAlgorithmStruct> {
	let mut retv :Vec<signatureAlgorithmStruct> = vec![];
	let nullasn1 :Asn1Null = Asn1Null::init_asn1();
	let nullbytes :Vec<u8> = nullasn1.encode_asn1().unwrap();
	let emptycode :Vec<u8> = vec![];
	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::MD5WithRSA,"MD5-RSA",OID_MD5_WITH_RSA,&nullbytes,PublicKeyAlgorithm::RSA));
	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA1WithRSA,"SHA1-RSA",OID_SHA1_WITH_RSA,&nullbytes,PublicKeyAlgorithm::RSA));
	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA1WithRSA,"SHA1-RSA",OID_ISO_SHA1_WITH_RSA,&nullbytes,PublicKeyAlgorithm::RSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA256WithRSA,"SHA256-RSA",OID_SHA256_WITH_RSA,&nullbytes,PublicKeyAlgorithm::RSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA384WithRSA,"SHA384-RSA",OID_SHA384_WITH_RSA,&nullbytes,PublicKeyAlgorithm::RSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA512WithRSA,"SHA512-RSA",OID_SHA512_WITH_RSA,&nullbytes,PublicKeyAlgorithm::RSA));





	let mut pssenc :pss_encode = pss_encode::init_asn1();
	let mut nalgor :Asn1X509Algor = Asn1X509Algor::init_asn1();
	let mut nany :Asn1Any = Asn1Any::init_asn1();
	let nullobj :Asn1Null = Asn1Null::init_asn1();
	let mut code :Vec<u8>;

	pssenc.elem.val.push(pss_encode_elem::init_asn1());
	pssenc.elem.val[0].kaglo1.val.push(Asn1X509Algor::init_asn1());
	pssenc.elem.val[0].kaglo1.val[0].elem.val.push(Asn1X509AlgorElem::init_asn1());
	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].algorithm.set_value(OID_SHA256_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].parameters.val = Some(nany.clone());

	pssenc.elem.val[0].kaglo2.val.push(Asn1X509Algor::init_asn1());
	pssenc.elem.val[0].kaglo2.val[0].elem.val.push(Asn1X509AlgorElem::init_asn1());
	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].algorithm.set_value(OID_RSA_MGF1).unwrap();

	nalgor.elem.val.push(Asn1X509AlgorElem::init_asn1());
	nalgor.elem.val[0].algorithm.set_value(OID_SHA256_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();
	nalgor.elem.val[0].parameters.val = Some(nany.clone());
	code = nalgor.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].parameters.val = Some(nany.clone());
	pssenc.elem.val[0].size.val.push(Asn1Integer::init_asn1());
	pssenc.elem.val[0].size.val[0].val = 0x20;

	code = pssenc.encode_asn1().unwrap();

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA256WithRSAPSS,"SHA256-RSAPSS",OID_RSA_PSS,&code,PublicKeyAlgorithm::RSA));


	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].algorithm.set_value(OID_SHA384_DIGEST).unwrap();

	nalgor.elem.val[0].algorithm.set_value(OID_SHA384_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();
	nalgor.elem.val[0].parameters.val = Some(nany.clone());
	code = nalgor.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].parameters.val = Some(nany.clone());

	pssenc.elem.val[0].size.val[0].val = 0x30;
	code = pssenc.encode_asn1().unwrap();
	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA384WithRSAPSS,"SHA384-RSAPSS",OID_RSA_PSS,&code,PublicKeyAlgorithm::RSA));


	pssenc.elem.val[0].kaglo1.val[0].elem.val[0].algorithm.set_value(OID_SHA512_DIGEST).unwrap();

	nalgor.elem.val[0].algorithm.set_value(OID_SHA512_DIGEST).unwrap();
	code = nullobj.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();
	nalgor.elem.val[0].parameters.val = Some(nany.clone());
	code = nalgor.encode_asn1().unwrap();
	nany.decode_asn1(&code).unwrap();

	pssenc.elem.val[0].kaglo2.val[0].elem.val[0].parameters.val = Some(nany.clone());

	pssenc.elem.val[0].size.val[0].val = 0x40;
	code = pssenc.encode_asn1().unwrap();
	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::SHA512WithRSAPSS,"SHA512-RSAPSS",OID_RSA_PSS,&code,PublicKeyAlgorithm::RSA));



	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::DSAWithSHA1,"DSA-SHA1",OID_DSA_WITH_SHA1,&emptycode,PublicKeyAlgorithm::DSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::DSAWithSHA256,"DSA-SHA256",OID_DSA_WITH_SHA256,&emptycode,PublicKeyAlgorithm::DSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::ECDSAWithSHA1,"ECDSA-SHA1",OID_ECDSA_WITH_SHA1,&emptycode,PublicKeyAlgorithm::ECDSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::ECDSAWithSHA256,"ECDSA-SHA256",OID_ECDSA_WITH_SHA256,&emptycode,PublicKeyAlgorithm::ECDSA));


	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::ECDSAWithSHA384,"ECDSA-SHA384",OID_ECDSA_WITH_SHA384,&emptycode,PublicKeyAlgorithm::ECDSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::ECDSAWithSHA512,"ECDSA-SHA512",OID_ECDSA_WITH_SHA512,&emptycode,PublicKeyAlgorithm::ECDSA));

	retv.push(signatureAlgorithmStruct::new(SignatureAlgorithm::PureEd25519,"Ed25519",OID_PURE_ED25519,&emptycode,PublicKeyAlgorithm::Ed25519));

	retv
}

fn get_sig_algorithm_from_oid(oid :&str) -> Result<SignatureAlgorithm,Box<dyn Error>> {
	for f in SIGNAGURE_ALGORITHM.iter() {
		if f.oid == oid {
			return Ok(f.algo.clone());
		}
	}
	ssllib_new_error!{SslX509Error,"not find algorithm oid [{}]", oid}
}

lazy_static!{
	static ref SIGNAGURE_ALGORITHM :Vec<signatureAlgorithmStruct> = {
		create_signature_algorithm()
	};

}

pub trait X509PublickKey {
	fn export_pubkey(&self) -> Result<(Vec<u8>,Asn1X509Algor),Box<dyn Error>>;
}

pub trait X509Privatekey {
	fn public_asn1_code(&self) -> Result<(String,Vec<u8>),Box<dyn Error>>;
}

fn get_sign_asn1_code(algo :SignatureAlgorithm) -> Result<(String,Vec<u8>),Box<dyn Error>> {
	let mut idx :usize = 0;
	while idx < SIGNAGURE_ALGORITHM.len() {
		if algo == SIGNAGURE_ALGORITHM[idx].algo {
			let rets :String = format!("{}",SIGNAGURE_ALGORITHM[idx].oid);
			let retc :Vec<u8> = SIGNAGURE_ALGORITHM[idx].params.clone();
			return Ok((rets,retc));
		}
		idx += 1;
	}
	ssllib_new_error!{SslX509Error,"no match algo {:?}", algo}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1PkixNameElem {
	pub country :Asn1Opt<Asn1X509NameEntry>,
	pub province :Asn1Opt<Asn1X509NameEntry>,
	pub locality :Asn1Opt<Asn1X509NameEntry>,
	pub street_address :Asn1Opt<Asn1X509NameEntry>,
	pub postal_code :Asn1Opt<Asn1X509NameEntry>,
	pub organization :Asn1Opt<Asn1X509NameEntry>,
	pub organizational_unit :Asn1Opt<Asn1X509NameEntry>,
	pub common_name :Asn1Opt<Asn1X509NameEntry>,
	pub serial_number :Asn1Opt<Asn1X509NameEntry>,
	pub extra_names :Asn1Opt<Asn1Set<Asn1Seq<Asn1X509NameAnyElement>>>,
}

fn append_name(set :&mut Vec<String>, n :&Asn1X509NameElement) -> Result<(),Box<dyn Error>> {
	set.push(format!("{}",n.name.val));
	Ok(())
}

fn append_extranames(set :&mut Vec<Asn1X509NameAnyElement>, n :&Asn1X509NameElement) -> Result<(),Box<dyn Error>> {
	let mut c :Asn1X509NameAnyElement = Asn1X509NameAnyElement::init_asn1();
	c.obj.set_value(&n.obj.get_value())?;
	let mut a :Asn1Any = Asn1Any::init_asn1();
	let code = n.encode_asn1()?;
	a.decode_asn1(&code)?;
	c.value = a.clone();
	set.push(c);
	Ok(())
}

fn append_name_extra(set :&mut Vec<String>,n :&Asn1X509NameAnyElement) -> Result<(),Box<dyn Error>> {
	let s = String::from_utf8_lossy(&n.value.content).to_string();
	set.push(s);
	Ok(())
}


fn append_extranames_extra(set :&mut Vec<Asn1X509NameAnyElement>, n :&Asn1X509NameAnyElement) -> Result<(),Box<dyn Error>> {
	set.push(n.clone());
	Ok(())
}

macro_rules! expand_fixup_part {
	($elemname:expr,$pkix:expr) => {
		ssllib_log_trace!("compile element");
		if $elemname.val.is_some() {
			let _cvals :Asn1X509NameEntry = $elemname.val.as_ref().unwrap().clone();
			if _cvals.names.val.len() > 0 {
				let mut _idx :usize = 0;
				let mut _jdx :usize = 0;
				_idx = 0;
				while _idx < _cvals.names.val.len() {
					ssllib_log_trace!("{} value",_idx);
					if _cvals.names.val[_idx].val.len() > 0 {
						_jdx = 0;	
						while _jdx < _cvals.names.val[_idx].val.len() {
							ssllib_log_trace!("[{}].[{}] value",_idx,_jdx);
							let _curname :Asn1X509NameElement = _cvals.names.val[_idx].val[_jdx].clone();
							let _curoid :String = _curname.obj.get_value();
							if _curoid == OID_COUNTRY {
								let _ = append_name(&mut $pkix.country,&_curname)?;
							} else if _curoid == OID_PROVINCE {
								let _ = append_name(&mut $pkix.province,&_curname)?;
							} else if _curoid == OID_LOCALITY {
								let _ = append_name(&mut $pkix.locality,&_curname)?;
							} else if _curoid == OID_STREET_ADDRESS {
								let _ = append_name(&mut $pkix.street_address,&_curname)?;
							} else if _curoid == OID_ORGANIZATION {
								let _ = append_name(&mut $pkix.organization,&_curname)?;
							} else if _curoid == OID_ORGANIZATIONAL_UNIT {
								let _ = append_name(&mut $pkix.organizational_unit,&_curname)?;
							} else if _curoid == OID_POSTAL_CODE {
								let _ = append_name(&mut $pkix.postal_code,&_curname)?;
							} else if _curoid == OID_SERIAL_NUMBER {
								let _ = append_name(&mut $pkix.serial_number,&_curname)?;
							} else if _curoid == OID_COMMON_NAME {
								let _ = append_name(&mut $pkix.common_name,&_curname)?;
							} else {
								let _ = append_extranames(&mut $pkix.extra_names,&_curname)?;
							}

							_jdx += 1;
						}
					}
					_idx += 1;
				}
			}
		}

	}
}

macro_rules! expand_fixup_extra {
	($elemname:expr,$pkix:expr) => {
		ssllib_log_trace!("extra_compile");
		if $elemname.val.is_some() {
			let _cvals :Asn1Set<Asn1Seq<Asn1X509NameAnyElement>> = $elemname.val.as_ref().unwrap().clone();
			let mut _idx :usize;
			let mut _jdx :usize;

			_idx = 0;
			while _idx < _cvals.val.len() {
				if _cvals.val[_idx].val.len() > 0 {
					_jdx = 0 ;
					while _jdx < _cvals.val[_idx].val.len() {
						let _curname :Asn1X509NameAnyElement = _cvals.val[_idx].val[_jdx].clone();
						let _curoid :String = _curname.obj.get_value();
						if _curoid == OID_COUNTRY {
							let _ = append_name_extra(&mut $pkix.country,&_curname)?;
						} else if _curoid == OID_PROVINCE {
							let _ = append_name_extra(&mut $pkix.province,&_curname)?;
						} else if _curoid == OID_LOCALITY {
							let _ = append_name_extra(&mut $pkix.locality,&_curname)?;
						} else if _curoid == OID_STREET_ADDRESS {
							let _ = append_name_extra(&mut $pkix.street_address,&_curname)?;
						} else if _curoid == OID_ORGANIZATION {
							let _ = append_name_extra(&mut $pkix.organization,&_curname)?;
						} else if _curoid == OID_ORGANIZATIONAL_UNIT {
							let _ = append_name_extra(&mut $pkix.organizational_unit,&_curname)?;
						} else if _curoid == OID_POSTAL_CODE {
							let _ = append_name_extra(&mut $pkix.postal_code,&_curname)?;
						} else if _curoid == OID_SERIAL_NUMBER {
							let _ = append_name_extra(&mut $pkix.serial_number,&_curname)?;
						} else if _curoid == OID_COMMON_NAME {
							let _ = append_name_extra(&mut $pkix.common_name,&_curname)?;
						} else {
							let _ = append_extranames_extra(&mut $pkix.extra_names,&_curname)?;
						}
						_jdx += 1;
					}
				}
				_idx += 1;
			}
		}
		ssllib_log_trace!("extra exit");
	}
}


macro_rules! set_name_entry {
	($elemname:expr,$varexpr :expr,$oid :expr) => {
		if $varexpr.len() > 0 {
			let mut _cv :Asn1X509NameEntry = Asn1X509NameEntry::init_asn1();
			let mut _idx :usize;
			_cv.names.val.push(Asn1Seq::init_asn1());
			_idx = 0;
			while _idx < $varexpr.len() {
				let mut _cb :Asn1X509NameElement = Asn1X509NameElement::init_asn1();
				_cb.obj.set_value($oid)?;
				_cb.name.val = format!("{}",$varexpr[_idx]);
				_cv.names.val[0].val.push(_cb);
				_idx += 1;
			}
			$elemname.val = Some(_cv);
		} else {
			$elemname.val = None;
		}
	}
}

macro_rules! set_name_extra {
	($elemname:expr,$varexpr :expr) => {
		if $varexpr.len() > 0 {
			let mut _cv :Asn1Set<Asn1Seq<Asn1X509NameAnyElement>> = Asn1Set::init_asn1();
			_cv.val.push(Asn1Seq::init_asn1());
			let mut _idx :usize;
			_idx = 0;
			while _idx < $varexpr.len() {
				_cv.val[0].val.push($varexpr[_idx].clone());
				_idx += 1;
			}
			$elemname.val = Some(_cv);
		} else {
			$elemname.val = None;
		}
	}
}


impl Asn1PkixNameElem {
	pub fn fixup(&mut self) -> Result<(),Box<dyn Error>> {
		let mut pkixname :PkixName = PkixName::new();

		expand_fixup_part!(self.country,pkixname);
		expand_fixup_part!(self.province,pkixname);
		expand_fixup_part!(self.locality,pkixname);
		expand_fixup_part!(self.street_address,pkixname);
		expand_fixup_part!(self.postal_code,pkixname);
		expand_fixup_part!(self.organization,pkixname);
		expand_fixup_part!(self.organizational_unit,pkixname);
		expand_fixup_part!(self.common_name,pkixname);
		expand_fixup_part!(self.serial_number,pkixname);

		expand_fixup_extra!(self.extra_names,pkixname);


		set_name_entry!(self.country,pkixname.country,OID_COUNTRY);
		set_name_entry!(self.province,pkixname.province,OID_PROVINCE);
		set_name_entry!(self.locality,pkixname.locality,OID_LOCALITY);
		set_name_entry!(self.street_address,pkixname.street_address,OID_STREET_ADDRESS);
		set_name_entry!(self.postal_code,pkixname.postal_code,OID_POSTAL_CODE);
		set_name_entry!(self.organization,pkixname.organization,OID_ORGANIZATION);
		set_name_entry!(self.organizational_unit,pkixname.organizational_unit,OID_ORGANIZATIONAL_UNIT);
		set_name_entry!(self.common_name,pkixname.common_name,OID_COMMON_NAME);
		set_name_entry!(self.serial_number,pkixname.serial_number,OID_SERIAL_NUMBER);

		set_name_extra!(self.extra_names,pkixname.extra_names);

		Ok(())
	}

	pub fn from_pkixname(pkixname :&PkixName) -> Result<Self,Box<dyn Error>> {
		let mut retv :Self = Self::init_asn1();

		set_name_entry!(retv.country,pkixname.country,OID_COUNTRY);
		set_name_entry!(retv.province,pkixname.province,OID_PROVINCE);
		set_name_entry!(retv.locality,pkixname.locality,OID_LOCALITY);
		set_name_entry!(retv.street_address,pkixname.street_address,OID_STREET_ADDRESS);
		set_name_entry!(retv.postal_code,pkixname.postal_code,OID_POSTAL_CODE);
		set_name_entry!(retv.organization,pkixname.organization,OID_ORGANIZATION);
		set_name_entry!(retv.organizational_unit,pkixname.organizational_unit,OID_ORGANIZATIONAL_UNIT);
		set_name_entry!(retv.common_name,pkixname.common_name,OID_COMMON_NAME);
		set_name_entry!(retv.serial_number,pkixname.serial_number,OID_SERIAL_NUMBER);

		set_name_extra!(retv.extra_names,pkixname.extra_names);

		Ok(retv)
	}
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1PkixName {
	pub elem :Asn1Seq<Asn1PkixNameElem>,
}

impl Asn1PkixName {
	pub fn fixup(&mut self) -> Result<(),Box<dyn Error>> {
		if self.elem.val.len() < 1 {
			return Ok(());
		}

		return self.elem.val[0].fixup();
	}

	pub fn from_pkixname(pkixname :&PkixName) -> Result<Self,Box<dyn Error>> {
		let mut retv :Self = Self::init_asn1();
		retv.elem.val.push(Asn1PkixNameElem::from_pkixname(pkixname)?);
		Ok(retv)
	}
}

#[allow(unused_assignments)]
#[allow(unused_variables)]
pub fn create_x509_from_config_build(template :&X509BuildConfig,parent :&Asn1X509,_pubkey :Box<dyn X509PublickKey>,privkey :Box<dyn X509Privatekey>) -> Result<Vec<u8>,Box<dyn Error>> {
	let zv :BigInt = zero();
	let retv :Vec<u8> = vec![];
	let algooid :String;
	let algocode :Vec<u8>;
	let puboid :String;
	let pubcode :Vec<u8>;
	let mut pubalgo :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
	if template.serial_number <  zv {
		ssllib_new_error!{SslX509Error,"serial number {} must >= 0", template.serial_number}
	}

	(algooid,algocode) = get_sign_asn1_code(template.signature_algorithm.clone())?;
	(puboid,pubcode) = privkey.public_asn1_code()?;

	let _ = pubalgo.decode_asn1(&pubcode)?;


	Ok(retv)
}