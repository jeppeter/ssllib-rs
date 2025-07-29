#[allow(unused_imports)]
use crate::{ssllib_new_error,ssllib_error_class};
#[allow(unused_imports)]
use crate::{ssllib_buffer_trace,ssllib_buffer_error,ssllib_format_buffer_log,ssllib_log_trace};
use crate::logger::*;
use crate::x509::*;
use std::error::Error;
use asn1obj::complex::*;
use asn1obj::asn1impl::*;

#[allow(unused_imports)]
use num_bigint::{BigInt,Sign};
use num_traits::{zero};
#[allow(unused_imports)]
use chrono::{Utc,Datelike,DateTime};

ssllib_error_class!{X509BuildError}



#[derive(Debug)]
#[derive(Clone)]
pub enum SignatureAlgorithm {
	UnknownSignatureAlgorithm,
	MD2WithRSA,
	MD5WithRSA,
	SHA1WithRSA,
	SHA256WithRSA,
	SHA384WithRSA,
	SHA512WithRSA,
	DSAWithSHA1,
	DSAWithSHA256,
	ECDSAWithSHA1,
	ECDSAWithSHA256,
	ECDSAWithSHA384,
	ECDSAWithSHA512,
	SHA256WithRSAPSS,
	SHA384WithRSAPSS,
	SHA512WithRSAPSS,
	PureEd25519,
}

impl PartialEq for SignatureAlgorithm {
	fn eq(&self, other :&Self) -> bool {
		match self {
			SignatureAlgorithm::UnknownSignatureAlgorithm => {
				match other {
					SignatureAlgorithm::UnknownSignatureAlgorithm => {
						return true;
					}
					_ => {},
				}
			},
			SignatureAlgorithm::MD2WithRSA => {
				match other {
					SignatureAlgorithm::MD2WithRSA => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::MD5WithRSA => {
				match other {
					SignatureAlgorithm::MD5WithRSA => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::SHA1WithRSA => {
				match other {
					SignatureAlgorithm::SHA1WithRSA => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::SHA256WithRSA => {
				match other {
					SignatureAlgorithm::SHA256WithRSA => {
						return true;
					},
					_ => {},
				}				
			},
			SignatureAlgorithm::SHA384WithRSA=> {
				match other {
					SignatureAlgorithm::SHA384WithRSA => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::SHA512WithRSA=> {
				match other {
					SignatureAlgorithm::SHA512WithRSA => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::DSAWithSHA1=> {
				match other {
					SignatureAlgorithm::DSAWithSHA1 => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::DSAWithSHA256=> {
				match other {
					SignatureAlgorithm::DSAWithSHA256 => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::ECDSAWithSHA1=> {
				match other {
					SignatureAlgorithm::ECDSAWithSHA1 => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::ECDSAWithSHA256=> {
				match other {
					SignatureAlgorithm::ECDSAWithSHA256 => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::ECDSAWithSHA384=> {
				match other {
					SignatureAlgorithm::ECDSAWithSHA384 => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::ECDSAWithSHA512=> {
				match other {
					SignatureAlgorithm::ECDSAWithSHA512 => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::SHA256WithRSAPSS=> {
				match other {
					SignatureAlgorithm::SHA256WithRSAPSS => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::SHA384WithRSAPSS=> {
				match other {
					SignatureAlgorithm::SHA384WithRSAPSS => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::SHA512WithRSAPSS=> {
				match other {
					SignatureAlgorithm::SHA512WithRSAPSS => {
						return true;
					},
					_ => {},
				}
			},
			SignatureAlgorithm::PureEd25519=> {
				match other {
					SignatureAlgorithm::PureEd25519 => {
						return true;
					},
					_ => {},
				}
			},
		}
		return false;
	}

	fn ne(&self, other :&Self) -> bool {
		return !self.eq(other);
	}
}



#[derive(Debug)]
#[derive(Clone)]
pub enum KeyUsage {
	KeyUsageDigitalSignature,
	KeyUsageContentCommitment,
	KeyUsageKeyEncipherment,
	KeyUsageDataEncipherment,
	KeyUsageKeyAgreement,
	KeyUsageCertSign,
	KeyUsageCRLSign,
	KeyUsageEncipherOnly,
	KeyUsageDecipherOnly,
}

impl PartialEq for KeyUsage {
	fn eq(&self, other :&Self) -> bool {
		let mut retval : bool = false;
		match self {
			KeyUsage::KeyUsageDigitalSignature => {
				match other {
					KeyUsage::KeyUsageDigitalSignature => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageContentCommitment => {
				match other {
					KeyUsage::KeyUsageContentCommitment => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageKeyEncipherment => {
				match other {
					KeyUsage::KeyUsageKeyEncipherment => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageDataEncipherment => {
				match other {
					KeyUsage::KeyUsageDataEncipherment => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageKeyAgreement => {
				match other {
					KeyUsage::KeyUsageKeyAgreement => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageCertSign => {
				match other {
					KeyUsage::KeyUsageCertSign => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageCRLSign => {
				match other {
					KeyUsage::KeyUsageCRLSign => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageEncipherOnly => {
				match other {
					KeyUsage::KeyUsageEncipherOnly => {
						retval = true;
					},
					_ => {},
				}
			},
			KeyUsage::KeyUsageDecipherOnly => {
				match other {
					KeyUsage::KeyUsageDecipherOnly => {
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




#[derive(Clone)]
pub struct PkixName {
	pub country :Vec<String>,
	pub province :Vec<String>,
	pub locality :Vec<String>,
	pub street_address :Vec<String>,
	pub organization :Vec<String>,
	pub organizational_unit :Vec<String>,
	pub postal_code :Vec<String>,
	pub serial_number :Vec<String>,
	pub common_name :Vec<String>,
	pub extra_names :Vec<Asn1X509NameAnyElement>,
}

macro_rules! expand_pkix_fmt {
	($name :expr, $elem :expr, $f :expr) => {
		let mut _idx :usize = 0;
		$f.write_fmt(format_args!("{} : [",$name))?;
		while _idx < $elem.len() {
			if _idx > 0 {
				$f.write_fmt(format_args!(","))?;
			}
			$f.write_fmt(format_args!("\"{}\"",$elem[_idx]))?;
			_idx += 1;
		}
		$f.write_fmt(format_args!("]"))?;
	};
}

macro_rules! expand_pkix_fmt_extra {
	($name :expr, $elem :expr, $f :expr) => {
		let mut _idx :usize = 0;
		let mut _jdx :usize;
		$f.write_fmt(format_args!("{} :[",$name))?;
		while _idx < $elem.len() {
			if _idx > 0 {
				$f.write_fmt(format_args!(","))?;
			}
			$f.write_fmt(format_args!("{{ obj :\"{}\" ,tag: {}, content[",$elem[_idx].obj.get_value(),$elem[_idx].value.tag))?;
			_jdx = 0;
			while _jdx < $elem[_idx].value.content.len() {
				if _jdx > 0 {
					$f.write_fmt(format_args!(","))?;
				}
				$f.write_fmt(format_args!("{}",$elem[_idx].value.content[_jdx]))?;
				_jdx += 1;
			}
			$f.write_fmt(format_args!("]}}"))?;
			_idx += 1;
		}
		$f.write_fmt(format_args!("]"))?;		
	};
}

impl std::fmt::Debug for PkixName {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("PkixName{{"))?;
		expand_pkix_fmt!("country",self.country,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("province",self.province,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("locality",self.locality,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("street_address",self.street_address,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("postal_code",self.postal_code,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("organization",self.organization,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("organizational_unit",self.organizational_unit,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("common_name",self.common_name,f);
		f.write_fmt(format_args!(","))?;
		expand_pkix_fmt!("serial_number",self.serial_number,f);
		f.write_fmt(format_args!(","))?;

		expand_pkix_fmt_extra!("extra_names",self.extra_names,f);

		f.write_fmt(format_args!("}}"))
	}
}

macro_rules! set_pkix_name {
	($elemname:expr,$selfval :expr) => {
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
							let _curname :Asn1X509NameElement = _cvals.names.val[_idx].val[_jdx].clone();
							$selfval.push(format!("{}",_curname.name.val));
							_jdx += 1;
						}
					}
					_idx += 1;
				}
			}
		}
	}
}

macro_rules! set_pkix_extra {
	($elemname:expr,$selfval :expr) => {
		if $elemname.val.is_some() {
			let _cvals :Asn1Set<Asn1Seq<Asn1X509NameAnyElement>> = $elemname.val.as_ref().unwrap().clone();
			if _cvals.val.len() > 0 {
				let mut _idx :usize = 0;
				let mut _jdx :usize = 0;
				_idx = 0;
				while _idx < _cvals.val.len() {
					ssllib_log_trace!("{} value",_idx);
					if _cvals.val[_idx].val.len() > 0 {
						_jdx = 0;	
						while _jdx < _cvals.val[_idx].val.len() {
							let _curname :Asn1X509NameAnyElement = _cvals.val[_idx].val[_jdx].clone();
							$selfval.push(_curname);
							_jdx += 1;
						}
					}
					_idx += 1;
				}
			}
		}
	}
}


impl PkixName {
	pub fn new() -> Self {
		Self {
			country : vec![],
			organization :vec![],
			organizational_unit :vec![],
			locality :vec![],
			province :vec![],
			street_address :vec![],
			postal_code :vec![],
			serial_number : vec![],
			common_name : vec![],
			extra_names :vec![],
		}
	}

	#[allow(unused_assignments)]
	pub fn from_asn1(pkix :&Asn1PkixName) -> Result<Self,Box<dyn Error>> {
		let mut retv :Self = Self::new();
		let mut x :Asn1PkixNameElem = Asn1PkixNameElem::init_asn1();
		if pkix.elem.val.len() > 0 {
			x = pkix.elem.val[0].clone();
			x.fixup()?;
			set_pkix_name!(x.country,retv.country);
			set_pkix_name!(x.province,retv.province);
			set_pkix_name!(x.locality,retv.locality);
			set_pkix_name!(x.street_address,retv.street_address);
			set_pkix_name!(x.organization,retv.organization);
			set_pkix_name!(x.organizational_unit,retv.organizational_unit);
			set_pkix_name!(x.postal_code,retv.postal_code);
			set_pkix_name!(x.common_name,retv.common_name);
			set_pkix_name!(x.serial_number,retv.serial_number);

			set_pkix_extra!(x.extra_names, retv.extra_names);
		}
		
		Ok(retv)
	}

}


#[derive(Clone)]
#[derive(Debug)]
pub enum ExtKeyUsage {
    ExtKeyUsageAny,
    ExtKeyUsageServerAuth,
    ExtKeyUsageClientAuth,
    ExtKeyUsageCodeSigning,
    ExtKeyUsageEmailProtection,
    ExtKeyUsageIPSECEndSystem,
    ExtKeyUsageIPSECTunnel,
    ExtKeyUsageIPSECUser,
    ExtKeyUsageTimeStamping,
    ExtKeyUsageOCSPSigning,
    ExtKeyUsageMicrosoftServerGatedCrypto,
    ExtKeyUsageNetscapeServerGatedCrypto,
    ExtKeyUsageMicrosoftCommercialCodeSigning,
    ExtKeyUsageMicrosoftKernelCodeSigning,
}

impl PartialEq for ExtKeyUsage {
    fn ne(&self,other :&Self) -> bool {
        return !self.eq(other);
    }
    
    fn eq(&self,other :&Self) -> bool{
        let mut retval :bool = false;
        match self {
            ExtKeyUsage::ExtKeyUsageAny => {
                match other {
                    ExtKeyUsage::ExtKeyUsageAny => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageServerAuth => {
                match other {
                    ExtKeyUsage::ExtKeyUsageServerAuth => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageClientAuth => {
                match other {
                    ExtKeyUsage::ExtKeyUsageClientAuth => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageCodeSigning => {
                match other {
                    ExtKeyUsage::ExtKeyUsageCodeSigning => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageEmailProtection => {
                match other {
                    ExtKeyUsage::ExtKeyUsageEmailProtection => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageIPSECEndSystem => {
                match other {
                    ExtKeyUsage::ExtKeyUsageIPSECEndSystem => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageIPSECTunnel => {
                match other {
                    ExtKeyUsage::ExtKeyUsageIPSECTunnel => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageIPSECUser => {
                match other {
                    ExtKeyUsage::ExtKeyUsageIPSECUser => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageTimeStamping => {
                match other {
                    ExtKeyUsage::ExtKeyUsageTimeStamping => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageOCSPSigning => {
                match other {
                    ExtKeyUsage::ExtKeyUsageOCSPSigning => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageMicrosoftServerGatedCrypto => {
                match other {
                    ExtKeyUsage::ExtKeyUsageMicrosoftServerGatedCrypto => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageNetscapeServerGatedCrypto => {
                match other {
                    ExtKeyUsage::ExtKeyUsageNetscapeServerGatedCrypto => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageMicrosoftCommercialCodeSigning => {
                match other {
                    ExtKeyUsage::ExtKeyUsageMicrosoftCommercialCodeSigning => {retval = true;},
                    _ => {},
                }
            },
            ExtKeyUsage::ExtKeyUsageMicrosoftKernelCodeSigning => {
                match other {
                    ExtKeyUsage::ExtKeyUsageMicrosoftKernelCodeSigning => {retval = true;},
                    _ => {},
                }
            },
        }
        return retval;
    }
}



#[derive(Debug)]
#[derive(Clone)]
pub struct X509BuildConfig {
	pub version :i64,
	pub serial_number  :BigInt,
	pub basic_constraints_valid :bool,
	pub is_ca :bool,
	pub max_path_len : i64,
	pub signature_algorithm :SignatureAlgorithm,
	pub issuer :PkixName,
	pub subject : PkixName,
	pub not_before :DateTime<Utc>,
	pub not_after :DateTime<Utc>,
	pub key_usage :Vec<KeyUsage>,
	pub subject_key_id :Vec<u8>,
	pub ip_addresses :Vec<String>,
	pub email_addresses :Vec<String>,
	pub dns_names :Vec<String>,
	pub uris :Vec<String>,
	pub ex_ip_ranges :Vec<String>,
	pub ex_email_addresses :Vec<String>,
	pub ex_dns_names :Vec<String>,
	pub ex_uris :Vec<String>,
	pub perm_ip_ranges :Vec<String>,
	pub perm_email_addresses:Vec<String>,
	pub perm_dns_names :Vec<String>,
	pub perm_uris :Vec<String>,
	pub ext_key_usage :Vec<ExtKeyUsage>,
	pub unknown_ext_key_usage :Vec<String>,
	pub policies :Vec<String>,
	pub authority_key_id :Vec<u8>,
	pub ocsp_servers :Vec<String>,
	pub issuer_certificate_urls:Vec<String>,
}

impl X509BuildConfig {
	pub fn new() -> X509BuildConfig {
		let ct :DateTime<Utc> = Utc::now();
		let (_, y) = ct.year_ce();
		let retv :Self = Self {
			version : 0,
			serial_number : zero(),
			basic_constraints_valid: false,
			is_ca: false,
			max_path_len : 0,
			signature_algorithm :SignatureAlgorithm::UnknownSignatureAlgorithm,
			issuer :PkixName::new(),
			subject :PkixName::new(),
			not_before : Utc::now(),
			not_after :Utc::now().with_year(y as i32 + 20).unwrap(),
			key_usage : vec![],
			subject_key_id : vec![],
			ip_addresses : vec![],
			email_addresses :vec![],
			dns_names :vec![],
			uris :vec![],
			ex_ip_ranges :vec![],
			ex_email_addresses :vec![],
			ex_dns_names :vec![],
			ex_uris :vec![],
			perm_ip_ranges :vec![],
			perm_email_addresses:vec![],
			perm_dns_names :vec![],
			perm_uris :vec![],
			ext_key_usage :vec![],
			unknown_ext_key_usage :vec![],
			policies : vec![],
			authority_key_id: vec![],
			ocsp_servers :vec![],
			issuer_certificate_urls:vec![],
		};

		retv
	}

	pub fn subject_bytes(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let asn1pkix :Asn1PkixName = Asn1PkixName::from_pkixname(&self.subject)?;
		let code = asn1pkix.encode_asn1()?;
		Ok(code)
	}

}

