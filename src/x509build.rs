#[allow(unused_imports)]
use crate::{ssllib_new_error,ssllib_error_class};
#[allow(unused_imports)]
use crate::{ssllib_buffer_trace,ssllib_buffer_error,ssllib_format_buffer_log,ssllib_log_trace,ssllib_log_error};
use crate::logger::*;
use crate::x509::*;
use crate::pemlib::{read_file_into_der};
use std::error::Error;
use asn1obj::complex::*;
use asn1obj::asn1impl::*;
use asn1obj::base::*;
use asn1obj::strop::{asn1_format_line};
use asn1obj_codegen::asn1_sequence;
use asn1obj::{asn1obj_error_class};
use std::io::{Write};

#[allow(unused_imports)]
use num_bigint::{BigInt,Sign};
use num_traits::{zero};
#[allow(unused_imports)]
use chrono::{Utc,DateTime,Datelike,Months};

use serde::{Deserialize, Serialize};
use crate::serde_obj::{StringVisitor,parse_to_bigint};
use std::collections::{HashMap};

ssllib_error_class!{X509BuildError}



#[derive(Debug)]
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="lowercase")]
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
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="lowercase")]
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



#[derive(Clone,Serialize,Deserialize)]
pub struct PkixName {
	#[serde(default = "array_string_default")]
	pub country :Vec<String>,
	#[serde(default = "array_string_default")]
	pub province :Vec<String>,
	#[serde(default = "array_string_default")]
	pub locality :Vec<String>,
	#[serde(default = "array_string_default")]
	pub street_address :Vec<String>,
	#[serde(default = "array_string_default")]
	pub organization :Vec<String>,
	#[serde(default = "array_string_default")]
	pub organizational_unit :Vec<String>,
	#[serde(default = "array_string_default")]
	pub postal_code :Vec<String>,
	#[serde(default = "array_string_default")]
	pub serial_number :Vec<String>,
	#[serde(default = "array_string_default")]
	pub common_name :Vec<String>,
	#[serde(default="extra_default")]
	pub extra_names :Vec<Asn1X509NameAnyElement>,
}

fn array_string_default() -> Vec<String> {
	vec![]
}

fn extra_default() -> Vec<Asn1X509NameAnyElement> {
	vec![]
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


#[derive(Clone,Serialize,Deserialize)]
pub struct PkixAttribute {
	#[serde(alias="type")]
	pub types :Asn1Object,
	pub value :Asn1Any,
}

impl PkixAttribute {
	pub fn new() -> Self {
		Self {
			types :Asn1Object::init_asn1(),
			value :Asn1Any::init_asn1(),
		}
	}
}

impl std::fmt::Debug for PkixAttribute {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("PkixAttribute {{"))?;
		f.write_fmt(format_args!("type : {},", self.types.get_value()))?;
		f.write_fmt(format_args!("value : {{"))?;
		f.write_fmt(format_args!("tag :{},", self.value.tag))?;
		f.write_fmt(format_args!("content ["))?;
		let mut idx :usize = 0;
		while idx < self.value.content.len() {
			if idx > 0 {
				f.write_fmt(format_args!(","))?;
			}
			f.write_fmt(format_args!("{}",self.value.content[idx]))?;
			idx += 1;
		}
		f.write_fmt(format_args!("]"))?;
		f.write_fmt(format_args!("}}"))?;
		f.write_fmt(format_args!("}}"))
	}
}

#[derive(Clone,Serialize,Deserialize)]
pub struct PkixAttributeSet {
	#[serde(alias="type")]
	pub types :Asn1Object,
	pub value :Vec<PkixAttribute>,
}

impl PkixAttributeSet {
	pub fn new() -> Self {
		Self {
			types :Asn1Object::init_asn1(),
			value :vec![],
		}
	}
}

impl std::fmt::Debug for PkixAttributeSet {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("PkixAttributeSet{{"))?;
		f.write_fmt(format_args!("types : {},", self.types.get_value()))?;
		f.write_fmt(format_args!("value : {:?}", self.value))?;
		f.write_fmt(format_args!("}}"))
	}	
}


#[asn1_sequence()]
#[derive(Clone,Serialize,Deserialize)]
pub struct PkixExtension {
	#[serde(alias="id")]
	pub types :Asn1Object,
	#[serde(default="pkix_extension_critical_default")]
	pub critical :Asn1Opt<Asn1Boolean>,
	#[serde(default="pkix_extension_value_default")]
	pub value :Asn1OctData,
}

impl std::fmt::Debug for PkixExtension {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_fmt(format_args!("PkixExtension{{"))?;
		f.write_fmt(format_args!("types : {},", self.types.get_value()))?;
		let mut bval :bool = false;
		if self.critical.val.is_some() {
			bval = self.critical.val.as_ref().unwrap().val;
		}
		f.write_fmt(format_args!("critical : {},",bval))?;
		f.write_fmt(format_args!("value : {:?}", self.value.data))?;
		f.write_fmt(format_args!("}}"))
	}	
}


fn pkix_extension_value_default() -> Asn1OctData {
	Asn1OctData::init_asn1()
}

fn pkix_extension_critical_default() -> Asn1Opt<Asn1Boolean> {
	Asn1Opt::init_asn1()
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct X509RequestBuildConfig {
	#[serde(default="x509build_pkixname_default")]
	pub subject :PkixName,
	#[serde(alias="signaturealgorithm",default = "x509build_signature_algorithm_default")]	
	pub signature_algorithm :SignatureAlgorithm,
	#[serde(default="pkix_attribute_set_default")]
	pub attributes :Vec<PkixAttributeSet>,
	#[serde(default="pkix_extension_default")]
	pub extensions :Vec<PkixExtension>,
	#[serde(alias="extraextensions",default="pkix_extension_default")]
	pub extra_extensions :Vec<PkixExtension>,
	#[serde(alias="dnsnames",default = "array_string_default")]
	pub dns_names :Vec<String>,
	#[serde(alias="emailaddresses",default = "array_string_default")]
	pub email_addresses:Vec<String>,
	#[serde(alias="ipaddresses",default = "array_string_default")]
	pub ip_addresses :Vec<String>,
	#[serde(default = "array_string_default")]
	pub uris :Vec<String>,
}

fn pkix_extension_default() -> Vec<PkixExtension> {
	vec![]
}

fn pkix_attribute_set_default() -> Vec<PkixAttributeSet> {
	vec![]
}

impl X509RequestBuildConfig {
	pub fn new() -> Self {
		Self {
			subject :PkixName::new(),
			signature_algorithm: SignatureAlgorithm::SHA256WithRSA,
			attributes : vec![],
			extensions : vec![],
			extra_extensions :vec![],
			dns_names : vec![],
			email_addresses :vec![],
			ip_addresses : vec![],
			uris : vec![],
		}
	}
}


#[derive(Clone)]
#[derive(Debug,Serialize,Deserialize)]
#[serde(rename_all="lowercase")]
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
#[derive(Clone,Serialize,Deserialize)]
pub struct X509BuildConfig {
	#[serde(default = "x509build_version_default")]
	pub version :i64,
	#[serde(default = "x509build_serial_number_default",serialize_with="bigint_serialize",deserialize_with="bigint_deserialize",alias="serialnumber")]
	pub serial_number  :BigInt,
	#[serde(default = "x509build_basic_constraints_valid_default",alias="basicconstraintsvalid")]
	pub basic_constraints_valid :bool,
	#[serde(default = "x509build_is_ca_default",alias="isca")]
	pub is_ca :bool,
	#[serde(default = "x509build_max_path_len_default",alias="maxpathlen")]
	pub max_path_len : i64,
	#[serde(default = "x509build_max_path_zero_default",alias="maxpathlenzero")]
	pub max_path_zero :bool,
	#[serde(default = "x509build_signature_algorithm_default",alias="signaturealgorithm")]
	pub signature_algorithm :SignatureAlgorithm,
	#[serde(default = "x509build_pkixname_default")]
	pub issuer :PkixName,
	#[serde(default = "x509build_pkixname_default")]
	pub subject : PkixName,
	#[serde(default = "x509build_before_default", serialize_with= "date_time_serialize", deserialize_with = "date_time_deserialize",alias="notbefore")]
	pub not_before :DateTime<Utc>,
	#[serde(default = "x509build_after_default", serialize_with= "date_time_serialize", deserialize_with = "date_time_deserialize",alias="notafter")]
	pub not_after :DateTime<Utc>,
	#[serde(default = "x509build_key_usage_default",alias="keyusage")]
	pub key_usage :Vec<KeyUsage>,
	#[serde(default = "x509build_subject_key_id_default",alias="subjectkeyid")]
	pub subject_key_id :Vec<u8>,
	#[serde(default = "array_string_default",alias="ipaddresses")]
	pub ip_addresses :Vec<String>,
	#[serde(default = "array_string_default",alias="emailaddresses")]
	pub email_addresses :Vec<String>,
	#[serde(default = "array_string_default",alias="dnsnames")]
	pub dns_names :Vec<String>,
	#[serde(default = "array_string_default")]
	pub uris :Vec<String>,
	#[serde(default = "array_string_default",alias="excludedipranges")]
	pub ex_ip_ranges :Vec<String>,
	#[serde(default = "array_string_default",alias="excludedemailaddresses")]
	pub ex_email_addresses :Vec<String>,
	#[serde(default = "array_string_default",alias="excludeddnsdomains")]
	pub ex_dns_names :Vec<String>,
	#[serde(default = "array_string_default",alias="excludeduridomains")]
	pub ex_uris :Vec<String>,
	#[serde(default = "array_string_default",alias="permittedipranges")]
	pub perm_ip_ranges :Vec<String>,
	#[serde(default = "array_string_default",alias="permittedemailaddresses")]
	pub perm_email_addresses:Vec<String>,
	#[serde(default = "array_string_default",alias="permitteddnsdomains")]
	pub perm_dns_names :Vec<String>,
	#[serde(default = "array_string_default",alias="permitteduridomains")]
	pub perm_uris :Vec<String>,
	#[serde(default = "x509build_ext_key_usage_default",alias="extkeyusage")]
	pub ext_key_usage :Vec<ExtKeyUsage>,
	#[serde(default = "array_string_default",alias="unknownextkeyusage")]
	pub unknown_ext_key_usage :Vec<String>,
	#[serde(default = "array_string_default")]
	pub policies :Vec<String>,
	#[serde(default = "x509build_authority_key_id_default",alias="authoritykeyid")]
	pub authority_key_id :Vec<u8>,
	#[serde(default = "array_string_default",alias="ocspserver")]
	pub ocsp_servers :Vec<String>,
	#[serde(default = "array_string_default",alias="issuingcertificateurl")]
	pub issuer_certificate_urls:Vec<String>,
}

fn x509build_version_default() -> i64 {
	/*default version 2*/
	3
}

fn x509build_serial_number_default() -> BigInt {
	zero()
}

fn bigint_serialize<S>(oany :&BigInt,serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
	let c :String = format!("0x{:x}",oany);
	serializer.serialize_str(&c)
}




fn bigint_deserialize<'de, D>(deserializer :D) -> Result<BigInt, D::Error> 
where D: serde::de::Deserializer<'de> {
	let vs :StringVisitor = StringVisitor("".to_string());
	let c :String = format!("{}",deserializer.deserialize_str(vs)?);
	let retv :BigInt ;
	let ores = parse_to_bigint(&c);
	if ores.is_err() {
		let e  : D::Error =  serde::de::Error::custom( ores.err().unwrap().to_string());
		return Err(e);
	}
	retv = ores.unwrap();
	Ok(retv)
}


fn x509build_basic_constraints_valid_default() -> bool {
	false
}

fn x509build_is_ca_default() -> bool {
	false
}

fn x509build_max_path_len_default() -> i64 {
	0
}

fn x509build_max_path_zero_default() -> bool {
	false
}

fn x509build_signature_algorithm_default() -> SignatureAlgorithm {
	SignatureAlgorithm::SHA256WithRSA
}

fn x509build_pkixname_default() -> PkixName {
	PkixName::new()
}

fn x509build_before_default() -> DateTime<Utc> {
	Utc::now()
}

fn x509build_after_default() -> DateTime<Utc> {
	/*20 years with*/
	Utc::now() + Months::new(240)
}

fn date_time_serialize<S>(utime :&DateTime<Utc>,serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
	let c :String = format!("{}", utime.format("%Y-%m-%d %H:%M:%S"));
	serializer.serialize_str(&c)
}


fn date_time_deserialize<'de, D>(deserializer :D) -> Result<DateTime<Utc>, D::Error> 
where D: serde::de::Deserializer<'de> {
	let vs :StringVisitor = StringVisitor("".to_string());
	let mut c :String = format!("{}",deserializer.deserialize_str(vs)?);
	let formats :&str = "%Y-%m-%d %H:%M:%S%z";
	c.push_str("+00:00");
	let ores = DateTime::parse_from_str(&c,formats);
	if ores.is_err() {
		let e  : D::Error =  serde::de::Error::custom( ores.err().unwrap().to_string());
		return Err(e);		
	}
	let retv :DateTime<Utc> = ores.unwrap().into();
	Ok(retv)
}

fn x509build_key_usage_default() -> Vec<KeyUsage> {
	vec![]
}

fn x509build_subject_key_id_default() -> Vec<u8> {
	vec![]
}

fn x509build_ext_key_usage_default() -> Vec<ExtKeyUsage> {
	vec![]
}

fn x509build_authority_key_id_default() -> Vec<u8> {
	vec![]
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
			max_path_zero : false,
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


#[derive(Clone,Serialize,Deserialize)]
pub struct X509VerifyOptionJson {
	#[serde(default = "array_string_default")]
	pub roots :Vec<String>,
	#[serde(default = "array_string_default")]
	pub interns :Vec<String>,
	#[serde(default = "x509build_before_default", serialize_with = "date_time_serialize", deserialize_with = "date_time_deserialize")]
	pub currenttime :DateTime<Utc>,
	#[serde(default = "x509build_key_usage_default")]
	pub key_usage :Vec<KeyUsage>,
	#[serde(default = "x509_vfy_opt_max_constraints_comparisons_default")]
	pub max_constraints_comparisons :i32,
}

impl X509VerifyOptionJson {
	pub fn new() -> Self {
		Self {
			roots :vec![],
			interns :vec![],
			currenttime :Utc::now(),
			key_usage :vec![],
			max_constraints_comparisons : 0,
		}
	}
}


#[derive(Clone)]
pub struct X509VerifyOption {
	rootcerts :HashMap<String,Asn1X509>,
	interncerts :HashMap<String,Asn1X509>,
	issuermap :HashMap<String,Vec<String>>,
	currenttime :DateTime<Utc>,
	key_usage :Vec<KeyUsage>,	
	max_constraints_comparisons :i32,
}

impl std::convert::TryFrom<X509VerifyOptionJson> for X509VerifyOption {
	type Error = Box<dyn std::error::Error>;
	fn try_from(val :X509VerifyOptionJson) -> Result<Self,Box<dyn std::error::Error>> {
		let mut retv :Self = Self::new();

		/*now we should give the */
		for f in val.roots.iter() {
			let code = read_file_into_der(f)?;
			let ores = std::fs::canonicalize(f);
			if ores.is_err() {
				ssllib_new_error!{X509BuildError,"can not convert [{}] abspath error {:?}",f,ores.err().unwrap()}
			}
			let abspath = format!("{}",ores.unwrap().display());
			retv.add_root(&abspath,&code)?;
		}

		for f in val.interns.iter() {
			let code = read_file_into_der(f)?;
			let ores = std::fs::canonicalize(f);
			if ores.is_err() {
				ssllib_new_error!{X509BuildError,"can not convert [{}] abspath error {:?}",f,ores.err().unwrap()}
			}
			let abspath = format!("{}",ores.unwrap().display());
			retv.add_intern(&abspath,&code)?;
		}

		retv.set_current_time(&val.currenttime);
		for k in val.key_usage.iter() {
			retv.add_key_usage(k);
		}

		retv.set_max_comparison(val.max_constraints_comparisons);

		Ok(retv)
	}
}

fn x509_vfy_opt_max_constraints_comparisons_default() -> i32 {
	0
}


impl X509VerifyOption {
	pub fn new() -> Self {
		Self {
			rootcerts :HashMap::new(),
			interncerts : HashMap::new(),
			issuermap :HashMap::new(),
			currenttime : Utc::now(),
			key_usage : vec![],
			max_constraints_comparisons : 0,
		}
	}

	fn _check_insert(&self,fname :&str) -> Result<(),Box<dyn Error>> {

		match self.rootcerts.get(fname) {
			Some(_v) => {
				ssllib_new_error!{X509BuildError,"has already add {}",fname}
			},
			None=>{},
		}
		Ok(())
	}

	pub fn add_root(&mut self, fname :&str,code :&[u8]) -> Result<(),Box<dyn Error>> {	
		let x = self._get_x509(fname,code)?;
		/*now to check for x509 map*/
		let (hashidx,_) = x.get_subject_name()?;
		let mut insertvec:Vec<String> = vec![];
		self._check_insert(fname)?;

		if !x.is_self_signed() {
			ssllib_new_error!{X509BuildError,"[{}] not root", fname}
		}

		match self.issuermap.get(&hashidx) {
			Some(_v) => {
				insertvec = _v.clone();
			},
			None => {
			}
		}

		insertvec.push(format!("{}",fname));
		self.issuermap.insert(format!("{}",hashidx),insertvec);
		self.rootcerts.insert(format!("{}",fname),x);
		Ok(())
	}


	fn _get_x509(&self, _fname :&str,code :&[u8]) -> Result<Asn1X509,Box<dyn Error>> {
		let mut x :Asn1X509 = Asn1X509::init_asn1();
		let _ = x.decode_asn1(code)?;
		return Ok(x);
	}

	pub fn add_intern(&mut self, fname :&str,code :&[u8]) -> Result<(),Box<dyn Error>> {
		let x = self._get_x509(fname,code)?;
		let (hashidx,_) = x.get_subject_name()?;
		let mut insertvec:Vec<String>=vec![];
		self._check_insert(fname)?;
		if x.is_self_signed() {
			ssllib_new_error!{X509BuildError,"[{}] self signed for root",fname}
		}

		match self.issuermap.get(&hashidx) {
			Some(_v) => {
				insertvec = _v.clone();
			},
			None => {
			}
		}

		insertvec.push(format!("{}",fname));
		self.issuermap.insert(format!("{}",hashidx),insertvec);
		self.interncerts.insert(format!("{}",fname),x);
		Ok(())
	}

	pub fn get_root_certs(&mut self) -> Result<Vec<Asn1X509>,Box<dyn Error>> {
		let mut retv :Vec<Asn1X509> = vec![];

		for (_,v) in self.rootcerts.iter() {
			retv.push(v.clone());
		}

		return Ok(retv);
	}

	pub fn get_intern_certs(&mut self) -> Result<Vec<Asn1X509>,Box<dyn Error>> {
		let mut retv :Vec<Asn1X509> = vec![];

		for (_,v) in self.interncerts.iter() {
			retv.push(v.clone());
		}


		return Ok(retv);
	}

	pub fn add_key_usage(&mut self, usage :&KeyUsage) -> usize {
		self.key_usage.push(usage.clone());
		return self.key_usage.len();
	}

	pub fn set_max_comparison(&mut self, val :i32) -> i32 {
		let retv :i32 = self.max_constraints_comparisons;
		self.max_constraints_comparisons = val;
		retv
	}

	pub fn key_usage_in(&self, usage :&KeyUsage) -> i32 {
		let mut  ival :i32 = -1;
		let mut idx :usize = 0;
		for v in self.key_usage.iter() {
			if v == usage {
				ival = idx as i32;
				break;
			}
			idx += 1;
		}
		return ival;
	}

	pub fn set_current_time(&mut self, ct :&DateTime<Utc>) -> DateTime<Utc> {
		let retv :DateTime<Utc> = self.currenttime.clone();
		self.currenttime = ct.clone();
		retv
	}

	pub fn get_current_time(&self) -> DateTime<Utc> {
		return self.currenttime.clone();
	}

	fn _check_email_address_match(&self, email :&str , filters :&Vec<String>, okval :bool) -> Result<bool,Box<dyn Error>> {
		if email.len() == 0 {
			if okval {
				return Ok(true);	
			} else {
				return Ok(false);
			}		
		}

		let local :String;
		let domain :String;

		let esarr :Vec<&str> = email.split("@").collect();
		if esarr.len() > 1 {
			local = format!("{}",esarr[0]);
			domain = format!("{}",esarr[1]);
		} else {
			local = "".to_string();
			domain = format!("{}",esarr[0]);
		}

		for f in filters {
			let sarr :Vec<&str> = f.split("@").collect();
			if sarr.len() > 1 {
				if sarr[0] == local && sarr[1]  == domain {
					return Ok(true);
				}
			} else {
				if sarr[0] == domain {
					return Ok(true);
				}
			}
		}
		return Ok(false);
	}

	fn _revers_domain_names(&self, name :&str) -> Result<Vec<String>,Box<dyn Error>> {
		let mut retv :Vec<String> = vec![];
		let cbytes :Vec<u8> = name.as_bytes().to_vec().into_iter().collect();
		let mut idx :usize;
		let mut lastidx :usize;
		idx = cbytes.len() - 1;
		lastidx = idx;

		loop {
			if cbytes[idx] == '.' as u8 {
				let curs :String = String::from_utf8_lossy(&cbytes[idx..lastidx]).to_string();
				retv.push(curs);
				if idx == 0 {
					break;
				}
				lastidx = idx - 1;
			}

			if idx == 0 {
				break;
			}

			idx -= 1;
		}

		if lastidx > idx {
			let curs :String = String::from_utf8_lossy(&cbytes[idx..lastidx]).to_string();
			retv.push(curs);
		}

		if retv.len() > 0 && retv[0].len() == 0 {
			ssllib_new_error!{X509BuildError,"[{}] not valid dns name",name}
		}
		Ok(retv)
	}

	fn _check_dns_name(&self,dnsname :&str , filters :&Vec<String>,okval :bool) -> Result<bool,Box<dyn Error>> {
		let domainlabels :Vec<String> = self._revers_domain_names(dnsname)?;
		let mut idx :usize;
		if domainlabels.len() == 0  {
			if okval {
				return Ok(true);
			} else {
				return Ok(false);
			}
		}
		for f in filters.iter() {
			let mut nf :String = format!("{}",f);
			let mut musthassub :bool = false;
			if nf.starts_with(".") {
				nf = nf[1..].to_string();
				musthassub = true;
			}

			let filterlable = self._revers_domain_names(&nf)?;

			if domainlabels.len() < filterlable.len() || (
				musthassub && domainlabels.len() == filterlable.len()) {
				continue;
			}


			idx = 0;
			let mut matched :bool = true;
			while idx < filterlable.len() {
				if filterlable[idx] != domainlabels[idx] {
					matched = false;
					break;
				}
				idx += 1;
			}

			if matched {
				return Ok(true);
			}
		}
		return Ok(false);
	}

	fn _check_uri(&self, uri :&str, filters:&Vec<String>, okval :bool) -> Result<bool, Box<dyn Error>> {
		let nurl :url::Url = url::Url::parse(uri)?;
		let nhost :String;
		if nurl.host_str().is_some() {
			nhost = format!("{}",nurl.host_str().unwrap());
		} else {
			nhost = "".to_string();
		}
		let domainlabels :Vec<String> = self._revers_domain_names(&nhost)?;

		if domainlabels.len() == 0 {
			if okval {
				return Ok(true);
			} else {
				return Ok(false);
			}
		}

		let mut idx :usize;

		for f in filters.iter() {
			let curl :url::Url = url::Url::parse(f)?;
			let chost :String ;
			if curl.host_str().is_some() {
				chost = format!("{}",curl.host_str().unwrap());
			} else {
				continue;
			}
			let filterlable :Vec<String> = self._revers_domain_names(&chost)?;

			if domainlabels.len() < filterlable.len()  {
				continue;
			}


			idx = 0;
			let mut matched :bool = true;
			while idx < filterlable.len() {
				if filterlable[idx] != domainlabels[idx] {
					matched = false;
					break;
				}
				idx += 1;
			}

			if matched {
				return Ok(true);
			}
		}

		return Ok(false);
	}

	fn _check_ip_range(&self, ipaddr :&str, ipgranges :&Vec<String>, okval : bool) -> Result<bool,Box<dyn Error>> {
		Ok(false)
	}

	fn _check_cert(&self,cert :&Asn1X509,parent :&Asn1X509) -> Result<(),Box<dyn Error>> {
		let certbuild = cert.to_export_build()?;
		let parentbuild = parent.to_export_build()?;
		/*now to */
		if self.currenttime < certbuild.not_before || self.currenttime > certbuild.not_after {
			ssllib_new_error!{X509BuildError,"current time {} not in {} => {}  time", self.currenttime.format("%Y-%m-%d %H:%M:%S"),certbuild.not_before.format("%Y-%m-%d %H:%M:%S"),certbuild.not_after.format("%Y-%m-%d %H:%M:%S")}
		}

		if self.currenttime < parentbuild.not_before || self.currenttime > parentbuild.not_after {
			ssllib_new_error!{X509BuildError,"current time {} not in {} => {}  time", self.currenttime.format("%Y-%m-%d %H:%M:%S"),parentbuild.not_before.format("%Y-%m-%d %H:%M:%S"),parentbuild.not_after.format("%Y-%m-%d %H:%M:%S")}
		}

		/*now to check for value*/
		if parentbuild.ex_email_addresses.len() > 0 {
			for f in certbuild.email_addresses.iter() {
				let retb = self._check_email_address_match(f, &parentbuild.ex_email_addresses,false)?;
				if retb {
					ssllib_new_error!{X509BuildError,"{} email in ex_email_addresses {:?}", f, parentbuild.ex_email_addresses}
				}
			}
		}

		if parentbuild.perm_email_addresses.len() > 0 {
			for f in certbuild.email_addresses.iter() {
				let retb = self._check_email_address_match(f,&parentbuild.perm_email_addresses,true)?;
				if retb {
					ssllib_new_error!{X509BuildError,"{} email not in perm_email_addresses {:?}",f,parentbuild.perm_email_addresses}
				}
			}
		}

		if parentbuild.ex_dns_names.len() > 0 {
			for f in certbuild.dns_names.iter() {
				let retb = self._check_dns_name(f,&parentbuild.ex_dns_names,false)?;
				if retb {
					ssllib_new_error!{X509BuildError,"{} dns in ex_dns_names {:?}",f, parentbuild.ex_dns_names}
				}
			}
		}

		if parentbuild.perm_dns_names.len() > 0 {
			for f in certbuild.dns_names.iter() {
				let retb = self._check_dns_name(f,&parentbuild.perm_dns_names,true)?;
				if !retb {
					ssllib_new_error!{X509BuildError,"{} dns not in perm_dns_names {:?}",f, parentbuild.perm_dns_names}
				}
			}
		}

		if parentbuild.perm_uris.len() > 0 {
			for f in certbuild.uris.iter() {
				let retb = self._check_uri(f,&parentbuild.perm_uris,true)?;
				if !retb {
					ssllib_new_error!{X509BuildError,"{} uri not in perm_uris {:?}",f, parentbuild.perm_uris}
				}
			}
		}

		if parentbuild.ex_uris.len() > 0 {
			for f in certbuild.uris.iter() {
				let retb = self._check_uri(f,&parentbuild.ex_uris,false)?;
				if retb {
					ssllib_new_error!{X509BuildError,"{} uri not in ex_uris {:?}",f, parentbuild.ex_uris}
				}
			}
		}

		if parentbuild.perm_ip_ranges.len() > 0 {
			for f in certbuild.ip_addresses.iter() {
				let retb = self._check_ip_range(f,&parentbuild.perm_ip_ranges,true)?;
				if !retb {
					ssllib_new_error!{X509BuildError,"{} uri not in perm_ip_ranges {:?}",f, parentbuild.perm_ip_ranges}
				}
			}
		}

		if parentbuild.ex_ip_ranges.len() > 0 {
			for f in certbuild.ip_addresses.iter() {
				let retb = self._check_ip_range(f,&parentbuild.ex_ip_ranges,false)?;
				if retb {
					ssllib_new_error!{X509BuildError,"{} uri not in perm_ip_ranges {:?}",f, parentbuild.ex_ip_ranges}
				}
			}
		}

		Ok(())
	}

	fn _check_ca_mode(&self,x509cert :&Asn1X509,chainsize :usize) -> Result<(),Box<dyn Error>> {
		let certbuild :X509BuildConfig = x509cert.to_export_build()?;
		if !certbuild.is_ca || !certbuild.basic_constraints_valid {
			if !x509cert.is_self_signed() {
				ssllib_new_error!{X509BuildError,"not authorized cert"}
			}
		}

		if certbuild.basic_constraints_valid && certbuild.max_path_len > 0 {
			if certbuild.max_path_len as usize >= chainsize {
				ssllib_new_error!{X509BuildError,"greater than max_path_len {}", certbuild.max_path_len}
			}
		}

		Ok(())
	}


	pub fn verify_cert(&self,cert :&Asn1X509) -> Result<Vec<Asn1X509>,Box<dyn Error>> {
		let mut retv :Vec<Asn1X509> = vec![];
		let mut scaned :Vec<Asn1X509>;
		let mut curcert :Asn1X509 = cert.clone();
		let mut matched :bool;

		loop {
			let retb :bool = curcert.is_self_signed();
			if retb {
				retv.push(curcert.clone());
				return Ok(retv);
			}

			retv.push(curcert.clone());
			scaned = vec![];

			/*now to check */
			let (hashidx,_) = curcert.get_issuer_name()?;
			match self.issuermap.get(&hashidx) {
				Some(_v) => {
					for _k in _v.iter() {
						match self.rootcerts.get(_k) {
							Some(_x509) => {
								let ores = curcert.verify_cert(_x509);
								if ores.is_ok() {
									let retb = ores.unwrap();
									if retb {
										scaned.push(_x509.clone());
									}
								}
							},
							None => {},
						}

						match self.interncerts.get(_k) {
							Some(_x509) => {
								let ores = curcert.verify_cert(_x509);
								if ores.is_ok() {
									let retb = ores.unwrap();
									if retb {
										scaned.push(_x509.clone());
									}
								}
							},
							None => {},
						}
					}

				},
				None => {
					ssllib_new_error!{X509BuildError,"can not find cert for [{}]",hashidx}
				}
			}

			if scaned.len() == 0 {
				ssllib_new_error!{X509BuildError,"no candidate for cert"}
			}

			/*now to give*/
			matched = false;
			for sx509 in scaned.iter() {
				let ores = self._check_cert(&curcert,sx509);
				if ores.is_ok() {
					/*we check twice*/
					let ores = self._check_cert(cert,sx509);
					if ores.is_ok() {
						let ores = self._check_ca_mode(sx509,retv.len());
						if ores.is_ok() {
							curcert = sx509.clone();
							matched = true;
							break;
						} else {
							ssllib_log_error!("not ca mode {:?}",ores.err().unwrap());
						}

					}

				}
			}

			if !matched {
				ssllib_new_error!{X509BuildError,"no matched"}
			}
		}
	}
}