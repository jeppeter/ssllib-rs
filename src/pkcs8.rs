#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};
use asn1obj::consts::*;
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::strop::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use asn1obj::*;

use std::error::Error;
use std::io::{Write};


use crate::*;
use crate::config::*;
use crate::consts::*;
use crate::x509::*;

ssllib_error_class!{SslPkcs8Error}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs8PrivKeyInfoElem {
	pub version :Asn1Integer,
	pub pkeyalg : Asn1X509Algor,
	pub pkey : Asn1OctData,
	pub attributes : Asn1Opt<Asn1ImpSet<Asn1X509Attribute,0>>,
}

impl Asn1Pkcs8PrivKeyInfoElem {
	pub fn get_cmd(&self, _cfg :&ConfigValue) -> Result<ConfigValue,Box<dyn Error>> {
		let mut retv :ConfigValue = ConfigValue::new("{}").unwrap();
		let types = self.pkeyalg.get_algorithm()?;
		if types == OID_EC_PUBLICK_KEY {
			let _ = retv.set_str(KEY_JSON_TYPE,KEY_JSON_EC)?;
			let mut eccfg :ConfigValue = ConfigValue::new("{}").unwrap();
			let ores  = self.pkeyalg.get_param()?;
			if ores.is_none() {
				ssllib_new_error!{SslPkcs8Error,"none pkeyalg param"}
			}
			let anyv :Asn1Any = ores.unwrap();
			if anyv.tag as u8 != ASN1_OBJECT_FLAG {
				ssllib_new_error!{SslPkcs8Error,"not valid tag [0x{:x}] != ASN1_OBJECT_FLAG[0x{:x}]",anyv.tag,ASN1_OBJECT_FLAG}
			}
			let bcode = anyv.encode_asn1()?;
			let mut anyobj :Asn1Object = Asn1Object::init_asn1();
			let _ = anyobj.decode_asn1(&bcode)?;
			if anyobj.get_value() == OID_SECP384R1 {
				let _ = eccfg.set_str(KEY_JSON_TYPE,KEY_JSON_SECP384R1)?;
			} else {
				ssllib_new_error!{SslPkcs8Error,"not suport object [{}]", anyobj.get_value()}
			}
			let _ = retv.set_config(KEY_JSON_EC,&eccfg)?;			
		} else {
			ssllib_new_error!{SslPkcs8Error,"not valid pkeyalg [{}]", types}
		}
		Ok(retv)
	}

}

//#[asn1_sequence(debug=enable)]
#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs8PrivKeyInfo {
	pub elem : Asn1Seq<Asn1Pkcs8PrivKeyInfoElem>,
}


