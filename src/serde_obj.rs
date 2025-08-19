
use std::error::Error;
use num_bigint::{BigInt};
use num_traits::{zero};
use crate::*;
use asn1obj::base::{Asn1Object,Asn1Any,Asn1OctData,Asn1Boolean};
use asn1obj::asn1impl::{Asn1Op};
use asn1obj::complex::{Asn1Opt};
use serde::ser::{SerializeStruct,SerializeSeq};
ssllib_error_class!{SslSerdeObjError}


#[allow(dead_code)]
pub struct StringVisitor(pub String);

impl<'de> serde::de::Visitor<'de> for StringVisitor {
	type Value = String;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "an string")
	}

	fn visit_str<E>(self, v :&str) -> Result<Self::Value,E>
	where E :Error
	{
		Ok(format!("{}",v))
	}
}

pub fn parse_to_bigint(instr :&str) -> Result<BigInt,Box<dyn Error>> {
	let mut _cparse = format!("{}",instr);
	let mut base :u32 = 10;
	let mut retv :BigInt = zero();
	let mut curv :BigInt ;
	let mut curvi :i32;
	let mut addi :i32 = 0;
	let mut bbchar :String;
	let mut negv :bool = false;
	let cparse :Vec<u8>;
	if _cparse.starts_with("0x") || _cparse.starts_with("0X") {
		_cparse = _cparse[2..].to_string();
		base = 16;
		addi += 2;
	} else if _cparse.starts_with("x") || _cparse.starts_with("X") {
		_cparse = _cparse[1..].to_string();
		base = 16;
		addi += 1;
	}

	if _cparse.starts_with("-") {
		_cparse = _cparse[1..].to_string();
		negv = true;
		addi += 1;
	}

	cparse = _cparse.as_bytes().to_vec();

	if cparse.len() == 0 {
		ssllib_new_error!{SslSerdeObjError,"not valid [{}]",instr};
	}

	let mut lasti :usize = 0;
	let mut idx :i32 = 0;
	while lasti < cparse.len() {
		if base == 10 {
			if cparse[lasti] >= ('0' as u8) && cparse[lasti] <= ('9' as u8) {
				curvi = (cparse[lasti] - ('0' as u8)) as i32;
			} else {
				bbchar = "".to_string();
				if cparse[lasti] >= 0x20 && cparse[lasti] <= 0x7e {
					bbchar.push(cparse[lasti] as char);
				} else {
					bbchar.push_str(&format!("char[0x{:x}]",cparse[lasti]));
				}
				
				ssllib_new_error!{SslSerdeObjError,"[{}] character not valid [{}]", idx + addi,bbchar}
			}
			curv = curvi.into();
			retv *= 10;
			retv += curv;
		} else {
			if cparse[lasti] >= ('0'  as u8) && cparse[lasti] <= ('9' as u8) {
				curvi = (cparse[lasti] - ('0' as u8)) as i32;
			} else if cparse[lasti] >= ('a'  as u8) && cparse[lasti] <= ('f' as u8){
				curvi = (cparse[lasti] - ('a' as u8)) as i32 + 10;
			} else if cparse[lasti] >= ('A' as u8 ) && cparse[lasti] <= ('F' as u8)  { 
				curvi = (cparse[lasti] - ('A' as u8)) as i32 + 10;
			} else {
				bbchar = "".to_string();
				if cparse[lasti] >= 0x20 && cparse[lasti] <= 0x7e {
					bbchar.push(cparse[lasti] as char);
				} else {
					bbchar.push_str(&format!("char[0x{:x}]",cparse[lasti]));
				}

				ssllib_new_error!{SslSerdeObjError,"[{}] character not valid [{}]", idx + addi,bbchar}
			}
			curv = curvi.into();
			retv *= 16;
			retv += curv;
		}
		lasti += 1;
		idx += 1;
	}

	if negv {
		retv = -retv;
	}
	Ok(retv)
}


pub fn asn1_object_serialize<S>(obj :&Asn1Object,serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
	serializer.serialize_str(&obj.get_value())
}




pub fn asn1_object_deserialize<'de, D>(deserializer :D) -> Result<Asn1Object,D::Error> 
where D: serde::de::Deserializer<'de> {
	let vs :StringVisitor = StringVisitor("".to_string());
	let s = format!("{}",deserializer.deserialize_str(vs)?);
	let mut obj :Asn1Object = Asn1Object::init_asn1();
	let ores = obj.set_value(&s);
	if ores.is_err() {
		let e  : D::Error =  serde::de::Error::custom( ores.err().unwrap().to_string());
		return Err(e);
	}
	Ok(obj)
}

pub fn asn1_any_serialize<S>(oany :&Asn1Any,serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
	let mut map = serializer.serialize_struct("Asn1Any",2)?;
	map.serialize_field("tag",&oany.tag)?;
	map.serialize_field("data",&oany.content)?;
	map.end()
}

#[allow(dead_code)]
struct Asn1AnyVisitor(Asn1Any);

impl<'de> serde::de::Visitor<'de> for Asn1AnyVisitor {
	type Value = Asn1Any;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "a map need")
	}



	fn visit_map<A>(self, mut mapv: A) -> Result<Asn1Any, A::Error>
	where A: serde::de::MapAccess<'de>,
	{
		let mut oany :Asn1Any = Asn1Any::init_asn1();
		let mut tagv :Option<u64> = None;
		let mut contentv :Option<Vec<u8>> = None;

		while let Some(key) = mapv.next_key::<String>()? {
			match key.as_str() {
				"tag" => {

					if tagv.is_some() {
						return Err(serde::de::Error::duplicate_field("tag"));
					}
					tagv = Some(mapv.next_value::<u64>()?);
				},
				"content" => {
					if contentv.is_some() {
						return Err(serde::de::Error::duplicate_field("content"));
					}
					contentv = Some(mapv.next_value::<Vec<u8>>()?);
				},
				_ => {

				},
			}
		}

		if tagv.is_some() {
			oany.tag = tagv.as_ref().unwrap().clone();
		}

		if contentv.is_some() {
			oany.content = contentv.as_ref().unwrap().clone();
		}

		Ok(oany)
	}
}



pub fn asn1_any_deserialize<'de, D>(deserializer :D) -> Result<Asn1Any, D::Error> 
where D: serde::de::Deserializer<'de> {
	let visitor :Asn1AnyVisitor = Asn1AnyVisitor(Asn1Any::init_asn1());
	deserializer.deserialize_map(visitor)
}


pub fn asn1_octdata_serialize<S>(oany :&Asn1OctData,serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
	let mut seq = serializer.serialize_seq(Some(oany.data.len()))?;
	for v in oany.data.iter() {
		seq.serialize_element(v)?;
	}
	seq.end()
}

#[allow(dead_code)]
struct Asn1OctDataNSeq(Asn1OctData);

impl<'de> serde::de::Visitor<'de> for Asn1OctDataNSeq {
	type Value = Asn1OctData;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "an array need")
	}



	fn visit_seq<A>(self, mut seq: A) -> Result<Asn1OctData, A::Error>
	where A: serde::de::SeqAccess<'de>,
	{
		let mut odata :Asn1OctData= Asn1OctData::init_asn1();

		while let Some(v) = seq.next_element::<u8>()? {
			odata.data.push(v);
		}
		Ok(odata)

	}
}



pub fn asn1_octdata_deserialize<'de, D>(deserializer :D) -> Result<Asn1OctData, D::Error> 
where D: serde::de::Deserializer<'de> {
	let visitor :Asn1OctDataNSeq = Asn1OctDataNSeq(Asn1OctData::init_asn1());
	deserializer.deserialize_seq(visitor)
}

pub fn asn1_opt_boolean_serialize<S>(oany :&Asn1Opt<Asn1Boolean>,serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
	if oany.val.is_none() {
		/*nothing to handle*/
		return Ok(S::Ok);
	}
	let retv:bool = oany.val.as_ref().unwrap().clone();
	serializer.serialize_bool(retv)
}



pub fn asn1_opt_boolean_deserialize<'de, D>(deserializer :D) -> Result<Asn1Opt<Asn1Boolean>, D::Error> 
where D: serde::de::Deserializer<'de> {
	let ores = deserializer.deserialize_bool();
	let mut val :Asn1Opt<Asn1Boolean> = Asn1Opt::init_asn1();
	if ores.is_err() {
		return Ok(val);
	}
	let bval = ores.unwrap();
	let mut b :Asn1Boolean = Asn1Boolean::init_asn1();
	b.val = bval;
	val.val = Some(b);
	Ok(val)
}

