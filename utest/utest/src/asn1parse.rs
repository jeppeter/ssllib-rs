#[allow(unused_imports)]
use extargsparse_codegen::{extargs_load_commandline,ArgSet,extargs_map_function};
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};
#[allow(unused_imports)]
use extargsparse_worker::namespace::{NameSpaceEx};
#[allow(unused_imports)]
use extargsparse_worker::argset::{ArgSetImpl};
use extargsparse_worker::parser::{ExtArgsParser};
use extargsparse_worker::funccall::{ExtArgsParseFunc};
use asn1obj::asn1impl::Asn1Op;

use std::cell::RefCell;
use std::sync::Arc;
use std::error::Error;
use std::boxed::Box;
#[allow(unused_imports)]
use regex::Regex;
#[allow(unused_imports)]
use std::any::Any;

use lazy_static::lazy_static;
use std::collections::HashMap;

use super::*;
use super::loglib::*;
use super::pemlib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use std::io::Write;
use asn1obj::consts::*;
use asn1obj::base::*;


extargs_error_class!{Asn1ParseError}


fn asn1_parse_out<T : std::io::Write>(code :&[u8],outf :&mut T,tabs :i32,offseti :usize) -> Result<(),Box<dyn Error>> {
	let mut curv :usize = 0;
	let capv :usize = code.len();

	while curv < code.len() {
		let mut oany :Asn1Any = Asn1Any::init_asn1();
		let ores = oany.decode_asn1(&(code[curv..capv]));

		if ores.is_err() {
			extargs_new_error!{Asn1ParseError,"parse at [0x{:x}] offset error", curv + offseti}
		}
		let stepv = ores.unwrap();
		let btag = oany.tag as u8;
		let incode = oany.encode_asn1()?;
		if btag == ASN1_BOOLEAN_FLAG {
			let mut basn1 :Asn1Boolean = Asn1Boolean::init_asn1();
			let _ = basn1.decode_asn1(&incode)?;
			if basn1.val {
				write_tab_line!(outf,tabs,"[0x{:x}]: Asn1Boolean True", curv + offseti);
			} else {
				write_tab_line!(outf,tabs,"[0x{:x}]: Asn1Boolean False", curv + offseti);
			}

		} else if btag == ASN1_INTEGER_FLAG {
			let mut iasn1 :Asn1BigNum = Asn1BigNum::init_asn1();
			let _ = iasn1.decode_asn1(&incode)?;
			let bn :Vec<u8> = iasn1.val.to_bytes_be();
			write_tab_buffer!(outf,tabs,bn.as_ptr(),bn.len(),"[0x{:x}] Asn1BigNum value", curv + offseti);
		} else if btag == ASN1_BIT_STRING_FLAG {
			let mut bitasn1 :Asn1BitData = Asn1BitData::init_asn1();
			let ores = bitasn1.decode_asn1(&incode);
			if ores.is_err() {
				let mut bitflag :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
				let _ = bitflag.decode_asn1(&incode)?;
				write_tab_buffer!(outf,tabs,bitflag.data.as_ptr(),bitflag.data.len(),"[0x{:x}] Asn1BitDataFlag value flag 0x{:02x}",curv + offseti,(bitflag.flag & 0xff) as u8);
			} else {
				write_tab_buffer!(outf,tabs,bitasn1.data.as_ptr(),bitasn1.data.len(),"[0x{:x}] Asn1BitData value",curv + offseti);	
			}			
		} else if btag == ASN1_OCT_STRING_FLAG {
			let mut octasn1 :Asn1OctData = Asn1OctData::init_asn1();
			let _ = octasn1.decode_asn1(&incode)?;
			write_tab_buffer!(outf,tabs,octasn1.data.as_ptr(),octasn1.data.len(),"[0x{:x}] Asn1OctData value",curv + offseti);
		} else if btag == ASN1_NULL_FLAG {
			write_tab_line!(outf,tabs,"[0x{:x}] Asn1Null",curv + offseti);
		} else if btag == ASN1_OBJECT_FLAG {
			let mut objasn1 :Asn1Object = Asn1Object::init_asn1();
			let _ = objasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs,"[0x{:x}] Asn1Object [{}]", curv+ offseti,objasn1.get_value());
		} else if btag == ASN1_ENUMERATED_FLAG {
			let mut enumasn1 :Asn1Enumerated = Asn1Enumerated::init_asn1();
			let _ = enumasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs ,"[0x{:x}] Asn1Enumerated [{}:0x{:x}]", curv + offseti,enumasn1.val,enumasn1.val);
		} else if btag == ASN1_UTF8STRING_FLAG {
			let mut prntasn1 :Asn1PrintableString = Asn1PrintableString::init_asn1();
			let _ = prntasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs,"[0x{:x}] Utf8String [{}]", curv + offseti, prntasn1.val);
		} else if btag == ASN1_PRINTABLE_FLAG {
			let mut prntasn1 :Asn1PrintableString = Asn1PrintableString::init_asn1();
			let _ = prntasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs,"[0x{:x}] PrintableString [{}]", curv + offseti, prntasn1.val);
		} else if btag == ASN1_T61STRING_FLAG {
			let mut prntasn1 :Asn1PrintableString = Asn1PrintableString::init_asn1();
			let _ = prntasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs,"[0x{:x}] T61String [{}]", curv + offseti, prntasn1.val);
		} else if btag == ASN1_PRINTABLE2_FLAG {
			let mut prntasn1 :Asn1IA5String = Asn1IA5String::init_asn1();
			let _ = prntasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs,"[0x{:x}] Printable2String [{}]", curv + offseti, prntasn1.val);
		} else if btag == ASN1_UTCTIME_FLAG {
			let mut utcasn1 :Asn1Time = Asn1Time::init_asn1();
			let _ = utcasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs,"[0x{:x}] UtcTime [{}]", curv + offseti, utcasn1.get_value_str());
		} else if btag == ASN1_GENERALTIME_FLAG {
			let mut utcasn1 :Asn1Time = Asn1Time::init_asn1();
			let _ = utcasn1.decode_asn1(&incode)?;
			write_tab_line!(outf,tabs,"[0x{:x}] GeneralTime [{}]", curv + offseti, utcasn1.get_value_str());
		} else if btag == ASN1_SEQ_MASK {
			let mut boffset : usize = curv + offseti;
			boffset += incode.len() - oany.content.len();
			write_tab_line!(outf,tabs,"[0x{:x}] Sequence size [{}:0x{:x}]", curv + offseti,incode.len(),incode.len());
			let _ = asn1_parse_out(&(oany.content),outf,tabs + 1, boffset)?;
		} else if btag == ASN1_SET_MASK {
			let mut boffset : usize = curv + offseti;
			boffset += incode.len() - oany.content.len();
			write_tab_line!(outf,tabs,"[0x{:x}] Set size [{}:0x{:x}]", curv + offseti,incode.len(),incode.len());
			let _ = asn1_parse_out(&(oany.content),outf,tabs + 1, boffset)?;
		} else if (btag & ASN1_IMP_SET_MASK) == ASN1_IMP_SET_MASK {
			let ctag = (oany.tag as u8 ) & ASN1_PRIMITIVE_TAG ;
			let mut boffset : usize = curv + offseti;
			boffset += incode.len() - oany.content.len();
			write_tab_line!(outf,tabs,"[0x{:x}] ImpSet tag [{}:0x{:x}] size [{}:0x{:x}]", curv + offseti, ctag,ctag,incode.len(),incode.len());
			let _ = asn1_parse_out(&(oany.content),outf,tabs + 1, boffset)?;
		} else if (btag & ASN1_IMP_FLAG_MASK) == ASN1_IMP_FLAG_MASK {
			let ctag = (oany.tag as u8 ) & ASN1_PRIMITIVE_TAG ;
			let mut boffset : usize = curv + offseti;
			boffset += incode.len() - oany.content.len();
			write_tab_line!(outf,tabs,"[0x{:x}] Imp tag [{}:0x{:x}] size [{}:0x{:x}]", curv + offseti, ctag,ctag,incode.len(),incode.len());
			let _ = asn1_parse_out(&(oany.content),outf,tabs + 1, boffset)?;
		} else {
			extargs_new_error!{Asn1ParseError,"parse at [0x{:x}] offset", curv + offseti}
		}
		curv += stepv;
	}
	Ok(())
}

fn asn1parse_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {	
	let sarr :Vec<String>;
	let mut sout = std::io::stdout();

	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_into_der(f)?;
		let _ = asn1_parse_out(&code, &mut sout,0,0)?;
	}

	Ok(())
}

#[extargs_map_function(asn1parse_handler)]
pub fn load_asn1parse_handler(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = r#"
	{
		"asn1parse<asn1parse_handler>##file ... to dump file asn1 value##" : {
			"$" : "+"
		}
	}
	"#;
	extargs_load_commandline!(parser,cmdline)?;
	Ok(())
}