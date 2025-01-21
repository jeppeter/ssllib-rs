#[allow(unused_imports)]
use super::{debug_trace,debug_buffer_trace,format_buffer_log};
#[allow(unused_imports)]
use super::loglib::{log_get_timestamp,log_output_function,init_log};

#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};

use base64;
use std::error::Error;
use std::io::Write;

extargs_error_class!{StrOpError}

#[allow(dead_code)]
pub fn encode_base64(bb :&[u8]) -> String {
	return base64::encode(bb);
}

pub fn out_buffer_data(code :&[u8],file :&str,lineno:u32,fmtstr :&str) -> Result<(),Box<dyn Error>> {
	let mut c :String = format!("[{}:{}]",file,lineno);
	let mut outf = std::io::stdout();
	c.push_str(": ");
	if fmtstr.len() > 0 {
		c.push_str(&(format!("{}",fmtstr)));	
	}

	let _ptr :*const u8 = code.as_ptr() as *const u8;
	let  mut _ci :usize;
	let _totallen: usize = code.len();
	let mut _lasti :usize = 0;
	let mut _nb :u8;
	c.push_str(&format!(" buffer [{:?}][{}]",_ptr,_totallen));
	_ci = 0;
	while _ci < _totallen {
		if (_ci % 16) == 0 {
			if _ci > 0 {
				c.push_str("    ");
				while _lasti < _ci {
					unsafe{
						_nb = *_ptr.offset(_lasti as isize);	
					}

					if _nb >= 0x20 && _nb <= 0x7e {
						c.push(_nb as char);
					} else {
						c.push_str(".");
					}
					_lasti += 1;
				}
			}
			if c.len() > 1024 {
				outf.write_all(c.as_bytes())?;
				c = "".to_string();
			}
			c.push_str(&format!("\n0x{:08x}:", _ci));
		}
		unsafe {_nb = *_ptr.offset(_ci as isize);}			
		c.push_str(&format!(" 0x{:02x}",_nb));
		_ci += 1;
	}

	if _lasti < _ci {
		while (_ci % 16) != 0 {
			c.push_str("     ");
			_ci += 1;
		}

		c.push_str("    ");

		while _lasti < _totallen {
			unsafe {_nb = *_ptr.offset(_lasti as isize);}				
			if _nb >= 0x20 && _nb <= 0x7e {
				c.push(_nb as char);
			} else {
				c.push_str(".");
			}
			_lasti += 1;
		}
		c.push_str("\n");
	}
	let _ = outf.write_all(c.as_bytes())?;
	Ok(())
}

#[allow(dead_code)]
pub fn decode_base64(instr :&str) -> Result<Vec<u8>,Box<dyn Error>> {
	let res = base64::decode(instr);
	if res.is_err() {
		let err = res.err().unwrap();
		extargs_new_error!{StrOpError,"can not parse [{}] for base64 error [{:?}]", instr,err}
	}
	let bv = res.unwrap();
	Ok(bv)
}

#[allow(dead_code)]
pub fn parse_u64(instr :&str) -> Result<u64,Box<dyn Error>> {
	let mut cparse = format!("{}",instr);
	let mut base :u32 = 10;
	let retv :u64;
	if cparse.starts_with("0x") || cparse.starts_with("0X") {
		cparse = cparse[2..].to_string();
		base = 16;
	} else if cparse.starts_with("x") || cparse.starts_with("X") {
		cparse = cparse[1..].to_string();
		base = 16;
	}

	match u64::from_str_radix(&cparse,base) {
		Ok(v) => {
			retv = v;
		},
		Err(e) => {
			extargs_new_error!{StrOpError, "parse [{}] error [{:?}]", instr, e}
		}
	}
	Ok(retv)
}

