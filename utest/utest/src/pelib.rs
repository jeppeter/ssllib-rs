use super::*;
use super::fileop::{read_file_bytes};
use ssllib::digest::ssllib_get_digest_operator;
use super::loglib::*;


extargs_error_class!{PeLibError}

pub struct PeHeader {
	pub headersize :usize,
	pub pe32plus :usize,
}

impl PeHeader {
	fn new(pecode :&[u8]) -> Result<Self,Box<dyn Error>> {
		let mut retv :Self = Self {
			headersize : 0,
			pe32plus :  0,
		};
		if pecode.len() < 64 {
			extargs_new_error!{PeLibError,"must at least 64"}
		}
		let mut idx :usize = 0;
		while idx < 4 {
			retv.headersize += (pecode[idx+60] as usize) << (idx * 8);
			idx += 1;
		}
		if pecode.len() < (retv.headersize + 24 + 2) {
			extargs_new_error!{PeLibError,"must at least {} + 24 + 2",retv.headersize}	
		}
		let mut magic :u16 = 0;
		idx = 0;
		while idx < 2 {
			magic += (pecode[retv.headersize + 24 + idx] as u16) << (idx * 8);
			idx += 1;
		}
		if magic == 0x20b {
			retv.pe32plus = 1;
		} else if magic == 0x10b {
			retv.pe32plus = 0;
		} else {
			extargs_new_error!{PeLibError,"0x{:x} not valid magic",magic}
		}
		Ok(retv)
	}
}

pub fn get_pe_header_by_bytes(pecode :&[u8]) -> Result<PeHeader,Box<dyn Error>> {
	let retv :PeHeader = PeHeader::new(&pecode)?;
	return Ok(retv);
}

pub fn pe_get_digest_in_bytes(digestname :&str, pecode :&[u8], times :u32, initv :&[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
	let ores = ssllib_get_digest_operator(&digestname);
	let mut start:usize;
	let mut end :usize;
	let mut incode :Vec<u8>;
	if ores.is_none() {
		extargs_new_error!{PeLibError,"can not find {} digest", digestname}
	}
	let pehdr = get_pe_header_by_bytes(pecode)?;
	let digop = ores.unwrap();

	digop.borrow_mut().init_digest(times,initv)?;
	/*first before header size*/
	start = 0;
	end = pehdr.headersize + 88;
	digop.borrow_mut().digest_update(&pecode[start..end])?;
	/*the place is checksum*/
	start = pehdr.headersize + 88 + 4;
	end = start + 60;
	if pehdr.pe32plus != 0 {
		end += pehdr.pe32plus * 16;
	}
	digop.borrow_mut().digest_update(&pecode[start..end])?;
	/*now at the end*/
	start = end + 8;
	end = pecode.len();
	digop.borrow_mut().digest_update(&pecode[start..end])?;

	/*be 8 bytes alignment*/
	if (pecode.len() % 8) != 0 {
		let nlen :usize = 8 - (pecode.len() % 8);
		incode = vec![];
		while incode.len() != nlen {
			incode.push(0);
		}
		digop.borrow_mut().digest_update(&incode)?;
	}

	return digop.borrow_mut().digest_final();
}

pub fn pe_get_digest(digestname :&str, pefile :&str,times :u32,initv :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let pecode :Vec<u8> = read_file_bytes(pefile)?;
	return pe_get_digest_in_bytes(digestname,&pecode,times,initv);
}

pub fn pe_get_calc_checksum(pecode :&[u8]) -> Result<u16,Box<dyn Error>> {
	let pehdr = get_pe_header_by_bytes(pecode)?;
	let mut retv :u32 = 0;
	let mut size :u32 = 0;

	while (size as usize) < pecode.len() {
		let mut val :u32 = 0;
		if size > (pehdr.headersize as u32  + 90) ||  size < (pehdr.headersize as u32 + 88)  {
			for c in 0..2 {
				val += (pecode[(size+c) as usize] as u32)  << (c * 8) ;
			}
		}

		retv += val;
		retv = 0xffff & (retv + (retv >> 0x10));
		if size < 32 {
			debug_trace!("[{}]=[0x{:x}] checkSum 0x{:x}", size, val, retv);
		}
		size += 2;
	}

	debug_trace!("checkSum 0x{:x}",retv);
	retv = 0xffff & (retv + (retv >> 0x10));
	debug_trace!("checkSum 0x{:x}",retv);
	retv += size;
	debug_trace!("checkSum 0x{:x}",retv);
	Ok(retv as u16)
}

pub fn pe_set_calc_checksum(pecode :&mut [u8]) -> Result<(),Box<dyn Error>> {
	let chksum :u16 = pe_get_calc_checksum(pecode)?;
	let pehdr = PeHeader::new(pecode)?;
	for i in 0..2 {
		pecode[pehdr.headersize + 88 + i] = ((chksum >> (i * 8)) & 0xff ) as u8;
		debug_trace!("0x{:x} set checksum 0x{:x}", pehdr.headersize + 88 + i, (chksum >> (i * 8)) & 0xff );
	}
	Ok(())
}
