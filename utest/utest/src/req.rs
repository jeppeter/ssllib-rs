use reqwest::blocking::{Client,  Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use extargsparse_worker::namespace::{NameSpaceEx};
use super::{debug_error,format_str_log};
use super::loglib::*;
use std::error::Error;
use std::str::FromStr;
use std::io::Read;



pub fn reqpost_data(url :&str,ns :NameSpaceEx, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let mut bld = Client::builder();
	let timeout = ns.get_int("timeout");
	if timeout != 0 {
		bld = bld.timeout(std::time::Duration::from_secs(timeout as u64));
	}

	let client = bld.build()?;
	let mut reqbld :reqwest::blocking::RequestBuilder = client.post(url);
	let mut hdrmap :HeaderMap = HeaderMap::new();
	let mut hdrname :HeaderName;
	let mut hdrval :HeaderValue;
	let mut resp : Response;
	hdrname = HeaderName::from_str("Content-Type")?;
	hdrval = HeaderValue::from_str("application/timestamp-query")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());

	hdrname = HeaderName::from_str("Accept")?;
	hdrval = HeaderValue::from_str("application/timestamp-reply")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());

	hdrname = HeaderName::from_str("User-Agent")?;
	hdrval = HeaderValue::from_str("Transport")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());


	hdrname = HeaderName::from_str("Cache-Control")?;
	hdrval = HeaderValue::from_str("no-cache")?;
	hdrmap.insert(hdrname.clone(),hdrval.clone());

	reqbld = reqbld.headers(hdrmap);
	reqbld = reqbld.body(data.to_vec().clone());

	loop {
		let ores = reqbld.try_clone();
		if ores.is_none() {
			debug_error!("clone error");
			continue;
		}
		let cbld = ores.unwrap();
		let ores = cbld.send();
		if ores.is_err() {
			let e = ores.err().unwrap();
			debug_error!("clone {:?}", e);
			continue;
		}
		resp = ores.unwrap();
		break;
	}

	let totalsize = resp.content_length().unwrap();
	let mut retv :Vec<u8> = vec![];
	let mut cbuf = [0;2096];
	while retv.len() < totalsize as usize {
		let rcnt = resp.read(&mut cbuf)?;
		for i in 0..rcnt {
			retv.push(cbuf[i]);
		}
	}
	Ok(retv)

}
