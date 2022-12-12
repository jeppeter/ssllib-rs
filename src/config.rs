
use crate::{ssllib_error_class,ssllib_new_error};
use std::error::Error;

ssllib_error_class!{SslConfigError}

pub struct ConfigValue {
	val :serde_json::value::Value,
}

impl ConfigValue {
	pub fn new(jsons :&str) -> Result<Self,Box<dyn Error>> {
		let ores = serde_json::from_str(jsons);
		if ores.is_err() {
			let e = ores.err().unwrap();
			ssllib_new_error!{SslConfigError,"can not parse json {:?}\n{}",e,jsons}
		}
		Ok(ConfigValue{
			val : ores.unwrap(),
		})
	}

	fn _split_path(&self,path :&str) -> Result<(Vec<String>,String),Box<dyn Error>> {
		let bname :String = format!("{}",path);
		let sarr : Vec<&str> = bname.split("/").collect();
		let mut dnames :Vec<String> = Vec::new();
		let fname :String;
		if sarr.len() > 1 {
			for i in 0..(sarr.len()-1) {
				dnames.push(format!("{}",sarr[i]));
			}
			fname = format!("{}",sarr[sarr.len()-1]);
		} else {
			fname = format!("{}",path);
		}
		Ok((dnames,fname))
	}


	fn _get_map_path(&self,curpath :&Vec<String>) -> Result<serde_json::value::Value,Box<dyn Error>> {
		let retv :serde_json::value::Value ;
		if curpath.len() == 0 {
			retv = serde_json::json!(self.val.clone());
		} else {
			let mut curmap :serde_json::value::Value;
			curmap = serde_json::json!(self.val.clone());
			for i in 0..curpath.len() {
				if !curmap.is_object() {
					ssllib_new_error!{SslConfigError,"at[{}] not valid map", i}
				}
				let ck = curmap.get(&curpath[i]);
				if ck.is_none() {
					ssllib_new_error!{SslConfigError,"at[{}].[{}] can not get map",i,curpath[i]}
				}
				curmap = serde_json::json!(ck.unwrap().clone());
			}

			if !curmap.is_object() {
				ssllib_new_error!{SslConfigError,"[{:?}] not valid map",curpath}
			}
			retv = curmap.clone();
		}
		Ok(retv)
	}

	fn _get_str_must(&self,cmap :&serde_json::value::Value,key :&str) -> Result<String,Box<dyn Error>> {
		let v = cmap.get(key);
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"no [{}] get",key}
		}
		let vmap = serde_json::json!(v.clone());
		if !vmap.is_string() {
			ssllib_new_error!{SslConfigError,"[{}] not string", key}
		}
		let s = vmap.as_str().unwrap();
		Ok(format!("{}",s))
	}

	fn _get_i64_must(&self,cmap :&serde_json::value::Value,key :&str) -> Result<i64,Box<dyn Error>> {
		let v = cmap.get(key);
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"no [{}] get",key}
		}
		let vmap = serde_json::json!(v.clone());
		if !vmap.is_i64() {
			ssllib_new_error!{SslConfigError,"[{}] not i64", key}
		}
		let v64 = vmap.as_i64().unwrap();
		Ok(v64)
	}

	pub fn get_string_must(&self,key :&str) -> Result<String,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_str_must(&vmap,&fname);
	}

	pub fn get_string_def(&self,key :&str,defval :&str) -> String {
		let ores = self.get_string_must(key);
		if ores.is_err() {
			return format!("{}",defval);
		}
		return ores.unwrap();
	}

	pub fn get_i64_must(&self,key :&str) -> Result<i64,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_i64_must(&vmap,&fname);
	}

	pub fn get_i64_def(&self, key :&str, defval :i64) -> i64 {
		let ores = self.get_i64_must(key);
		if ores.is_err() {
			return defval;
		}
		return ores.unwrap();
	}

	fn _get_array_idx_str(&self, vmap :&serde_json::value::Value, key :&str, idx :usize) -> Result<String,Box<dyn Error>> {
		let v = vmap.get(key);
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"[{}] can not get",key}
		}
		let vk = v.unwrap();
		if !vk.is_array() {
			ssllib_new_error!{SslConfigError,"[{}] not array", key}
		}
		let karr = vk.as_array().unwrap();
		if karr.len() < idx {
			ssllib_new_error!{SslConfigError,"[{}].[{}] out range",key,idx}
		}
		let sv = serde_json::json!(karr[idx].clone());
		if !sv.is_string() {
			ssllib_new_error!{SslConfigError,"[{}].[{}] not string",key,idx}
		}
		return Ok(format!("{}",sv.as_str().unwrap()));
	}

	fn _get_array_idx_len(&self, vmap :&serde_json::value::Value, key :&str) -> Result<usize,Box<dyn Error>> {
		let v = vmap.get(key);
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"[{}] can not get",key}
		}
		let vk = v.unwrap();
		if !vk.is_array() {
			ssllib_new_error!{SslConfigError,"[{}] not array", key}
		}
		let karr = vk.as_array().unwrap();
		return Ok(karr.len());
	}


	pub fn get_array_idx_str_must(&self,key :&str,idx :usize)  ->  Result<String,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_array_idx_str(&vmap,&fname,idx);
	}

	pub fn get_array_idx_str_len(&self,key :&str)  ->  Result<usize,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_array_idx_len(&vmap,&fname);
	}


	fn _get_array_idx_i64(&self, vmap :&serde_json::value::Value, key :&str, idx :usize) -> Result<i64,Box<dyn Error>> {
		let v = vmap.get(key);
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"[{}] can not get",key}
		}
		let vk = v.unwrap();
		if !vk.is_array() {
			ssllib_new_error!{SslConfigError,"[{}] not array", key}
		}
		let karr = vk.as_array().unwrap();
		if karr.len() < idx {
			ssllib_new_error!{SslConfigError,"[{}].[{}] out range",key,idx}
		}
		let sv = serde_json::json!(karr[idx].clone());
		if !sv.is_i64() {
			ssllib_new_error!{SslConfigError,"[{}].[{}] not i64",key,idx}
		}
		return Ok(sv.as_i64().unwrap());
	}

	pub fn get_array_idx_i64_must(&self,key :&str,idx :usize)  ->  Result<i64,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_array_idx_i64(&vmap,&fname,idx);
	}

}

