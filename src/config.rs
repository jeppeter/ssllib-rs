
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

	fn _get_map_path(&self,curpath :&str) -> Result<serde_json::value::Value,Box<dyn Error>> {
		let retv :serde_json::value::Value ;
		if curpath.len() == 0 {
			retv = serde_json::json!(self.val.clone());
		} else {

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

	fn _split_path(&self,path :&str) -> Result<(Vec<String>,String),Box<dyn Error>> {

	}

	pub fn get_string_must(&self,key :&str) -> Result<String,Box<dyn Error>> {
		let vmap = self._get_map_path()?;
		return self._get_str_must(&vmap,last);
	}

	pub fn get_string_def(&self,key :&str,defval :&str) -> String {
		let ores = self.get_string_must(key);
		if ores.is_err() {
			return format!("{}",defval);
		}
		return ores.unwrap();
	}

	pub fn get_i64_must(&self,key :&str) -> Result<i64,Box<dyn Error>> {
		let v = self.val.get(key);
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"no [{}] get",key}
		}
		let vmap = serde_json::json!(v.clone());	

		if !vmap.is_i64() {
			ssllib_new_error!{SslConfigError,"[{}] not i64", key}
		}
		let val = vmap.as_i64().unwrap();
		Ok(val)
	}

	pub fn get_i64_def(&self, key :&str, defval :i64) -> i64 {
		let ores = self.get_i64_must(key);
		if ores.is_err() {
			return defval;
		}
		return ores.unwrap();
	}

}

