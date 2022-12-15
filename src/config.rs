
use crate::{ssllib_error_class,ssllib_new_error};
use std::error::Error;
use crate::{ssllib_log_trace};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};


ssllib_error_class!{SslConfigError}

#[derive(Clone)]
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

	pub fn format(&self) -> Result<String,Box<dyn Error>> {
		let cs = serde_json::to_string_pretty(&(self.val))?;
		Ok(cs)
	}

	fn _get_path_whole(&self,paths :&[String]) -> String {
		let mut s :String = "/".to_string();
		for i in 0..paths.len() {
			if i > 0 {
				s.push_str("/");
			}
			s.push_str(&paths[i]);
		}
		if s.len() == 1 {
			s = "".to_string();
		}
		ssllib_log_trace!("path [{}]",s);
		return s;
	}

	fn _set_str(&mut self,paths :&[String],key :&str, strv:&str) -> Result<Option<String>,Box<dyn Error>> {
		let vs :serde_json::value::Value = serde_json::from_str(&format!("\"{}\"",strv))?;
		let vmap  = self.val.pointer_mut(&(self._get_path_whole(paths))).unwrap();
		let mut retv :Option<String> = None;

		if key.len() > 0 {
			let ores = vmap.get(key);
			if ores.is_some() {
				let ck = ores.unwrap();
				if ck.is_string() {
					retv = Some(format!("{}",ck.as_str().unwrap()));
				}
			}
			vmap[key] = vs;
		} else {
			if vmap.is_string() {
				retv = Some(format!("{}",vmap.as_str().unwrap()));
			}
			*vmap = vs;
		}
		Ok(retv)
	}

	fn _set_str_array(&mut self,paths :&[String],key :&str, strv:&Vec<String>) -> Result<Option<Vec<String>>,Box<dyn Error>> {
		let mut forms :String = "[".to_string();
		for i in 0..strv.len() {
			if i > 0 {
				forms.push_str(",");
			}
			forms.push_str(&format!("\"{}\"",strv[i]));
		}
		forms.push_str("]");
		let vs :serde_json::value::Value = serde_json::from_str(&forms)?;
		let vmap  = self.val.pointer_mut(&(self._get_path_whole(paths))).unwrap();
		let mut retv :Option<Vec<String>> = None;
		let mut allok :bool = true;
		let mut allstr :Vec<String> = Vec::new();

		if key.len() > 0 {
			let ores = vmap.get(key);
			if ores.is_some() {
				let ck = ores.unwrap();
				if ck.is_array() {
					let carr = ck.as_array().unwrap();
					for k in carr.iter() {
						if !k.is_string() {
							allok = false;
							break;
						}
						allstr.push(format!("{}",k.as_str().unwrap()));
					}

					if allok {
						retv = Some(allstr.clone());
					}
				}
			}
			vmap[key] = vs;
		} else {
			if vmap.is_array() {
				let carr = vmap.as_array().unwrap();
				for k in carr.iter() {
					if !k.is_string() {
						allok = false;
						break;
					}
					allstr.push(format!("{}",k.as_str().unwrap()));
				}

				if allok {
					retv = Some(allstr.clone());
				}				
			}
			*vmap = vs;
		}
		Ok(retv)
	}



	fn _set_u8(&mut self,paths :&[String],key :&str, val :u8) -> Result<Option<u8>,Box<dyn Error>> {
		let vs :serde_json::value::Value = serde_json::from_str(&format!("{}",val))?;
		let vmap  = self.val.pointer_mut(&(self._get_path_whole(paths))).unwrap();
		let mut retv :Option<u8> = None;

		if key.len() > 0 {
			let ores = vmap.get(key);
			if ores.is_some() {
				let ck = ores.unwrap();
				if ck.is_i64() {
					retv = Some(ck.as_i64().unwrap() as u8);
				}
			}
			vmap[key] = vs;
		} else {
			if vmap.is_i64() {
				retv = Some(vmap.as_i64().unwrap() as u8);
			}
			*vmap = vs;
		}
		Ok(retv)
	}


	fn _set_u8_array(&mut self,paths :&[String],key :&str, strv:&Vec<u8>) -> Result<Option<Vec<u8>>,Box<dyn Error>> {
		let mut forms :String = "[".to_string();
		for i in 0..strv.len() {
			if i > 0 {
				forms.push_str(",");
			}
			forms.push_str(&format!("{}",strv[i]));
		}
		forms.push_str("]");
		let vs :serde_json::value::Value = serde_json::from_str(&forms)?;
		let vmap  = self.val.pointer_mut(&(self._get_path_whole(paths))).unwrap();
		let mut retv :Option<Vec<u8>> = None;
		let mut allok :bool = true;
		let mut allstr :Vec<u8> = Vec::new();

		if key.len() > 0 {
			let ores = vmap.get(key);
			if ores.is_some() {
				let ck = ores.unwrap();
				if ck.is_array() {
					let carr = ck.as_array().unwrap();
					for k in carr.iter() {
						if !k.is_i64() {
							allok = false;
							break;
						}
						allstr.push(k.as_i64().unwrap() as u8);
					}

					if allok {
						retv = Some(allstr.clone());
					}
				}
			}
			vmap[key] = vs;
		} else {
			if vmap.is_array() {
				let carr = vmap.as_array().unwrap();
				for k in carr.iter() {
					if !k.is_i64() {
						allok = false;
						break;
					}
					allstr.push(k.as_i64().unwrap() as u8);
				}

				if allok {
					retv = Some(allstr.clone());
				}
			}
			*vmap = vs;
		}
		Ok(retv)
	}

	fn _set_i64(&mut self,paths :&[String],key :&str, val :i64) -> Result<Option<i64>,Box<dyn Error>> {
		let vs :serde_json::value::Value = serde_json::from_str(&format!("{}",val))?;
		let vmap  = self.val.pointer_mut(&(self._get_path_whole(paths))).unwrap();
		let mut retv :Option<i64> = None;

		if key.len() > 0 {
			let ores = vmap.get(key);
			if ores.is_some() {
				let ck = ores.unwrap();
				if ck.is_i64() {
					retv = Some(ck.as_i64().unwrap());
				}
			}
			vmap[key] = vs;
		} else {
			if vmap.is_i64() {
				retv = Some(vmap.as_i64().unwrap());
			}
			*vmap = vs;
		}
		Ok(retv)
	}

	fn _set_i64_array(&mut self,paths :&[String],key :&str, strv:&Vec<i64>) -> Result<Option<Vec<i64>>,Box<dyn Error>> {
		let mut forms :String = "[".to_string();
		for i in 0..strv.len() {
			if i > 0 {
				forms.push_str(",");
			}
			forms.push_str(&format!("{}",strv[i]));
		}
		forms.push_str("]");
		let vs :serde_json::value::Value = serde_json::from_str(&forms)?;
		let vmap  = self.val.pointer_mut(&(self._get_path_whole(paths))).unwrap();
		let mut retv :Option<Vec<i64>> = None;
		let mut allok :bool = true;
		let mut allstr :Vec<i64> = Vec::new();

		if key.len() > 0 {
			let ores = vmap.get(key);
			if ores.is_some() {
				let ck = ores.unwrap();
				if ck.is_array() {
					let carr = ck.as_array().unwrap();
					for k in carr.iter() {
						if !k.is_i64() {
							allok = false;
							break;
						}
						allstr.push(k.as_i64().unwrap());
					}

					if allok {
						retv = Some(allstr.clone());
					}
				}
			}
			vmap[key] = vs;
		} else {
			if vmap.is_array() {
				let carr = vmap.as_array().unwrap();
				for k in carr.iter() {
					if !k.is_i64() {
						allok = false;
						break;
					}
					allstr.push(k.as_i64().unwrap());
				}

				if allok {
					retv = Some(allstr.clone());
				}
			}
			*vmap = vs;
		}
		Ok(retv)
	}


	fn _get_map_path_write(&mut self,paths :&[String]) -> Result<(),Box<dyn Error>> {
		let mut s :String;
		if paths.len() > 0 {
			for i in 0..paths.len() {
				s = "/".to_string();
				for j in 0..(i+1) {
					if j > 0 {
						s.push_str("/");
					}
					s.push_str(&paths[j]);
				}
				if s.len() == 1 {
					s = "".to_string();
				}
				let ores = self.val.pointer(&s);
				if ores.is_none() {
					s = "/".to_string();
					for j in 0..i {
						if j > 0 {
							s.push_str("/");
						}
						s.push_str(&paths[j]);
					}
					if s.len() == 1 {
						s = "".to_string();
					}
					let ores2 = self.val.pointer_mut(&s);
					if ores2.is_none() {
						ssllib_new_error!{SslConfigError,"can not get [{}] pointer",s}
					}
					let c = ores2.unwrap();
					c[&paths[i]] = serde_json::json!({});
				} else {
					let c = ores.unwrap();
					if !c.is_object() {
						ssllib_new_error!{SslConfigError,"can not set [{}] object", paths[i]}
					}
				}
			}
		}
		Ok(())
	}

	pub fn set_str(&mut self,key :&str, strv :&str) -> Result<Option<String>,Box<dyn Error>> {
		let (paths,bname) = self._split_path(key)?;
		let _ = self._get_map_path_write(&paths)?;
		return self._set_str(&paths,&bname,strv);
	}


	pub fn set_u8(&mut self,key :&str, val :u8) -> Result<Option<u8>,Box<dyn Error>> {
		let (paths,bname) = self._split_path(key)?;
		let _ = self._get_map_path_write(&paths)?;
		return self._set_u8(&paths,&bname,val);
	}


	pub fn set_i64(&mut self,key :&str, val :i64) -> Result<Option<i64>,Box<dyn Error>> {
		let (paths,bname) = self._split_path(key)?;
		let _ = self._get_map_path_write(&paths)?;
		return self._set_i64(&paths,&bname,val);
	}

	pub fn set_str_array(&mut self,key :&str, val :&Vec<String>) -> Result<Option<Vec<String>>,Box<dyn Error>> {
		let (paths,bname) = self._split_path(key)?;
		let _ = self._get_map_path_write(&paths)?;
		return self._set_str_array(&paths,&bname,val);
	}

	pub fn set_u8_array(&mut self,key :&str, val :&Vec<u8>) -> Result<Option<Vec<u8>>,Box<dyn Error>> {
		let (paths,bname) = self._split_path(key)?;
		let _ = self._get_map_path_write(&paths)?;
		return self._set_u8_array(&paths,&bname,val);
	}

	pub fn set_i64_array(&mut self,key :&str, val :&Vec<i64>) -> Result<Option<Vec<i64>>,Box<dyn Error>> {
		let (paths,bname) = self._split_path(key)?;
		let _ = self._get_map_path_write(&paths)?;
		return self._set_i64_array(&paths,&bname,val);
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

	pub fn get_str(&self,key :&str) -> Result<String,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_str_must(&vmap,&fname);
	}

	pub fn get_str_def(&self,key :&str,defval :&str) -> String {
		let ores = self.get_str(key);
		if ores.is_err() {
			return format!("{}",defval);
		}
		return ores.unwrap();
	}

	pub fn get_i64(&self,key :&str) -> Result<i64,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_i64_must(&vmap,&fname);
	}

	pub fn get_u8(&self,key :&str) -> Result<u8,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		let ores =  self._get_i64_must(&vmap,&fname);
		if ores.is_err() {
			let e = ores.err().unwrap();
			return Err(e);
		}
		let retu8 :u8 = ores.unwrap() as u8;
		return Ok(retu8);
	}


	pub fn get_i64_def(&self, key :&str, defval :i64) -> i64 {
		let ores = self.get_i64(key);
		if ores.is_err() {
			return defval;
		}
		return ores.unwrap();
	}

	pub fn get_u8_def(&self,key :&str,defval :u8) -> u8 {
		let ores = self.get_u8(key);
		if ores.is_err() {
			return defval;
		}
		return ores.unwrap();
	}


	fn _get_array_str(&self, vmap :&serde_json::value::Value, key :&str) -> Result<Vec<String>,Box<dyn Error>> {
		let v = vmap.get(key);
		let mut retv :Vec<String> = Vec::new();
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"[{}] can not get",key}
		}
		let vk = v.unwrap();
		if !vk.is_array() {
			ssllib_new_error!{SslConfigError,"[{}] not array", key}
		}
		let karr = vk.as_array().unwrap();
		for i in 0..karr.len() {
			let sv = serde_json::json!(karr[i].clone());
			if !sv.is_string() {
				ssllib_new_error!{SslConfigError,"[{}].[{}] not string",key,i}
			}
			retv.push(format!("{}",sv.as_str().unwrap()))
		}
		return Ok(retv);
	}

	pub fn get_array_str(&self,key :&str)  ->  Result<Vec<String>,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_array_str(&vmap,&fname);
	}


	fn _get_array_i64(&self, vmap :&serde_json::value::Value, key :&str) -> Result<Vec<i64>,Box<dyn Error>> {
		let v = vmap.get(key);
		let mut retv :Vec<i64> = Vec::new();
		if v.is_none() {
			ssllib_new_error!{SslConfigError,"[{}] can not get",key}
		}
		let vk = v.unwrap();
		if !vk.is_array() {
			ssllib_new_error!{SslConfigError,"[{}] not array", key}
		}
		let karr = vk.as_array().unwrap();
		for i in 0..karr.len() {
			let sv = serde_json::json!(karr[i].clone());
			if !sv.is_i64() {
				ssllib_new_error!{SslConfigError,"[{}].[{}] not i64", key,i}
			}
			retv.push(sv.as_i64().unwrap());
		}
		return Ok(retv);
	}

	pub fn get_array_i64(&self,key :&str)  ->  Result<Vec<i64>,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		return self._get_array_i64(&vmap,&fname);
	}

	pub fn get_u8_array(&self,key :&str)  ->  Result<Vec<u8>,Box<dyn Error>> {
		let (dnames,fname) = self._split_path(key)?;
		let vmap = self._get_map_path(&dnames)?;
		let ores =  self._get_array_i64(&vmap,&fname);
		if ores.is_err() {
			let e = ores.err().unwrap();
			return Err(e);
		}
		let mut retu8 :Vec<u8> = Vec::new();
		for k in ores.unwrap().iter() {
			retu8.push( (*k) as u8);
		}
		return Ok(retu8);
	}

	fn _set_config(&mut self,paths :&Vec<String>,val :&ConfigValue) -> Result<(),Box<dyn Error>> {
		let vs :serde_json::value::Value = val.val.clone();
		let vmap  = self.val.pointer_mut(&(self._get_path_whole(paths))).unwrap();
		*vmap = vs;
		Ok(())
	}

	pub fn set_config(&mut self,key :&str, val :&ConfigValue) -> Result<Option<ConfigValue>,Box<dyn Error>> {
		let mut retv :Option<ConfigValue> = None;
		let ores = self.get_config(key);
		if ores.is_ok() {
			retv = ores.unwrap();
		}
		let (mut dnames, fname) = self._split_path(key)?;
		dnames.push(fname);

		/*now to make sure*/
		let _ = self._get_map_path_write(&dnames)?;
		/*now to set */
		let _ = self._set_config(&dnames,val)?;
		return Ok(retv);
	}

	pub fn get_config(&self,key :&str) -> Result<Option<ConfigValue>,Box<dyn Error>> {
		let ( mut dnames,fname) = self._split_path(key)?;
		dnames.push(fname);
		let ores = self._get_map_path(&dnames);
		if ores.is_err() {
			return Ok(None);
		}
		let vk = ores.unwrap();
		if !vk.is_object() {
			ssllib_new_error!{SslConfigError,"{} not valid object", key}
		}
		let cs = serde_json::to_string_pretty(&vk)?;
		let retv = Some(ConfigValue::new(&cs)?);
		Ok(retv)
	}
}

