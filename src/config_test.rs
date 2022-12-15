
use crate::config::*;
use crate::{ssllib_log_trace};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};


fn check_array_u8(a1 :Vec<u8>, a2 :Vec<u8>) -> bool {
    if a1.len() != a2.len() {
        ssllib_log_trace!("[{}] != [{}]",a1.len(),a2.len());
        return false;
    }

    let mut idx :usize = 0;
    while idx < a1.len() {
        if a1[idx] != a2[idx] {
            ssllib_log_trace!("[{}] [{}] != [{}]", idx,a1[idx],a2[idx]);
            return false;
        }
        idx += 1;
    }
    return true;
}


#[test]
fn cfgtest_a001() {
	let mut c :ConfigValue = ConfigValue::new("{}").unwrap();

	c.set_str("key","value").unwrap();
	c.set_str("bk/cc","ccvalue").unwrap();
	let bv = c.get_str("key").unwrap();
	assert!(bv == "value");
	let bc = c.get_str("bk/cc").unwrap();
	assert!(bc == "ccvalue");
	let c8 :Vec<u8> = vec![20,23,66];
	c.set_u8_array("bu8",&c8).unwrap();
	let g8 = c.get_u8_array("bu8").unwrap();
	assert!(check_array_u8(c8,g8));
	return;
}
