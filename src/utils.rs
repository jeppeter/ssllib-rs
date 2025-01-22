use crate::*;
use std::error::Error;
use lazy_static::lazy_static;
use std::collections::HashMap;
use crate::consts::*;

ssllib_error_class!{SslUtilsError}


pub (crate) fn expand_uni(passin :&[u8]) -> Vec<u8> {
    let mut retv :Vec<u8> = Vec::new();
    for i in 0..passin.len() {
        retv.push(0);
        retv.push(passin[i]);
    }
    /*at last one*/
    retv.push(0);
    retv.push(0);
    return retv;
}

pub (crate) fn check_equal_u8(a :&[u8],b :&[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }


    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    return true;
}

pub fn get_digest_from_pkey(pkey :&str) -> Result<String,Box<dyn Error>> {
    ssllib_new_error!{SslUtilsError,"cannot find {}",pkey}
}


lazy_static !{
    static ref DIGEST_MAP_STRING_OID :HashMap<String,String> = {
        let mut retv :HashMap<String,String> = HashMap::new();
        retv.insert(DGST_SHA256.to_string(),OID_SHA256_DIGEST.to_string());
        retv
    };

    static ref PKEY_MAP_STRING_OID :HashMap<String,String> = {
        let mut retv :HashMap<String,String> = HashMap::new();
        retv.insert(ECDSA_SHA256_PKEY.to_string(),OID_ECDSA_WITH_SHA256_PKEY.to_string());
        retv
    };
}

pub fn ssllib_get_digest_oid(sname :&str) -> Option<String> {
    match DIGEST_MAP_STRING_OID.get(sname) {
        Some(v) => {
            return Some(format!("{}",v));
        }
        _ => {
            return None;
        }
    }
}

pub fn ssllib_get_pkey_oid(sname :&str)  -> Option<String> {
    match PKEY_MAP_STRING_OID.get(sname) {
        Some(v) => {
            return Some(format!("{}",v));
        }
        _ => {
            return None;
        }
    }
}