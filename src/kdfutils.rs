
use crate::consts::*;
use crate::{ssllib_buffer_trace,ssllib_format_buffer_log};
use crate::logger::{ssllib_log_get_timestamp,ssllib_debug_out};
use sha2::{Sha256,Digest};


#[allow(non_snake_case)]
pub (crate) fn get_pkcs12kdf_sha256(passin :&[u8],salt :&[u8], idval :u8, iterval :usize,totaln :usize) -> Vec<u8> {
    let mut Darr :Vec<u8> = Vec::new();
    let mut Aiarr :Vec<u8> = Vec::new();
    let mut Barr :Vec<u8> = Vec::new();
    let mut Iarr :Vec<u8> = Vec::new();
    let mut retv :Vec<u8> = Vec::new();
    let v :usize = SHA256_BLOCK_SIZE;
    let u :usize = SHA256_DIGEST_SIZE;
    let slen :usize = v * ((salt.len() + v - 1) / v);
    let  plen :usize ;
    if passin.len() != 0 {
        plen = v * ((passin.len() + v - 1) / v);
    } else {
        plen = 0;
    }
    let ilen :usize = slen + plen;

    for _ in 0..v {
        Darr.push(idval);
    }

    for i in 0..slen {
        Iarr.push(salt[i % salt.len()]);
    }

    for i in 0..plen {
        Iarr.push(passin[i % passin.len()]);
    }

    for  _ in 0..(v + 1) {
        Barr.push(0);
    }

    for _ in 0..(u) {
        Aiarr.push(0);
    }

    loop {
        let mut hasher = Sha256::new();
        hasher.update(&Darr[0..v]);
        hasher.update(&Iarr[0..ilen]);
        let res = hasher.finalize();
        let rdata = res.to_vec();
        for i in 0..rdata.len() {
            Aiarr[i] = rdata[i];
        }

        ssllib_buffer_trace!(Darr.as_ptr(),u,"Darr Data");
        ssllib_buffer_trace!(Iarr.as_ptr(),Iarr.len(), "Iarr Data");

        ssllib_buffer_trace!(Aiarr.as_ptr(),Aiarr.len(),"Aiarr Data");
        for _ in 1..iterval {
            let mut hasher = Sha256::new();
            hasher.update(&Aiarr[0..u]);
            let res = hasher.finalize();
            let rdata = res.to_vec();
            for i in 0..rdata.len() {
                Aiarr[i] = rdata[i];
            }
        }
        ssllib_buffer_trace!(Aiarr.as_ptr(),Aiarr.len(),"Aiarr Data");

        for i in 0..u {
            if retv.len() >= totaln {
                break;
            }
            retv.push(Aiarr[i]);
        }

        if retv.len() >= totaln {
            break;
        }

        for j in 0..v {
            Barr[j] = Aiarr[j % u];
        }
        let mut jdx :usize = 0;
        while jdx < ilen {
            let mut k :usize = v;
            let mut c :u16 = 1;
            while k > 0 {
                k -= 1;
                c += Iarr[k+jdx] as u16 + Barr[k] as u16;
                Iarr[k + jdx] = c as u8;
                c >>= 8;
            }
            jdx += v;
        }
    }

    return retv;
}
