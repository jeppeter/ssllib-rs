
use crate::impls::*;
use crate::*;
use crate::consts::*;
use crate::cfbmode::*;


extern crate crypto;
use crypto::buffer::{ReadBuffer,WriteBuffer};
//use crypto::symmetriccipher::{BlockEncryptor,BlockDecryptor};
//use crypto;
use aes;
use aes::cipher::KeyIvInit;
//use aes::cipher::AsyncStreamCipher;
//use aes::cipher::BlockEncryptMut;
//use aes::cipher::BlockDecryptMut;
//use cbc;
//use cfb_mode;

use std::error::Error;
// use lazy_static::lazy_static;
// use std::collections::HashMap;
use std::sync::Arc;
use std::cell::RefCell;

ssllib_error_class!{SslEncDeError}


macro_rules! expand_cbc_class {
    ($algname:ident,$keylen:expr,$ivlen:expr,$size:path) => {
        pub struct $algname {
            encb :bool,
            decb :bool,
            enc :Vec<Box<dyn crypto::symmetriccipher::Encryptor>>,
            dec :Vec<Box<dyn crypto::symmetriccipher::Decryptor>>,
        }

        impl $algname {
            pub fn new() -> Result<Self,Box<dyn Error>> {
                Ok(Self {
                    encb :false,
                    decb :false,
                    enc :vec![],
                    dec :vec![],
                })
            }
        }

        impl Asn1EncryptOp for $algname {
            fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
                if self.decb {
                    self.decb = false;
                    self.dec = vec![];
                }

                if key.len() < $keylen || iv.len() < $ivlen {
                    ssllib_new_error!{SslEncDeError,"key len {} < {} iv len {} < {}" ,key.len(),$keylen,iv.len(),$ivlen}
                }

                let mut okey :Vec<u8> = key.to_vec();
                let mut oiv :Vec<u8> = iv.to_vec();
                if okey.len() > $keylen {
                    okey = okey[0..$keylen].to_vec();
                }

                if oiv.len() > $ivlen {
                    oiv = oiv[0..$ivlen].to_vec();
                }

                self.encb = true;
                let c = crypto::aes::cbc_encryptor($size, &okey,&oiv,crypto::blockmodes::PkcsPadding);
                if self.enc.len() > 0 {
                    self.enc[0] = c;
                } else {
                    self.enc.push(c);
                }
                Ok(())
            }

            fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
                if !self.encb {
                    ssllib_new_error!{SslEncDeError,"not in encrypt init"}
                }

                let mut final_result=Vec::<u8>::new();
                let mut read_buffer=crypto::buffer::RefReadBuffer::new(data);
                let mut buffer=[0;4096];
                let mut write_buffer=crypto::buffer::RefWriteBuffer::new(&mut buffer);
                loop{
                    let ro=self.enc[0].encrypt(&mut read_buffer,&mut write_buffer,true);
                    if ro.is_err() {
                        let e = ro.err().unwrap();
                        ssllib_new_error!{SslEncDeError,"encrypt error [{:?}]",e}
                    }
                    let result = ro.unwrap();

                    final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

                    match result {
                        crypto::buffer::BufferResult::BufferUnderflow=>break,
                        crypto::buffer::BufferResult::BufferOverflow=>{},
                    }
                }
                return Ok(final_result);
            }

            fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
                Ok(vec![])
            }
        }

        impl Asn1DecryptOp for $algname {
            fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
                if self.encb {
                    self.encb = false;
                    self.enc = vec![];
                }

                if key.len() < $keylen || iv.len() < $ivlen {
                    ssllib_new_error!{SslEncDeError,"key len {} < {} iv len {} < {}" ,key.len(),$keylen,iv.len(),$ivlen}
                }

                let mut okey :Vec<u8> = key.to_vec();
                let mut oiv :Vec<u8> = iv.to_vec();
                if okey.len() > $keylen {
                    okey = okey[0..$keylen].to_vec();
                }

                if oiv.len() > $ivlen {
                    oiv = oiv[0..$ivlen].to_vec();
                }

                self.decb = true;
                let d = crypto::aes::cbc_decryptor($size, &okey,&oiv,crypto::blockmodes::PkcsPadding);
                if self.dec.len() > 0 {
                    self.dec[0] = d;
                } else {
                    self.dec.push(d);
                }
                Ok(())
            }
            fn decrypt_update(&mut self, encdata :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
                if !self.decb {
                    ssllib_new_error!{SslEncDeError,"not initialized for decrypt"}
                }
                let mut final_result = Vec::<u8>::new();
                let mut read_buffer = crypto::buffer::RefReadBuffer::new(encdata);
                let mut buffer = [0; 4096];
                let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

                loop {
                    let ro = self.dec[0].decrypt(&mut read_buffer, &mut write_buffer, true);
                    if ro.is_err() {
                        let e = ro.err().unwrap();
                        ssllib_new_error!{SslEncDeError,"decrypt error [{:?}]",e}
                    }
                    let result = ro.unwrap();
                    final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
                    match result {
                        crypto::buffer::BufferResult::BufferUnderflow => break,
                        crypto::buffer::BufferResult::BufferOverflow => { }
                    }
                }

                return Ok(final_result);
            }

            fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
                Ok(vec![])
            }
        }

    };
}

expand_cbc_class!(Aes128CbcAlgo,16,16,crypto::aes::KeySize::KeySize128);
expand_cbc_class!(Aes192CbcAlgo,24,16,crypto::aes::KeySize::KeySize192);
expand_cbc_class!(Aes256CbcAlgo,32,16,crypto::aes::KeySize::KeySize256);


macro_rules! expand_cfb_class {
    ($algname:ident,$aestype:path,$encls:ident,$decls:ident,$bitsize:expr,$keylen:expr,$ivlen:expr) => {
        pub type $encls = CfbBitsBufEncryptor<$aestype,$bitsize>;
        pub type $decls = CfbBitsBufDecryptor<$aestype,$bitsize>;

        #[derive(Clone)]
        pub struct $algname {
            iv :Vec<u8>,
            key :Vec<u8>,
            innerenc : $encls,
            innerdec : $decls,
            initenc :bool,
            initdec :bool,
        }

        impl $algname {
            pub fn new() -> Result<Self,Box<dyn Error>> {
                let key = vec![0;$keylen];
                let iv =vec![0;$ivlen];
                let ckey :&[u8] = &key;
                let civ :&[u8] = &iv;
                let retv = Self {
                    iv : iv.clone(),
                    key :key.clone(),
                    innerenc :$encls::new(ckey.into(),civ.into()),
                    innerdec : $decls::new(ckey.into(),civ.into()),
                    initenc : false,
                    initdec :false,
                };
                Ok(retv)
            }
        }


        impl Asn1EncryptOp for $algname {
            fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
                self.iv = iv.to_vec();
                self.key = key.to_vec();
                if self.iv.len() < $ivlen || self.key.len() < $keylen {
                    ssllib_new_error!{SslEncDeError,"iv.len {} < {} || key.len {} < {}",iv.len(),$ivlen ,key.len(),$keylen}
                }

                if self.iv.len() > $ivlen {
                    self.iv = self.iv[0..$ivlen].to_vec();
                }

                if self.key.len() > $keylen {
                    self.key = self.key[0..$keylen].to_vec();
                }

                self.initenc = true;
                self.initdec = false;
                let ckey :&[u8] = &self.key;
                let civ :&[u8] = &self.iv;
                self.innerenc = $encls::new(ckey.into(),civ.into());

                Ok(())
            }
            fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
                let mut retdata :Vec<u8> = data.to_vec();
                if !self.initenc {
                    ssllib_new_error!{SslEncDeError,"not init encrypt"}
                }
                let _ = self.innerenc.encrypt(&mut retdata)?;
                Ok(retdata)
            }
            fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
                if !self.initenc {
                    ssllib_new_error!{SslEncDeError,"not init encrypt"}   
                }
                Ok(vec![])
            }
        }

        impl Asn1DecryptOp for $algname {
            fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
                self.iv = iv.to_vec();
                self.key = key.to_vec();
                if self.iv.len() < $ivlen || self.key.len() < $keylen {
                    ssllib_new_error!{SslEncDeError,"iv.len {} < {} || key.len {} < {}",iv.len(),$ivlen,key.len(),$keylen}
                }

                if self.iv.len() > $ivlen {
                    self.iv = self.iv[0..$ivlen].to_vec();
                }

                if self.key.len() > $keylen {
                    self.key = self.key[0..$keylen].to_vec();
                }

                self.initdec = true;
                self.initenc = false;
                let ckey :&[u8] = &self.key;
                let civ :&[u8] = &self.iv;
                self.innerdec = $decls::new(ckey.into(),civ.into());

                Ok(())
            }
            fn decrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
                let mut retdata :Vec<u8> = data.to_vec();
                if !self.initdec {
                    ssllib_new_error!{SslEncDeError,"not init decrypt"}
                }
                let _ = self.innerdec.decrypt(&mut retdata)?;
                Ok(retdata)
            }
            fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
                if !self.initdec {
                    ssllib_new_error!{SslEncDeError,"not init decrypt"}
                }
                Ok(vec![])
            }
        }
    };
}

expand_cfb_class!{Aes128CfbAlgo,aes::Aes128,Aes128CfbEnc,Aes128CfbDec,128,16,16}
expand_cfb_class!{Aes128Cfb1Algo,aes::Aes128,Aes128Cfb1Enc,Aes128Cfb1Dec,1,16,16}
expand_cfb_class!{Aes128Cfb8Algo,aes::Aes128,Aes128Cfb8Enc,Aes128Cfb8Dec,8,16,16}
expand_cfb_class!{Aes192CfbAlgo,aes::Aes192,Aes192CfbEnc,Aes192CfbDec,128,24,16}
expand_cfb_class!{Aes192Cfb1Algo,aes::Aes192,Aes192Cfb1Enc,Aes192Cfb1Dec,1,24,16}
expand_cfb_class!{Aes192Cfb8Algo,aes::Aes192,Aes192Cfb8Enc,Aes192Cfb8Dec,8,24,16}
expand_cfb_class!{Aes256CfbAlgo,aes::Aes256,Aes256CfbEnc,Aes256CfbDec,128,32,16}
expand_cfb_class!{Aes256Cfb1Algo,aes::Aes256,Aes256Cfb1Enc,Aes256Cfb1Dec,1,32,16}
expand_cfb_class!{Aes256Cfb8Algo,aes::Aes256,Aes256Cfb8Enc,Aes256Cfb8Dec,8,32,16}


pub fn get_encryptor(name :&str) -> Option<Arc<RefCell<dyn Asn1EncryptOp>>> {
    // let key :Vec<u8> = vec![];
    // let iv :Vec<u8> = vec![];
    if name == ENC_AES_128_CBC {
        let ores = Aes128CbcAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));    
        }        
    } else if name == ENC_AES_192_CBC {
        let ores = Aes192CbcAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));    
        }
    } else if name == ENC_AES_256_CBC {
        let ores = Aes256CbcAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));    
        }
    } else if name == ENC_AES_256_CFB {
        let ores = Aes256CfbAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_256_CFB1 {
        let ores = Aes256Cfb1Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_256_CFB8 {
        let ores = Aes256Cfb8Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_192_CFB {
        let ores = Aes192CfbAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_192_CFB1 {
        let ores = Aes192Cfb1Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_192_CFB8 {
        let ores = Aes192Cfb8Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_128_CFB {
        let ores = Aes128CfbAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_128_CFB1 {
        let ores = Aes128Cfb1Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_128_CFB8 {
        let ores = Aes128Cfb8Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    }

    return None;
}

pub fn get_enc_names() -> Vec<String> {
    return vec![ENC_AES_128_CBC.to_string(),ENC_AES_192_CBC.to_string(),ENC_AES_256_CBC.to_string(),ENC_AES_128_CFB.to_string(),ENC_AES_128_CFB1.to_string(),ENC_AES_128_CFB8.to_string(),ENC_AES_192_CFB.to_string(),ENC_AES_192_CFB1.to_string(),ENC_AES_192_CFB8.to_string(),ENC_AES_256_CFB.to_string(),ENC_AES_256_CFB1.to_string(),ENC_AES_256_CFB8.to_string()];
}


pub fn get_decryptor(name :&str) -> Option<Arc<RefCell<dyn Asn1DecryptOp>>> {
    // let key :Vec<u8> = vec![];
    // let iv :Vec<u8> = vec![];
    if name == ENC_AES_128_CBC {
        let ores = Aes128CbcAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));    
        }        
    } else if name == ENC_AES_192_CBC {
        let ores = Aes192CbcAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));    
        }
    } else if name == ENC_AES_256_CBC {
        let ores = Aes256CbcAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));    
        }
    } else if name == ENC_AES_256_CFB {
        let ores = Aes256CfbAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_256_CFB1 {
        let ores = Aes256Cfb1Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_256_CFB8 {
        let ores = Aes256Cfb8Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_192_CFB {
        let ores = Aes192CfbAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_192_CFB1 {
        let ores = Aes192Cfb1Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_192_CFB8 {
        let ores = Aes192Cfb8Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_128_CFB {
        let ores = Aes128CfbAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_128_CFB1 {
        let ores = Aes128Cfb1Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    } else if name == ENC_AES_128_CFB8 {
        let ores = Aes128Cfb8Algo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));
        }
    }

    return None;
}