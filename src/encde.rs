
use crate::impls::*;
use crate::*;
use crate::consts::*;


extern crate crypto;
use crypto::buffer::{ReadBuffer,WriteBuffer};
//use crypto::symmetriccipher::{BlockEncryptor,BlockDecryptor};
//use crypto;
use aes;
use aes::cipher::KeyIvInit;
use aes::cipher::AsyncStreamCipher;
//use aes::cipher::BlockEncryptMut;
//use aes::cipher::BlockDecryptMut;
//use cbc;
use cfb_mode;

use std::error::Error;
// use lazy_static::lazy_static;
// use std::collections::HashMap;
use std::sync::Arc;
use std::cell::RefCell;

ssllib_error_class!{SslEncDeError}


//type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
//type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;


pub struct Aes128CbcAlgo {
    encb :bool,
    decb :bool,
    enc :Vec<Box<dyn crypto::symmetriccipher::Encryptor>>,
    dec :Vec<Box<dyn crypto::symmetriccipher::Decryptor>>,
}

impl Aes128CbcAlgo {
    fn new() -> Result<Self,Box<dyn Error>> {
        Ok(Self {
            encb :false,
            decb :false,
            enc :vec![],
            dec :vec![],
        })
    }
}

impl Asn1EncryptOp for Aes128CbcAlgo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        if self.decb {
            self.decb = false;
            self.dec = vec![];
        }

        self.encb = true;
        let c = crypto::aes::cbc_encryptor(crypto::aes::KeySize::KeySize128, key,iv,crypto::blockmodes::PkcsPadding);
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



        // if false {          
        //     let mut encryptor=crypto::aes::cbc_encryptor(
        //         crypto::aes::KeySize::KeySize256,
        //         &self.key,
        //         &self.iv,
        //         crypto::blockmodes::PkcsPadding);
        //     let mut final_result=Vec::<u8>::new();
        //     let mut read_buffer=crypto::buffer::RefReadBuffer::new(data);
        //     let mut buffer=[0;4096];
        //     let mut write_buffer=crypto::buffer::RefWriteBuffer::new(&mut buffer);
        //     loop{
        //         let ro=encryptor.encrypt(&mut read_buffer,&mut write_buffer,true);
        //         if ro.is_err() {
        //             let e = ro.err().unwrap();
        //             ssllib_new_error!{SslEncDeError,"encrypt error [{:?}]",e}
        //         }
        //         let result = ro.unwrap();

        //         final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        //         match result {
        //             crypto::buffer::BufferResult::BufferUnderflow=>break,
        //             crypto::buffer::BufferResult::BufferOverflow=>{},
        //         }
        //     }
        //     Ok(final_result)
        //}
    }

    fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}

impl Asn1DecryptOp for Aes128CbcAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        if self.encb {
            self.encb = false;
            self.enc = vec![];
        }
        self.encb = true;
        let d = crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize128, key,iv,crypto::blockmodes::PkcsPadding);
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

        // if false {
        //     let mut decryptor = crypto::aes::cbc_decryptor(
        //         crypto::aes::KeySize::KeySize256,
        //         &self.key,
        //         &self.iv,
        //         crypto::blockmodes::PkcsPadding);

        //     let mut final_result = Vec::<u8>::new();
        //     let mut read_buffer = crypto::buffer::RefReadBuffer::new(encdata);
        //     let mut buffer = [0; 4096];
        //     let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

        //     loop {
        //         let ro = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true);
        //         if ro.is_err() {
        //             let e = ro.err().unwrap();
        //             ssllib_new_error!{SslEncDeError,"decrypt error [{:?}]",e}
        //         }
        //         let result = ro.unwrap();
        //         final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        //         match result {
        //             crypto::buffer::BufferResult::BufferUnderflow => break,
        //             crypto::buffer::BufferResult::BufferOverflow => { }
        //         }
        //     }

        //     Ok(final_result)            
        // }
    }

    fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}



#[derive(Clone)]
pub struct Aes256CbcAlgo {
    iv :Vec<u8>,
    key :Vec<u8>,
}

//type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
//type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;



impl Aes256CbcAlgo {
    pub fn new(iv :&[u8],key :&[u8]) -> Result<Self,Box<dyn Error>> {
        let retv = Aes256CbcAlgo {
            iv : iv.to_vec(),
            key :key.to_vec(),
        };
        Ok(retv)
    }
}



impl Asn1EncryptOp for Aes256CbcAlgo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        Ok(())
    }

    fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut encryptor=crypto::aes::cbc_encryptor(
            crypto::aes::KeySize::KeySize256,
            &self.key,
            &self.iv,
            crypto::blockmodes::PkcsPadding);
        let mut final_result=Vec::<u8>::new();
        let mut read_buffer=crypto::buffer::RefReadBuffer::new(data);
        let mut buffer=[0;4096];
        let mut write_buffer=crypto::buffer::RefWriteBuffer::new(&mut buffer);
        loop{
            let ro=encryptor.encrypt(&mut read_buffer,&mut write_buffer,true);
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
        Ok(final_result)
    }

    fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}

impl Asn1DecryptOp for Aes256CbcAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        Ok(())
    }
    fn decrypt_update(&mut self, encdata :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut decryptor = crypto::aes::cbc_decryptor(
            crypto::aes::KeySize::KeySize256,
            &self.key,
            &self.iv,
            crypto::blockmodes::PkcsPadding);

        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = crypto::buffer::RefReadBuffer::new(encdata);
        let mut buffer = [0; 4096];
        let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let ro = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true);
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

        Ok(final_result)
    }

    fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}

#[derive(Clone)]
pub struct Aes256CfbAlgo {
    iv :Vec<u8>,
    key :Vec<u8>,
}

impl Aes256CfbAlgo {
    pub fn new(iv :&[u8],key :&[u8]) -> Result<Self,Box<dyn Error>> {
        let retv = Aes256CfbAlgo {
            iv : iv.to_vec(),
            key :key.to_vec(),
        };
        Ok(retv)
    }
}

pub type Aes256CfbEnc = cfb_mode::Encryptor<aes::Aes256>;
pub type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;


impl Asn1EncryptOp for Aes256CfbAlgo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        Ok(())
    }
    fn encrypt_update(&mut self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retdata :Vec<u8> = data.to_vec();
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        Aes256CfbEnc::new(ckey.into(),civ.into()).encrypt(&mut retdata);
        Ok(retdata)
    }
    fn encrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}

impl Asn1DecryptOp for Aes256CfbAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.key = key.to_vec();
        self.iv = iv.to_vec();
        Ok(())
    }
    fn decrypt_update(&mut self, encdata :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retdata :Vec<u8> = encdata.to_vec();
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        Aes256CfbDec::new(ckey.into(),civ.into()).decrypt(&mut retdata);
        Ok(retdata)
    }
    fn decrypt_final(&mut self) -> Result<Vec<u8>,Box<dyn Error>> {
        Ok(vec![])
    }
}



pub fn get_encryptor(name :&str) -> Option<Arc<RefCell<dyn Asn1EncryptOp>>> {
    // let key :Vec<u8> = vec![];
    // let iv :Vec<u8> = vec![];
    if name == ENC_AES_128_CBC {
        let ores = Aes128CbcAlgo::new();
        if ores.is_ok() {
            return Some(Arc::new(RefCell::new(ores.unwrap())));    
        }
        
    }

    return None;
}