
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

        if key.len() < 16 || iv.len() < 16 {
            ssllib_new_error!{SslEncDeError,"key len {} < 16 iv len {} < 16" ,key.len(),iv.len()}
        }

        let mut okey :Vec<u8> = key.to_vec();
        let mut oiv :Vec<u8> = iv.to_vec();
        if okey.len() > 16 {
            okey = okey[0..16].to_vec();
        }

        if oiv.len() > 16 {
            oiv = oiv[0..16].to_vec();
        }

        self.encb = true;
        let c = crypto::aes::cbc_encryptor(crypto::aes::KeySize::KeySize128, &okey,&oiv,crypto::blockmodes::PkcsPadding);
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

impl Asn1DecryptOp for Aes128CbcAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        if self.encb {
            self.encb = false;
            self.enc = vec![];
        }

        if key.len() < 16 || iv.len() < 16 {
            ssllib_new_error!{SslEncDeError,"key len {} < 16 iv len {} < 16" ,key.len(),iv.len()}
        }

        let mut okey :Vec<u8> = key.to_vec();
        let mut oiv :Vec<u8> = iv.to_vec();
        if okey.len() > 16 {
            okey = okey[0..16].to_vec();
        }

        if oiv.len() > 16 {
            oiv = oiv[0..16].to_vec();
        }

        self.decb = true;
        let d = crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize128, &okey,&oiv,crypto::blockmodes::PkcsPadding);
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


pub struct Aes192CbcAlgo {
    encb :bool,
    decb :bool,
    enc :Vec<Box<dyn crypto::symmetriccipher::Encryptor>>,
    dec :Vec<Box<dyn crypto::symmetriccipher::Decryptor>>,
}

impl Aes192CbcAlgo {
    fn new() -> Result<Self,Box<dyn Error>> {
        Ok(Self {
            encb :false,
            decb :false,
            enc :vec![],
            dec :vec![],
        })
    }
}

impl Asn1EncryptOp for Aes192CbcAlgo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        if self.decb {
            self.decb = false;
            self.dec = vec![];
        }

        if key.len() < 24 || iv.len() < 16 {
            ssllib_new_error!{SslEncDeError,"key len {} < 16 iv len {} < 16" ,key.len(),iv.len()}
        }

        let mut okey :Vec<u8> = key.to_vec();
        let mut oiv :Vec<u8> = iv.to_vec();
        if okey.len() > 24 {
            okey = okey[0..24].to_vec();
        }

        if oiv.len() > 16 {
            oiv = oiv[0..16].to_vec();
        }

        self.encb = true;
        let c = crypto::aes::cbc_encryptor(crypto::aes::KeySize::KeySize192, &okey,&oiv,crypto::blockmodes::PkcsPadding);
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

impl Asn1DecryptOp for Aes192CbcAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        if self.encb {
            self.encb = false;
            self.enc = vec![];
        }

        if key.len() < 24 || iv.len() < 16 {
            ssllib_new_error!{SslEncDeError,"key len {} < 24 iv len {} < 16" ,key.len(),iv.len()}
        }

        let mut okey :Vec<u8> = key.to_vec();
        let mut oiv :Vec<u8> = iv.to_vec();
        if okey.len() > 24 {
            okey = okey[0..24].to_vec();
        }

        if oiv.len() > 16 {
            oiv = oiv[0..16].to_vec();
        }

        self.decb = true;
        let d = crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize192, &okey,&oiv,crypto::blockmodes::PkcsPadding);
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



pub struct Aes256CbcAlgo {
    encb :bool,
    decb :bool,
    enc :Vec<Box<dyn crypto::symmetriccipher::Encryptor>>,
    dec :Vec<Box<dyn crypto::symmetriccipher::Decryptor>>,
}

impl Aes256CbcAlgo {
    pub (crate) fn new() -> Result<Self,Box<dyn Error>> {
        Ok(Self {
            encb :false,
            decb :false,
            enc :vec![],
            dec :vec![],
        })
    }
}

impl Asn1EncryptOp for Aes256CbcAlgo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        if self.decb {
            self.decb = false;
            self.dec = vec![];
        }

        if key.len() < 32 || iv.len() < 16 {
            ssllib_new_error!{SslEncDeError,"key len {} < 32 iv len {} < 16" ,key.len(),iv.len()}
        }

        let mut okey :Vec<u8> = key.to_vec();
        let mut oiv :Vec<u8> = iv.to_vec();
        if okey.len() > 32 {
            okey = okey[0..32].to_vec();
        }

        if oiv.len() > 16 {
            oiv = oiv[0..16].to_vec();
        }

        self.encb = true;
        let c = crypto::aes::cbc_encryptor(crypto::aes::KeySize::KeySize256, &okey,&oiv,crypto::blockmodes::PkcsPadding);
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

impl Asn1DecryptOp for Aes256CbcAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        if self.encb {
            self.encb = false;
            self.enc = vec![];
        }

        if key.len() < 32 || iv.len() < 16 {
            ssllib_new_error!{SslEncDeError,"key len {} < 32 iv len {} < 16" ,key.len(),iv.len()}
        }

        let mut okey :Vec<u8> = key.to_vec();
        let mut oiv :Vec<u8> = iv.to_vec();
        if okey.len() > 32 {
            okey = okey[0..32].to_vec();
        }

        if oiv.len() > 16 {
            oiv = oiv[0..16].to_vec();
        }

        self.decb = true;
        let d = crypto::aes::cbc_decryptor(crypto::aes::KeySize::KeySize256, &okey,&oiv,crypto::blockmodes::PkcsPadding);
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

pub type Aes256CfbEnc = CfbBitsBufEncryptor<aes::Aes256,128>;
pub type Aes256CfbDec = CfbBitsBufDecryptor<aes::Aes256,128>;


#[derive(Clone)]
pub struct Aes256CfbAlgo {
    iv :Vec<u8>,
    key :Vec<u8>,
    innerenc : Aes256CfbEnc,
    innerdec :Aes256CfbDec,
    initenc :bool,
    initdec :bool,
}

impl Aes256CfbAlgo {
    pub fn new() -> Result<Self,Box<dyn Error>> {
        let key = vec![0;32];
        let iv =vec![0;16];
        let ckey :&[u8] = &key;
        let civ :&[u8] = &iv;
        let retv = Aes256CfbAlgo {
            iv : iv.clone(),
            key :key.clone(),
            innerenc :Aes256CfbEnc::new(ckey.into(),civ.into()),
            innerdec :Aes256CfbDec::new(ckey.into(),civ.into()),
            initenc : false,
            initdec :false,
        };
        Ok(retv)
    }
}



impl Asn1EncryptOp for Aes256CfbAlgo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() < 16 || self.key.len() < 32{
            ssllib_new_error!{SslEncDeError,"iv.len {} < 16 || key.len {} < 32",iv.len(),key.len()}
        }

        if self.iv.len() > 16 {
            self.iv = self.iv[0..16].to_vec();
        }

        if self.key.len() > 32 {
            self.key = self.key[0..32].to_vec();
        }

        self.initenc = true;
        self.initdec = false;
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.innerenc = Aes256CfbEnc::new(ckey.into(),civ.into());

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

impl Asn1DecryptOp for Aes256CfbAlgo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() < 16 || self.key.len() < 32{
            ssllib_new_error!{SslEncDeError,"iv.len {} < 16 || key.len {} < 32",iv.len(),key.len()}
        }

        if self.iv.len() > 16 {
            self.iv = self.iv[0..16].to_vec();
        }

        if self.key.len() > 32 {
            self.key = self.key[0..32].to_vec();
        }

        self.initdec = true;
        self.initenc = false;
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.innerdec = Aes256CfbDec::new(ckey.into(),civ.into());

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


pub type Aes256Cfb1Enc = CfbBitsBufEncryptor<aes::Aes256,1>;
pub type Aes256Cfb1Dec = CfbBitsBufDecryptor<aes::Aes256,1>;


#[derive(Clone)]
pub struct Aes256Cfb1Algo {
    iv :Vec<u8>,
    key :Vec<u8>,
    innerenc : Aes256Cfb1Enc,
    innerdec :Aes256Cfb1Dec,
    initenc :bool,
    initdec :bool,
}

impl Aes256Cfb1Algo {
    pub fn new() -> Result<Self,Box<dyn Error>> {
        let key = vec![0;32];
        let iv =vec![0;16];
        let ckey :&[u8] = &key;
        let civ :&[u8] = &iv;
        let retv = Self {
            iv : iv.clone(),
            key :key.clone(),
            innerenc :Aes256Cfb1Enc::new(ckey.into(),civ.into()),
            innerdec :Aes256Cfb1Dec::new(ckey.into(),civ.into()),
            initenc : false,
            initdec :false,
        };
        Ok(retv)
    }
}



impl Asn1EncryptOp for Aes256Cfb1Algo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() < 16 || self.key.len() < 32{
            ssllib_new_error!{SslEncDeError,"iv.len {} < 16 || key.len {} < 32",iv.len(),key.len()}
        }

        if self.iv.len() > 16 {
            self.iv = self.iv[0..16].to_vec();
        }

        if self.key.len() > 32 {
            self.key = self.key[0..32].to_vec();
        }

        self.initenc = true;
        self.initdec = false;
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.innerenc = Aes256Cfb1Enc::new(ckey.into(),civ.into());

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

impl Asn1DecryptOp for Aes256Cfb1Algo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() < 16 || self.key.len() < 32{
            ssllib_new_error!{SslEncDeError,"iv.len {} < 16 || key.len {} < 32",iv.len(),key.len()}
        }

        if self.iv.len() > 16 {
            self.iv = self.iv[0..16].to_vec();
        }

        if self.key.len() > 32 {
            self.key = self.key[0..32].to_vec();
        }

        self.initdec = true;
        self.initenc = false;
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.innerdec = Aes256Cfb1Dec::new(ckey.into(),civ.into());

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

pub type Aes256Cfb8Enc = CfbBitsBufEncryptor<aes::Aes256,8>;
pub type Aes256Cfb8Dec = CfbBitsBufDecryptor<aes::Aes256,8>;


#[derive(Clone)]
pub struct Aes256Cfb8Algo {
    iv :Vec<u8>,
    key :Vec<u8>,
    innerenc : Aes256Cfb8Enc,
    innerdec :Aes256Cfb8Dec,
    initenc :bool,
    initdec :bool,
}

impl Aes256Cfb8Algo {
    pub fn new() -> Result<Self,Box<dyn Error>> {
        let key = vec![0;32];
        let iv =vec![0;16];
        let ckey :&[u8] = &key;
        let civ :&[u8] = &iv;
        let retv = Self {
            iv : iv.clone(),
            key :key.clone(),
            innerenc :Aes256Cfb8Enc::new(ckey.into(),civ.into()),
            innerdec :Aes256Cfb8Dec::new(ckey.into(),civ.into()),
            initenc : false,
            initdec :false,
        };
        Ok(retv)
    }
}



impl Asn1EncryptOp for Aes256Cfb8Algo {
    fn init_encrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() < 16 || self.key.len() < 32{
            ssllib_new_error!{SslEncDeError,"iv.len {} < 16 || key.len {} < 32",iv.len(),key.len()}
        }

        if self.iv.len() > 16 {
            self.iv = self.iv[0..16].to_vec();
        }

        if self.key.len() > 32 {
            self.key = self.key[0..32].to_vec();
        }

        self.initenc = true;
        self.initdec = false;
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.innerenc = Aes256Cfb8Enc::new(ckey.into(),civ.into());

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

impl Asn1DecryptOp for Aes256Cfb8Algo {
    fn init_decrypt(&mut self,key :&[u8],iv :&[u8]) -> Result<(),Box<dyn Error>> {
        self.iv = iv.to_vec();
        self.key = key.to_vec();
        if self.iv.len() < 16 || self.key.len() < 32{
            ssllib_new_error!{SslEncDeError,"iv.len {} < 16 || key.len {} < 32",iv.len(),key.len()}
        }

        if self.iv.len() > 16 {
            self.iv = self.iv[0..16].to_vec();
        }

        if self.key.len() > 32 {
            self.key = self.key[0..32].to_vec();
        }

        self.initdec = true;
        self.initenc = false;
        let ckey :&[u8] = &self.key;
        let civ :&[u8] = &self.iv;
        self.innerdec = Aes256Cfb8Dec::new(ckey.into(),civ.into());

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
    }

    return None;
}

pub fn get_enc_names() -> Vec<String> {
    return vec![ENC_AES_128_CBC.to_string(),ENC_AES_192_CBC.to_string(),ENC_AES_256_CBC.to_string(),ENC_AES_256_CFB.to_string(),ENC_AES_256_CFB1.to_string(),ENC_AES_256_CFB8.to_string()];
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
    }

    return None;
}