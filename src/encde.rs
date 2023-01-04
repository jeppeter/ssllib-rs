
use crate::impls::*;
use crate::*;

ssllib_error_class!{SslEncDeError}

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
	fn encrypt(&self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
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
}

impl Asn1DecryptOp for Aes256CbcAlgo {
	fn decrypt(&self, encdata :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
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
}

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
	fn encrypt(&self, data :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retdata :Vec<u8> = data.to_vec();
		let ckey :&[u8] = &self.key;
		let civ :&[u8] = &self.iv;
		Aes256CfbEnc::new(ckey.into(),civ.into()).encrypt(&mut retdata);
		Ok(retdata)
	}
}

impl Asn1DecryptOp for Aes256CfbAlgo {
	fn decrypt(&self, encdata :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retdata :Vec<u8> = encdata.to_vec();
		let ckey :&[u8] = &self.key;
		let civ :&[u8] = &self.iv;
		Aes256CfbDec::new(ckey.into(),civ.into()).decrypt(&mut retdata);
		Ok(retdata)
	}
}
