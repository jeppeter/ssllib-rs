use crate::*;
use crate::logger::*;
use cipher::{BlockEncryptMut,BlockCipher,Block,InnerIvInit,Iv,AlgorithmName,crypto_common::{InnerUser,IvSizeUser}};
use std::fmt;
use std::error::Error;
use zeroize::Zeroize;


ssllib_error_class!{CfbModeError}


fn get_mask_bits(inbytes :&[u8],bits :usize, offsetbits :usize) -> Vec<u8> {
    let mut idx :usize=0;
    let mut sbidx :usize;
    let mut scuridx :usize;
    let mut srem :usize;
    let mut dbix :usize;
    let mut drem :usize;
    let mut retv :Vec<u8> = vec![0;(bits + 7) >> 3];

    while idx < bits {
        scuridx = offsetbits + idx;
        sbidx = scuridx >> 3 ;
        srem = scuridx % 8;
        dbix = idx >> 3;
        drem = idx % 8;
        if (inbytes[sbidx] & ( 1 << (7 - srem))) != 0 {
            retv[dbix] |= 1 << (7 - drem);
        }
        idx += 1;
    }
    return retv;
}

fn mask_new_bits(data :&mut [u8],bits :usize, offsetbits :usize, maskbytes :&[u8]) {
    let mut idx :usize=0;
    let mut dbidx :usize;
    let mut dcuridx :usize;
    let mut drem :usize;
    let mut sbix :usize;
    let mut srem :usize;

    while idx < bits {
        dcuridx = offsetbits + idx;
        dbidx = dcuridx  >> 3;
        drem = dcuridx % 8;
        sbix = idx >> 3;
        srem = idx % 8;
        if (maskbytes[sbix] & ( 1 << (7 - srem))) != 0 {
            ssllib_log_trace!("[{}]bit set [{}] shift {} [0x{:x}] => [0x{:x}]",idx, dbidx,drem, data[dbidx],data[dbidx] | (1 << (7 - drem)));
            data[dbidx] |= 1 << (7 - drem);
        } else {
            ssllib_log_trace!("[{}]bit clear [{}] shift {} [0x{:x}] => [0x{:x}]",idx, dbidx, drem, data[dbidx], data[dbidx] & (!(1 << (7 - drem))));
            data[dbidx] &= !(1 << (7 - drem));
        }
        idx += 1;
    }
    return;

}


/// to make cfb1
#[derive(Clone)]
pub struct CfbBitsBufEncryptor<C,const BITSIZE:u8=8>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
    pos: usize,
}

impl<C,const BITSIZE:u8> CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{

    fn _encrypt_bitsize(&mut self,inbytes :&[u8],outbytes :&mut[u8],ivec :&mut [u8],nbits :usize) {
        let mut ovec :[u8;16*2+1] = [0;16*2+1];
        let num :usize = ((nbits + 7) >> 3) as usize;
        let mut n:usize;
        ssllib_buffer_trace!(ovec.as_ptr(),ovec.len(),"ovec");
        ovec[0..16].copy_from_slice(&ivec[0..16]);
        ssllib_buffer_trace!(ovec.as_ptr(),ovec.len(),"ovec");
        self.cipher.encrypt_block_mut(ivec.into());
        ssllib_buffer_trace!(ivec.as_ptr(),ivec.len(),"ivec");
        n = 0;
        while n<num {
            ssllib_log_trace!("out[{}]=ovec[16+{}] [0x{:x}] => [0x{:x}] (0x{:x} ^ 0x{:x})",n,n,ovec[16+n],inbytes[n] ^ ivec[n],inbytes[n],ivec[n]);
            ovec[16+n] = inbytes[n] ^ ivec[n];
            outbytes[n] = ovec[16+n];
            n += 1;
        }
        ssllib_buffer_trace!(ovec.as_ptr(),16,"ovec");
        //ssllib_buffer_trace!(outbytes.as_ptr(),16,"out");
        let rem = nbits % 8;
        let leftnum = (nbits >> 3) as usize;
        if rem == 0 {
            ivec[0..16].copy_from_slice(&ovec[leftnum..leftnum+16]);
        } else {
            n = 0;
            while n < 16 {
                ivec[n] = ((ovec[n + leftnum] << rem) | (ovec[n + leftnum + 1] >> (8 - rem))) as u8;
                n += 1;
            }
            ssllib_buffer_trace!(ivec.as_ptr(),16,"ivec");
            ssllib_buffer_trace!(ovec.as_ptr(),16,"ovec");
        }
        return;
    }

    #[allow(unused_variables)]
    #[allow(unused_assignments)]
    fn _encrypt_bits_shift(&mut  self, data :&mut [u8],ivec :&mut [u8],nbits :usize) {
        let mut c :Vec<u8>;
        let mut d  = vec![0;(nbits + 7) >> 3];
        let mut n :usize;
        let mask :u8;
        let topbits :u8;
        let totalbits :usize = data.len() * 8;
        let inbytes :Vec<u8> = data.to_vec().clone();
        let nbytes :Vec<u8> = vec![0;data.len()];
        data.copy_from_slice(&nbytes);
        let mut tmp1 :u8;
        let mut tmp2 :u8;
        topbits = ((1 << nbits) - 1) as u8;
        mask = (topbits << (8 - nbits)) as u8;

        n = 0;
        while n < totalbits {
            c = get_mask_bits(&inbytes,nbits,n);
            ssllib_log_trace!("tmpin 0x{:x}",c[0]);
            self._encrypt_bitsize(&c,&mut d,ivec,nbits);
            ssllib_log_trace!("out[{}/8] = 0x{:x} d[0] = 0x{:x}",n,data[n>>3],d[0]);
            tmp1 = data[n >> 3] & (!(1 << (7 - n % 8 )));
            tmp2 = ( d[0] & mask ) >> (n % 8);
            ssllib_log_trace!("tmp1 0x{:x} = out[{} / 8] [0x{:x}] & ~(1 << (unsigned int)(7 - {} % 8)))",tmp1,n,data[n >> 3],n);
            ssllib_log_trace!("tmp2 0x{:x} = (d[0] [0x{:x}] & 0x80) >> (n {} % 8)",tmp2,d[0],n);
            mask_new_bits(data,nbits,n,&d);
            //data[n >> 3] =  tmp1 | tmp2 ;
            ssllib_log_trace!("out[{} / 8] = 0x{:x}", n, data[n >> 3]);
            n += nbits;
        }
        return;
    }

    /// Encrypt a buffer in multiple parts.
    #[allow(unreachable_code)]
    pub fn encrypt(&mut self, mut data: &mut [u8]) -> Result<(),Box<dyn Error>> {

        if BITSIZE < 1 || BITSIZE as usize > (C::block_size() * 8) {
            ssllib_new_error!{CfbModeError,"BITSIZE {} < 1 || > {}",BITSIZE ,C::block_size()*8};
        }

        if ((data.len() * 8) % BITSIZE as usize) != 0 {
            ssllib_new_error!{CfbModeError,"{} % {} != 0",data.len() * 8,BITSIZE};
        }
        let mut iv = self.iv.clone();

        ssllib_buffer_trace!(iv.as_ptr(),iv.len(),"iv");
        self._encrypt_bits_shift(&mut data,&mut iv,BITSIZE as usize);
        self.iv = iv.clone();
        return Ok(());
    }

    /// Returns the current state (block and position) of the decryptor.
    pub fn get_state(&self) -> (&Block<C>, usize) {
        (&self.iv, self.pos)
    }

    /// Restore from the given state for resumption.
    pub fn from_state(cipher: C, iv: &Block<C>, pos: usize) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            pos,
        }
    }
}

impl<C,const BITSIZE:u8> InnerUser for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C,const BITSIZE:u8> IvSizeUser for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C,const BITSIZE:u8> InnerIvInit for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    #[allow(unused_mut)]
    fn inner_iv_init(mut cipher: C, iv: &Iv<Self>) -> Self {
        //let mut iv = iv.clone();
        //ssllib_buffer_trace!(iv.as_ptr(),iv.len(),"iv init");
        //cipher.encrypt_block_mut(&mut iv);
        //ssllib_buffer_trace!(iv.as_ptr(),iv.len(),"encrypt iv");
        Self { cipher : cipher, iv:iv.clone(), pos: 0 }
    }
}

impl<C,const BITSIZE:u8> AlgorithmName for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::CfbBitsBufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C,const BITSIZE:u8> std::fmt::Debug for CfbBitsBufEncryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::CfbBitsBufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

//#[cfg_attr(docsrs)]
//#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher,const BITSIZE:u8> Drop for CfbBitsBufEncryptor<C,BITSIZE> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

//#[cfg(feature = "zeroize")]
//#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
//impl<C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop,const BITSIZE:u8> ZeroizeOnDrop for CfbBitsBufEncryptor<C,BITSIZE> {}



/// CFB mode buffered decryptor.
#[derive(Clone)]
pub struct CfbBitsBufDecryptor<C,const BITSIZE:u8=8>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
    pos: usize,
}

impl<C,const BITSIZE:u8> CfbBitsBufDecryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{

    fn _decrypt_bitsize(&mut self,inbytes :&[u8],outbytes :&mut[u8],ivec :&mut [u8],nbits :usize) {
        let mut ovec :[u8;16*2+1] = [0;16*2+1];
        let num :usize = ((nbits + 7) >> 3) as usize;
        let mut n:usize;
        ssllib_buffer_trace!(ovec.as_ptr(),ovec.len(),"ovec");
        ovec[0..16].copy_from_slice(&ivec[0..16]);
        ssllib_buffer_trace!(ovec.as_ptr(),ovec.len(),"ovec");
        self.cipher.encrypt_block_mut(ivec.into());
        ssllib_buffer_trace!(ivec.as_ptr(),ivec.len(),"ivec");
        n = 0;
        while n<num {
            ssllib_log_trace!("out[{}]= [0x{:x}] => [0x{:}] ( 0x{:x} ^ 0x{:x}) ovec[16+{}] = [0x{:x}]",n,outbytes[n],inbytes[n] ^ ivec[n],inbytes[n],ivec[n],n,inbytes[n]);
            ovec[16+n] = inbytes[n];
            outbytes[n] = inbytes[n] ^ ivec[n];
            n += 1;
        }
        ssllib_buffer_trace!(ovec.as_ptr(),16,"ovec");
        //ssllib_buffer_trace!(outbytes.as_ptr(),16,"out");
        let rem = nbits % 8;
        let leftnum = (nbits >> 3) as usize;
        if rem == 0 {
            ivec[0..16].copy_from_slice(&ovec[leftnum..leftnum+16]);
        } else {
            n = 0;
            while n < 16 {
                ivec[n] = ((ovec[n + leftnum] << rem) | (ovec[n + leftnum + 1] >> (8 - rem))) as u8;
                n += 1;
            }
            ssllib_buffer_trace!(ivec.as_ptr(),16,"ivec");
            ssllib_buffer_trace!(ovec.as_ptr(),16,"ovec");
        }
        return;
    }

    #[allow(unused_variables)]
    #[allow(unused_assignments)]
    fn _decrypt_bits_shift(&mut  self, data :&mut [u8],ivec :&mut [u8],nbits :usize) {
        let mut c :Vec<u8>;
        let mut d  = vec![0;(nbits + 7) >> 3];
        let mut n :usize;
        let mask :u8;
        let topbits :u8;
        let totalbits :usize = data.len() * 8;
        let inbytes :Vec<u8> = data.to_vec().clone();
        let nbytes :Vec<u8> = vec![0;data.len()];
        data.copy_from_slice(&nbytes);
        let mut tmp1 :u8;
        let mut tmp2 :u8;
        topbits = ((1 << nbits) - 1) as u8;
        mask = (topbits << (8 - nbits)) as u8;

        n = 0;
        while n < totalbits {
            c = get_mask_bits(&inbytes,nbits,n);
            ssllib_log_trace!("tmpin 0x{:x}",c[0]);
            self._decrypt_bitsize(&c,&mut d,ivec,nbits);
            ssllib_log_trace!("out[{}/8] = 0x{:x} d[0] = 0x{:x}",n,data[n>>3],d[0]);
            tmp1 = data[n >> 3] & (!(1 << (7 - n % 8 )));
            tmp2 = ( d[0] & mask ) >> (n % 8);
            ssllib_log_trace!("tmp1 0x{:x} = out[{} / 8] [0x{:x}] & ~(1 << (unsigned int)(7 - {} % 8)))",tmp1,n,data[n >> 3],n);
            ssllib_log_trace!("tmp2 0x{:x} = (d[0] [0x{:x}] & 0x80) >> (n {} % 8)",tmp2,d[0],n);
            mask_new_bits(data,nbits,n,&d);
            //data[n >> 3] =  tmp1 | tmp2 ;
            ssllib_log_trace!("out[{} / 8] = 0x{:x}", n, data[n >> 3]);
            n += nbits;
        }
        return;
    }

    /// Decrypt a buffer in multiple parts.
    pub fn decrypt(&mut self, mut data: &mut [u8]) -> Result<(),Box<dyn Error>> {

        if BITSIZE < 1 || BITSIZE as usize > (C::block_size() * 8) {
            ssllib_new_error!(CfbModeError,"BITSIZE {} < 1 || > {}",BITSIZE, C::block_size() * 8);
        }

        if ((data.len() * 8) % BITSIZE as usize) != 0 {
            ssllib_new_error!(CfbModeError,"{} % {} != 0",data.len() * 8,BITSIZE);
        }
        let mut iv = self.iv.clone();

        ssllib_buffer_trace!(iv.as_ptr(),iv.len(),"iv");
        self._decrypt_bits_shift(&mut data,&mut iv,BITSIZE as usize);
        self.iv = iv.clone();
        return Ok(());
    }

    /// Returns the current state (block and position) of the decryptor.
    pub fn get_state(&self) -> (&Block<C>, usize) {
        (&self.iv, self.pos)
    }

    /// Restore from the given state for resumption.
    pub fn from_state(cipher: C, iv: &Block<C>, pos: usize) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            pos,
        }
    }
}

impl<C,const BITSIZE:u8> InnerUser for CfbBitsBufDecryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C,const BITSIZE:u8> IvSizeUser for CfbBitsBufDecryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C,const BITSIZE:u8> InnerIvInit for CfbBitsBufDecryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    #[allow(unused_mut)]
    fn inner_iv_init(mut cipher: C, iv: &Iv<Self>) -> Self {
        let  iv = iv.clone();
        Self { cipher, iv, pos: 0 }
    }
}

impl<C,const BITSIZE:u8> AlgorithmName for CfbBitsBufDecryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::CfbBitsBufDecryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C,const BITSIZE:u8> fmt::Debug for CfbBitsBufDecryptor<C,BITSIZE>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::CfbBitsBufDecryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

//#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher,const BITSIZE:u8> Drop for CfbBitsBufDecryptor<C,BITSIZE> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

//#[cfg(feature = "zeroize")]
//#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
//impl<C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop,const BITSIZE:u8> ZeroizeOnDrop for CfbBitsBufDecryptor<C,BITSIZE> {}
