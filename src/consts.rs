
pub const KEY_JSON_TYPE :&str = "type";
pub const KEY_JSON_SALT :&str = "salt";
pub const KEY_JSON_TIMES :&str = "times";
pub const KEY_JSON_PASSIN :&str = "passin";
pub const KEY_JSON_PASSOUT :&str = "passout";
pub const KEY_JSON_AESKEY :&str = "aeskey";
pub const KEY_JSON_ENCDATA :&str = "encdata";
pub const KEY_JSON_DECDATA :&str = "decdata";
pub const KEY_JSON_ENCTYPE :&str = "enctype";
pub const KEY_JSON_AES256CBC :&str = "aes256cbc";
pub const KEY_JSON_AES256CFB :&str = "aes256cfb";
pub const KEY_JSON_RANDFILE :&str = "randfile";
pub const KEY_JSON_KEY :&str = "key";
pub const KEY_JSON_RSA :&str = "rsa";
pub const KEY_JSON_EC :&str = "ec";
pub const KEY_JSON_DATA :&str = "data";
pub const KEY_JSON_PBES2 :&str = "pbes2";
pub const KEY_JSON_PBKDF2 :&str = "pbkdf2";
pub const KEY_JSON_DIGESTTYPE :&str = "digesttype";
pub const KEY_JSON_SECP384R1 :&str = "secp384r1";


pub const KEY_HMAC_WITH_SHA256 :&str = "hmacWithSha256";

pub const OID_PBES2 :&str = "1.2.840.113549.1.5.13";
pub const OID_PBKDF2 :&str = "1.2.840.113549.1.5.12";
pub const OID_HMAC_WITH_SHA256 :&str = "1.2.840.113549.2.9";
pub const OID_RSA_ENCRYPTION :&str = "1.2.840.113549.1.1.1";
pub const OID_EC_PUBLICKEY_ENCRYPTION :&str = "1.2.840.10045.2.1";
pub const OID_SHA256_WITH_RSA_ENCRYPTION :&str = "1.2.840.113549.1.1.11";
pub const OID_KEY_BAG :&str = "1.2.840.113549.1.12.10.1.1";
pub const OID_PKCS8_SHROUDED_KEY_BAG :&str = "1.2.840.113549.1.12.10.1.2";
pub const OID_PKCS12_CERT_BAG : &str = "1.2.840.113549.1.12.10.1.3";
pub const OID_SAFE_CONTENT_BAG : &str = "1.2.840.113549.1.12.10.1.6";
pub const OID_PKCS7_ENCRYPTED_DATA :&str = "1.2.840.113549.1.7.6";
pub const OID_PKCS7_DATA :&str = "1.2.840.113549.1.7.1";
pub const OID_PKCS12_SAFE_BAG_X509_CERT :&str = "1.2.840.113549.1.9.22.1";
pub const OID_SHA256_DIGEST :&str = "2.16.840.1.101.3.4.2.1";
pub const OID_EC_PUBLICK_KEY :&str = "1.2.840.10045.2.1";

pub const OID_FRIEDLY_NAME :&str = "1.2.840.113549.1.9.20";
pub const OID_LOCAL_KEY_ID:&str = "1.2.840.113549.1.9.21";


pub const OID_ECDSA_WITH_SHA256_PKEY :&str = "1.2.840.10045.4.3.2";

pub const OID_AES_128_CBC :&str = "2.16.840.1.101.3.4.1.2";
pub const OID_AES_192_CBC :&str = "2.16.840.1.101.3.4.1.22";
pub const OID_AES_256_CBC :&str = "2.16.840.1.101.3.4.1.42";

pub const OID_AES_128_CFB :&str = "2.16.840.1.101.3.4.1.4";
pub const OID_AES_192_CFB :&str = "2.16.840.1.101.3.4.1.24";
pub const OID_AES_256_CFB :&str = "2.16.840.1.101.3.4.1.44";


pub const OID_SECT163K1 :&str = "1.3.132.0.1";
pub const OID_SECT163R1 :&str = "1.3.132.0.2";
pub const OID_SECT239K1 :&str = "1.3.132.0.3";
pub const OID_SECT113R1 :&str = "1.3.132.0.4";
pub const OID_SECT113R2 :&str = "1.3.132.0.5";
pub const OID_SECP112R1 :&str = "1.3.132.0.6";
pub const OID_SECP112R2 :&str = "1.3.132.0.7";
pub const OID_SECP160R1 :&str = "1.3.132.0.8";
pub const OID_SECP160K1 :&str = "1.3.132.0.9";
pub const OID_SECP256K1 :&str = "1.3.132.0.10";
pub const OID_SECT163R2 :&str = "1.3.132.0.15";
pub const OID_SECT283K1 :&str = "1.3.132.0.16";
pub const OID_SECT283R1 :&str = "1.3.132.0.17";
pub const OID_SECT131R1 :&str = "1.3.132.0.22";
pub const OID_SECT131R2 :&str = "1.3.132.0.23";
pub const OID_SECT193R1 :&str = "1.3.132.0.24";
pub const OID_SECT193R2 :&str = "1.3.132.0.25";
pub const OID_SECT233K1 :&str = "1.3.132.0.26";
pub const OID_SECT233R1 :&str = "1.3.132.0.27";
pub const OID_SECP128R1 :&str = "1.3.132.0.28";
pub const OID_SECP128R2 :&str = "1.3.132.0.29";
pub const OID_SECP160R2 :&str = "1.3.132.0.30";
pub const OID_SECP192K1 :&str = "1.3.132.0.31";
pub const OID_SECP224K1 :&str = "1.3.132.0.32";
pub const OID_SECP224R1 :&str = "1.3.132.0.33";
pub const OID_SECP384R1 :&str = "1.3.132.0.34";
pub const OID_SECP521R1 :&str = "1.3.132.0.35";
pub const OID_SECT409K1 :&str = "1.3.132.0.36";
pub const OID_SECT409R1 :&str = "1.3.132.0.37";
pub const OID_SECT571K1 :&str = "1.3.132.0.38";
pub const OID_SECT571R1 :&str = "1.3.132.0.39";

pub const ENC_AES_128_CBC :&str = "aes-128-cbc";
pub const ENC_AES_192_CBC :&str = "aes-192-cbc";
pub const ENC_AES_256_CBC :&str = "aes-256-cbc";

pub const ENC_AES_128_CFB :&str = "aes-128-cfb";
pub const ENC_AES_128_CFB1 :&str = "aes-128-cfb1";
pub const ENC_AES_128_CFB8 :&str = "aes-128-cfb8";
pub const ENC_AES_192_CFB :&str = "aes-192-cfb";
pub const ENC_AES_192_CFB1 :&str = "aes-192-cfb1";
pub const ENC_AES_192_CFB8 :&str = "aes-192-cfb8";
pub const ENC_AES_256_CFB :&str = "aes-256-cfb";
pub const ENC_AES_256_CFB1 :&str = "aes-256-cfb1";
pub const ENC_AES_256_CFB8 :&str = "aes-256-cfb8";

pub const DIGEST_HMAC_SHA256 :&str = "hmacsha256";
//pub const DIGEST_HMAC_SHA256_EX :&str = "hmacsha256ex";
pub const DIGEST_HMAC_SHA256_SIMPLE :&str = "hmacsha256simple";
pub const DIGEST_SHA256 :&str = "sha256";

pub const PKCS12_MAC_ID :u8 = 3;
pub const SHA256_BLOCK_SIZE :usize = 64;
pub const SHA256_DIGEST_SIZE :usize = 32;

pub const DGST_SHA256 :&str = "sha256";
pub const ECDSA_SHA256_PKEY :&str = "ecdsa-with-sha256";


pub const PKCS7_TYPE_DATA :&str   = "data";
pub const PKCS7_TYPE_SIGNED :&str = "signed";
pub const PKCS7_TYPE_ENVLOP :&str = "envlop";
pub const PKCS7_TYPE_ENVLOP_AND_SIGNED :&str = "envlopandsigned";
pub const PKCS7_TYPE_DIGEST :&str = "digest";
pub const PKCS7_TYPE_ENCRYPTED :&str = "encrypted";



pub const PKCS7_DATA_OID :&str = "1.2.840.113549.1.7.1";
pub const PKCS7_SIGNED_DATA_OID :&str = "1.2.840.113549.1.7.2";
pub const PKCS7_ENVLOP_DATA_OID :&str = "1.2.840.113549.1.7.3";
pub const PKCS7_ENVLOP_AND_SIGNED_DATA_OID :&str = "1.2.840.113549.1.7.4";
pub const PKCS7_DIGEST_DATA_OID :&str = "1.2.840.113549.1.7.5";
pub const PKCS7_ENCRYPTED_DATA_OID :&str = "1.2.840.113549.1.7.6";


pub const SIGNING_TIME_OID:&str = "1.2.840.113549.1.9.5";

pub const PKCS8_PRIVATE_KEY_TYPE :&str = "pkcs8privatekey";