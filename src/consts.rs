
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
pub const OID_DSA_ENCRYPTION :&str = "1.2.840.10040.4.1";
pub const OID_X25519_ENCRYPTION :&str = "1.3.101.110";
pub const OID_PURE_ED25519 :&str = "1.3.101.112";
pub const OID_EC_PUBLICKEY_ENCRYPTION :&str = "1.2.840.10045.2.1";
pub const OID_KEY_BAG :&str = "1.2.840.113549.1.12.10.1.1";
pub const OID_PKCS8_SHROUDED_KEY_BAG :&str = "1.2.840.113549.1.12.10.1.2";
pub const OID_PKCS12_CERT_BAG : &str = "1.2.840.113549.1.12.10.1.3";
pub const OID_PKCS12_CRL_BAG : &str = "1.2.840.113549.1.12.10.1.4";
pub const OID_SAFE_CONTENT_BAG : &str = "1.2.840.113549.1.12.10.1.6";
pub const OID_PKCS7_ENCRYPTED_DATA :&str = "1.2.840.113549.1.7.6";
pub const OID_PKCS7_DATA :&str = "1.2.840.113549.1.7.1";
pub const OID_PKCS12_SAFE_BAG_X509_CERT :&str = "1.2.840.113549.1.9.22.1";
pub const OID_SHA256_DIGEST :&str = "2.16.840.1.101.3.4.2.1";
pub const OID_SHA384_DIGEST :&str = "2.16.840.1.101.3.4.2.2";
pub const OID_SHA512_DIGEST :&str = "2.16.840.1.101.3.4.2.3";
pub const OID_EC_PUBLICK_KEY :&str = "1.2.840.10045.2.1";

pub const OID_FRIEDLY_NAME :&str = "1.2.840.113549.1.9.20";
pub const OID_LOCAL_KEY_ID:&str = "1.2.840.113549.1.9.21";

pub const OID_SHA1_WITH_RSA_ENCRYPTION :&str = "1.2.840.113549.1.1.5";
pub const OID_SHA256_WITH_RSA_ENCRYPTION :&str = "1.2.840.113549.1.1.11";
pub const OID_SHA384_WITH_RSA_ENCRYPTION :&str = "1.2.840.113549.1.1.12";
pub const OID_SHA512_WITH_RSA_ENCRYPTION :&str = "1.2.840.113549.1.1.13";


pub const OID_X509_CERTIFICATE :&str =  "1.2.840.113549.1.9.22.1";
pub const OID_X509_SDSI_CERTIFICATE :&str = "1.2.840.113549.1.9.22.2";
pub const OID_X509_CRL :&str = "1.2.840.113549.1.9.23.1";

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
pub const DIGEST_MD5 :&str = "md5";
pub const DIGEST_SHA256 :&str = "sha256";
pub const DIGEST_SHA1 :&str = "sha1";
pub const DIGEST_SHA224 :&str = "sha224";
pub const DIGEST_SHA384 :&str = "sha384";
pub const DIGEST_SHA512 :&str = "sha512";

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


pub const TS_STATUS_GRANTED                  :i64 = 0;
pub const TS_STATUS_GRANTED_WITH_MODS        :i64 = 1;
pub const TS_STATUS_REJECTION                :i64 = 2;
pub const TS_STATUS_WAITING                  :i64 = 3;
pub const TS_STATUS_REVOCATION_WARNING       :i64 = 4;
pub const TS_STATUS_REVOCATION_NOTIFICATION  :i64 = 5;

pub const OID_MD5_WITH_RSA :&str = "1.2.840.113549.1.1.4";
pub const OID_SHA1_WITH_RSA :&str = "1.2.840.113549.1.1.5";
pub const OID_SHA256_WITH_RSA :&str = "1.2.840.113549.1.1.11";
pub const OID_SHA384_WITH_RSA :&str = "1.2.840.113549.1.1.12";
pub const OID_SHA512_WITH_RSA :&str = "1.2.840.113549.1.1.13";
pub const OID_RSA_PSS :&str = "1.2.840.113549.1.1.10";
pub const OID_DSA_WITH_SHA1 :&str = "1.2.840.10040.4.3";
pub const OID_DSA_WITH_SHA256 :&str = "2.16.840.1.101.3.4.3.2";
pub const OID_ECDSA_WITH_SHA1 :&str = "1.2.840.10045.4.1";
pub const OID_ECDSA_WITH_SHA256:&str = "1.2.840.10045.4.3.2";
pub const OID_ECDSA_WITH_SHA384:&str = "1.2.840.10045.4.3.3";
pub const OID_ECDSA_WITH_SHA512:&str = "1.2.840.10045.4.3.4";
pub const OID_ISO_SHA1_WITH_RSA :&str = "1.3.14.3.2.29";


pub const OID_RSA_MGF1 :&str = "1.2.840.113549.1.1.8";

pub const OID_COMMON_NAME :&str = "2.5.4.3";
pub const OID_SERIAL_NUMBER :&str = "2.5.4.5";
pub const OID_COUNTRY :&str = "2.5.4.6";
pub const OID_LOCALITY :&str = "2.5.4.7";
pub const OID_PROVINCE :&str = "2.5.4.8";
pub const OID_STREET_ADDRESS :&str = "2.5.4.9";
pub const OID_ORGANIZATION :&str = "2.5.4.10";
pub const OID_ORGANIZATIONAL_UNIT :&str = "2.5.4.11";
pub const OID_POSTAL_CODE :&str = "2.5.4.17";


pub const KEY_USAGE_DIGITAL_SIGNATURE :u8 = 0x80;
pub const KEY_USAGE_CONTENT_COMMITMENT :u8 = 0x40;
pub const KEY_USAGE_KEY_ENCIPHERMENT :u8 = 0x20;
pub const KEY_USAGE_DATA_ENCIPHERMENT :u8 = 0x10;
pub const KEY_USAGE_KEY_AGREEMENT :u8 = 0x8;
pub const KEY_USAGE_CERT_SIGN :u8 = 0x4;
pub const KEY_USAGE_CRL_SIGN :u8 = 0x2;
pub const KEY_USAGE_ENCIPHER_ONLY :u8 = 0x1;
pub const KEY_USAGE_DECIPHER_ONLY :u8 = 0x80;


pub const OID_KEY_USAGE :&str = "2.5.29.15";
pub const OID_CONSTRAINTS_VALID :&str = "2.5.29.19";
pub const OID_SUBJECT_KEY_ID :&str = "2.5.29.14";
pub const OID_URIS :&str = "2.5.29.17";
pub const OID_PERM_EX :&str = "2.5.29.30";
pub const OID_EXT_KEY_USAGE :&str = "2.5.29.37";
pub const OID_POLICIES :&str = "2.5.29.32";
pub const OID_AUTHORITY_KEY_ID :&str = "2.5.29.35";
pub const OID_AUTHORITY_INFO_ACCESS :&str = "1.3.6.1.5.5.7.1.1";

pub const TAG_DNS_NAMES :u64 = 0x82;
pub const TAG_EMAILS_ADDRESSES :u64= 0x81;
pub const TAG_IP_ADDRESSES :u64 = 0x87;
pub const TAG_URIS :u64 = 0x86;

pub const TAG_PERMITTED :u64 = 0xa0;
pub const TAG_EXCLUDED :u64 = 0xa1;


pub const OID_EXT_KEY_USAGE_ANY :&str = "2.5.29.37.0";
pub const OID_EXT_KEY_USAGE_SERVER_AUTH :&str = "1.3.6.1.5.5.7.3.1";
pub const OID_EXT_KEY_USAGE_CLIENT_AUTH :&str = "1.3.6.1.5.5.7.3.2";
pub const OID_EXT_KEY_USAGE_CODE_SIGNING :&str = "1.3.6.1.5.5.7.3.3";
pub const OID_EXT_KEY_USAGE_EMAIL_PROTECTION :&str = "1.3.6.1.5.5.7.3.4";
pub const OID_EXT_KEY_USAGE_IP_SEC_END_SYSTEM :&str = "1.3.6.1.5.5.7.3.5";
pub const OID_EXT_KEY_USAGE_IP_SEC_TUNNEL :&str = "1.3.6.1.5.5.7.3.6";
pub const OID_EXT_KEY_USAGE_IP_SEC_USER :&str = "1.3.6.1.5.5.7.3.7";
pub const OID_EXT_KEY_USAGE_TIME_STAMPING :&str = "1.3.6.1.5.5.7.3.8";
pub const OID_EXT_KEY_USAGE_OCSP_SIGNING :&str = "1.3.6.1.5.5.7.3.9";
pub const OID_EXT_KEY_USAGE_MICROSOFT_SERVER_GATED_CRYPTO :&str = "1.3.6.1.4.1.311.10.3.3";
pub const OID_EXT_KEY_USAGE_NETSCAPE_SERVER_GATED_CRYPTO :&str = "2.16.840.1.113730.4.1";
pub const OID_EXT_KEY_USAGE_MICROSOFT_COMMERCIAL_CODE_SIGNING :&str = "1.3.6.1.4.1.311.2.1.22";
pub const OID_EXT_KEY_USAGE_MICROSOFT_KERNEL_CODE_SIGNING :&str = "1.3.6.1.4.1.311.61.1.1";


pub const OID_AUTHORITY_INFO_ACCESS_OCSP :&str = "1.3.6.1.5.5.7.48.1";
pub const OID_AUTHORITY_INFO_ACCESS_ISSUER :&str = "1.3.6.1.5.5.7.48.2";

pub const PSS_LENGTH_TO_HASHSIZE :usize = 0xff;
pub const PSS_LENGTH_TO_AUTOSIZE :usize = 0;

pub const OID_X509_REQ_EXTENSION :&str = "1.2.840.113549.1.9.14";
