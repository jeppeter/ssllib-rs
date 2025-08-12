
use std::error::Error;
use std::boxed::Box;
#[allow(unused_imports)]
use regex::Regex;

use extargsparse_worker::{extargs_error_class,extargs_new_error};
use crate::base64::{decode_base64,encode_base64};
