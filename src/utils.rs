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
