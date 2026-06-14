use crate::user::wallet::Wallet;
use std::collections::HashMap;

pub fn post() {
    let w = Wallet;
    w.credit();
    let _seen: HashMap<String, i64> = HashMap::new();
}
