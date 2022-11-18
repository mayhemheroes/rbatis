#![no_main]
use libfuzzer_sys::fuzz_target;
use rbdc_pg::types::{Oid, decode::Decode};
use rbdc_pg::value::{PgValue, PgValueFormat};
use rbdc_pg::type_info::PgTypeInfo;
use rbs::Value;

fuzz_target!(|data: (u8, u32, &[u8])| {
    let (value_format, oid, data) = data;

    // unpack a value format
    let value_format = match value_format {
        0 => PgValueFormat::Binary,
        1 => PgValueFormat::Text,
        _ => return,
    };

    // unpack a type info
    let type_info = match PgTypeInfo::try_from_oid(Oid(oid)) {
        Some(ti) => ti,
        None => return,
    };
    
    let mut element_len = data.len() as i32;
    if element_len == 0 {
        element_len = -1;
    }
    let mut sized_data = element_len.to_be_bytes().to_vec();
    sized_data.extend_from_slice(data);
    
    let value = PgValue::get(&mut sized_data.as_slice(), value_format, type_info);
    let _ = Value::decode(value);
});
