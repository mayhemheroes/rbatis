use std::collections::HashMap;
use std::sync::Arc;

use crate::mysql::protocol;
use crate::mysql::{MySql, MySqlValue};
use crate::row::{ColumnIndex, Row};
use serde::de::DeserializeOwned;
use crate::value::RawValue;

#[derive(Debug)]
pub struct MySqlRow<'c> {
    pub(super) row: protocol::Row<'c>,
    pub(super) names: Arc<HashMap<Box<str>, u16>>,
}

impl<'c> MySqlRow<'c> {
    pub fn json_decode_impl<T, I>(&self, index: I) -> crate::Result<T>
        where
            I: ColumnIndex<'c, Self>,
            T: DeserializeOwned
    {
        self.json_decode(index)
    }
}

impl crate::row::private_row::Sealed for MySqlRow<'_> {}

impl<'c> Row<'c> for MySqlRow<'c> {
    type Database = MySql;

    fn len(&self) -> usize {
        self.row.len()
    }

    #[doc(hidden)]
    fn try_get_raw<I>(&self, index: I) -> crate::Result<MySqlValue<'c>>
        where
            I: ColumnIndex<'c, Self>,
    {
        let index = index.index(self)?;
        let column_ty = self.row.columns[index].clone();
        let buffer = self.row.get(index);
        let value = match (self.row.binary, buffer) {
            (_, None) => MySqlValue::null(),
            (true, Some(buf)) => MySqlValue::binary(column_ty, buf),
            (false, Some(buf)) => MySqlValue::text(column_ty, buf),
        };

        Ok(value)
    }

    fn json_decode<T, I>(&self, index: I) -> crate::Result<T>
        where
            I: ColumnIndex<'c, Self>,
            T: DeserializeOwned
    {
        let value = self.try_get_raw(index)?;
        let v = value.try_to_json();
        if (v.is_err()) {
            return Err(decode_err!("unexpected value {:?} for serde_json::Value", v.err().unwrap()));
        }
        let t: Result<T, serde_json::Error> = serde_json::from_value(v.unwrap());
        match t {
            Ok(r) => {
                return Ok(r);
            }
            Err(e) => {
                return Err(decode_err!("unexpected value {:?} for serde_json::from_value", e.to_string()));
            }
        }
    }
}

impl<'c> ColumnIndex<'c, MySqlRow<'c>> for usize {
    fn index(&self, row: &MySqlRow<'c>) -> crate::Result<usize> {
        let len = Row::len(row);

        if *self >= len {
            return Err(crate::Error::ColumnIndexOutOfBounds { len, index: *self });
        }

        Ok(*self)
    }
}

impl<'c> ColumnIndex<'c, MySqlRow<'c>> for str {
    fn index(&self, row: &MySqlRow<'c>) -> crate::Result<usize> {
        row.names
            .get(self)
            .ok_or_else(|| crate::Error::ColumnNotFound((*self).into()))
            .map(|&index| index as usize)
    }
}
