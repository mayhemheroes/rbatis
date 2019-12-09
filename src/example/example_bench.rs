use std::fs;
use crate::core::rbatis::Rbatis;
use serde_json::{json, Value};
use crate::ast::bind_node::BindNode;
use crate::ast::node::SqlNode;
use crate::ast::config_holder::ConfigHolder;
//use test::Bencher;
use chrono::Local;
use crate::utils;
use crate::ast::node_type::NodeType;
