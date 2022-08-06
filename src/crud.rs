///gen sql => INSERT INTO table_name (column1,column2,column3,...) VALUES (value1,value2,value3,...);
///
/// example:
/// ```rust
/// rbatis::impl_insert!(BizActivity{});
/// ```
///
#[macro_export]
macro_rules! impl_insert {
    ($table:ty{}) => {
        $crate::impl_insert!(
            $table,
            $crate::utils::string_util::to_snake_name(stringify!($table))
        );
    };
    ($table:ty,$table_name:expr) => {
        impl $table {
            pub async fn insert(
                rb: &mut dyn $crate::executor::Executor,
                table: &$table,
            ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                #[py_sql(
                    "`insert into ${table_name} (`
             trim ',':
               for k,v in table:
                  if k == 'id' && v== null:
                    #{continue}
                 ${k},
             `) VALUES (`
             trim ',':
               for k,v in table:
                  if k == 'id' && v== null:
                     #{continue}
                  #{v},
             )"
                )]
                async fn do_insert(
                    rb: &mut dyn $crate::executor::Executor,
                    table: &$table,
                    table_name: String,
                ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                    impled!()
                }
                let table_name = $table_name.to_string();
                do_insert(rb.into(), table, table_name).await
            }
        }
    };
}

///gen sql => SELECT (column1,column2,column3,...) FROM table_name (column1,column2,column3,...)  *** WHERE ***
///
/// example:
///```rust
/// pub struct BizActivity{}
///rbatis::impl_select!(BizActivity{});
///rbatis::impl_select!(BizActivity{select_all_by_id(id:&str,name:&str) => "select * from biz_activity where id = #{id} and name = #{name}"});
///rbatis::impl_select!(BizActivity{select_by_id(id:String) -> Option => "select * from biz_activity where id = #{id} limit 1"});
///
/// //use
/// //BizActivity::select**()
/// ```
///
#[macro_export]
macro_rules! impl_select {
    ($table:ty{}) => {
        $crate::impl_select!($table,$crate::utils::string_util::to_snake_name(stringify!($table)));
    };
    ($table:ty,$table_name:expr) => {
        impl $table{
            pub async fn select_all(rb: &mut dyn  $crate::executor::Executor)->Result<Vec<$table>,rbdc::Error>{
                #[py_sql(
"select * from ${table_name}")]
async fn do_select_all(rb: &mut dyn $crate::executor::Executor,table_name:String) -> Result<Vec<$table>,rbdc::Error> {impled!()}
            let table_name = $table_name.to_string();
            do_select_all(rb,table_name).await
            }
        }
    };
    ($table:ty{$fn_name:ident($($param_key:ident:$param_type:ty$(,)?)+) => $sql:expr}) => {
        impl $table{
            pub async fn $fn_name(rb: &mut dyn  $crate::executor::Executor,$($param_key:$param_type,)+)->Result<Vec<$table>,rbdc::Error>{
                 if $sql.starts_with("select"){
                     #[py_sql($sql)]
                     async fn do_select_all_raw(rb: &mut dyn $crate::executor::Executor,$($param_key:$param_type,)+) -> Result<Vec<$table>,rbdc::Error> {impled!()}
                     do_select_all_raw(rb,$($param_key ,)+).await
                 }else{
                     #[py_sql("select * from biz_activity ",$sql)]
                     async fn do_select_all(rb: &mut dyn $crate::executor::Executor,$($param_key:$param_type,)+) -> Result<Vec<$table>,rbdc::Error> {impled!()}
                     do_select_all(rb,$($param_key ,)+).await
                 }
            }
        }
    };
    // select to an container
    // for example:
    // impl_select!(BizActivity{select_by_id(id:String) -> Option => "select * from biz_activity where id = #{id} limit 1"});
    // impl_select!(BizActivity{select_by_id(id:String) -> HashMap => "select * from biz_activity where id = #{id} limit 1"});
    // impl_select!(BizActivity{select_by_id(id:String) -> Vec => "select * from biz_activity where id = #{id} limit 1"});
    ($table:ty{$fn_name:ident($($param_key:ident:$param_type:ty$(,)?)+) -> $container:tt => $sql:expr}) => {
        impl $table{
            pub async fn $fn_name(rb: &mut dyn  $crate::executor::Executor,$($param_key:$param_type,)+)->Result<$container<$table>,rbdc::Error>{
                if $sql.starts_with("select"){
                    #[py_sql($sql)]
                    async fn do_select_all_raw(rb: &mut dyn $crate::executor::Executor,$($param_key:$param_type,)+) -> Result<$container<$table>,rbdc::Error> {impled!()}
                    do_select_all_raw(rb,$($param_key ,)+).await
                }else{
                     #[py_sql("select * from biz_activity ",$sql)]
                     async fn do_select_all(rb: &mut dyn $crate::executor::Executor,$($param_key:$param_type,)+) -> Result<$container<$table>,rbdc::Error> {impled!()}
                     do_select_all(rb,$($param_key ,)+).await
                }
            }
        }
    };
}

/// gen sql = UPDATE table_name SET column1=value1,column2=value2,... WHERE some_column=some_value;
/// ```rust
/// rbatis::impl_update!(BizActivity{});
/// ```
#[macro_export]
macro_rules! impl_update {
    ($table:ty{}) => {
        $crate::impl_update!(
            $table,
            $crate::utils::string_util::to_snake_name(stringify!($table))
        );
    };
    ($table:ty,$table_name:expr) => {
        impl $table {
            pub async fn update_by_column(
                rb: &mut dyn $crate::executor::Executor,
                table: &$table,
                column: &str,
            ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                #[py_sql(
                    "`update ${table_name} set `
             trim ',':
               for k,v in table:
                  if k == column || v== null:
                    #{continue}
                 `${k}=#{v},`
             ` where  ${column} = #{column_value}`"
                )]
                async fn do_update_by_column(
                    rb: &mut dyn $crate::executor::Executor,
                    table_name: String,
                    table: &rbs::Value,
                    column_value: &rbs::Value,
                    column: &str,
                ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                    impled!()
                }
                let table_name = $table_name.to_string();
                let table = rbs::to_value!(table);
                let column_value = &table[column];
                do_update_by_column(rb, table_name, &table, column_value, column).await
            }
        }
    };
    ($table:ty{$fn_name:ident($($param_key:ident:$param_type:ty$(,)?)+)} => $sql_where:expr) => {
        impl $table {
            pub async fn $fn_name(
                rb: &mut dyn $crate::executor::Executor,
                table: &$table,
                $($param_key:$param_type,)+
            ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                #[py_sql("`update ${table_name} set  `
                               trim ',':
                                 for k,v in table:
                                   if k == column || v== null:
                                      #{continue}
                                   `${k}=#{v},`
                          ",$sql_where)]
                async fn do_update_by_where(
                    rb: &mut dyn $crate::executor::Executor,
                    table_name: String,
                    table: &rbs::Value,
                    $($param_key:$param_type,)+
                ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                    impled!()
                }
                let table_name = $crate::utils::string_util::to_snake_name(stringify!($table));
                let table = rbs::to_value!(table);
                do_update_by_where(rb, table_name, &table, $($param_key,)+).await
            }
        }
    };
}

/// gen sql = DELETE FROM table_name WHERE some_column=some_value;
///
/// ```rust
/// rbatis::impl_delete!(BizActivity{});
/// ```
#[macro_export]
macro_rules! impl_delete {
    ($table:ty{}) => {
        $crate::impl_delete!(
            $table,
            $crate::utils::string_util::to_snake_name(stringify!($table))
        );
    };
    ($table:ty,$table_name:expr) => {
        impl $table {
            pub async fn delete_by_column(
                rb: &mut dyn $crate::executor::Executor,
                column: &str,
                column_value: &rbs::Value,
            ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                #[py_sql("`delete from ${table_name} where  ${column} = #{column_value}`")]
                async fn do_delete_by_column(
                    rb: &mut dyn $crate::executor::Executor,
                    table_name: String,
                    column_value: &rbs::Value,
                    column: &str,
                ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                    impled!()
                }
                let table_name = $table_name.to_string();
                do_delete_by_column(rb, table_name, column_value, column).await
            }
        }
    };
    ($table:ty{$fn_name:ident($($param_key:ident:$param_type:ty$(,)?)+)} => $sql_where:expr) => {
        impl $table {
            pub async fn $fn_name(
                rb: &mut dyn $crate::executor::Executor,
                $($param_key:$param_type,)+
            ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                #[py_sql("`delete from ${table_name} `",$sql_where)]
                async fn do_delete_by_where(
                    rb: &mut dyn $crate::executor::Executor,
                    table_name: String,
                    $($param_key:$param_type,)+
                ) -> Result<rbdc::db::ExecResult, rbdc::Error> {
                    impled!()
                }
                let table_name = $crate::utils::string_util::to_snake_name(stringify!($table));
                do_delete_by_where(rb, table_name, $($param_key,)+).await
            }
        }
    };
}

#[macro_export]
macro_rules! impl_select_page {
    ($table:ty{$fn_name:ident($($param_key:ident:$param_type:ty$(,)?)+) => $where_sql:expr}) => {
        impl $table {
            pub async fn $fn_name(
                rb: &mut dyn $crate::executor::Executor,
                page_req:&PageRequest,
                $($param_key:$param_type,)+
            ) -> Result<$crate::sql::Page::<$table>, rbdc::Error> {
                #[py_sql("select count(1) as count from ${table_name} ",$where_sql)]
                async fn do_select_page_count(rb: &mut dyn $crate::executor::Executor,table_name: &str,$($param_key:$param_type,)+) -> Result<u64, rbdc::Error> {impled!()}
                let table_name = $crate::utils::string_util::to_snake_name(stringify!($table));
                let total:u64=do_select_page_count(rb, &table_name, $($param_key,)+).await?;
                let records:Vec<$table>;
                if $where_sql.contains("page_no") && $where_sql.contains("page_size"){
                    #[py_sql("select * from ${table_name} ",$where_sql)]
                    async fn do_select_page(rb: &mut dyn $crate::executor::Executor,table_name: &str,page_no:u64,page_size:u64,$($param_key:$param_type,)+) -> Result<Vec<$table>, rbdc::Error> {impled!()}
                    records = do_select_page(rb,&table_name,page_req.page_no, page_req.page_size,$($param_key,)+).await?;
                }else{
                    #[py_sql("select * from ${table_name} ",$where_sql,"
                              limit ${page_no},${page_size}")]
                    async fn do_select_page(rb: &mut dyn $crate::executor::Executor,table_name: &str,page_no:u64,page_size:u64,$($param_key:$param_type,)+) -> Result<Vec<$table>, rbdc::Error> {impled!()}
                    records = do_select_page(rb,&table_name,page_req.page_no, page_req.page_size,$($param_key,)+).await?;
                }
                let mut page = Page::<$table>::new_total(page_req.page_no, page_req.page_size, total);
                page.records = records;
                Ok(page)
            }
        }
    };
}
