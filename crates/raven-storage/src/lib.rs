// lib.rs
pub mod model;
pub mod store;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "duckdb")]
pub mod duckdb_store;

pub use store::{new_store, ListParams, ResultStore};
