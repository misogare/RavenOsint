//! raven-storage — SQLite / PostgreSQL persistence layer.
//!
//! ## Features
//! - `sqlite`   (default) — embeds SQLite via sqlx
//! - `postgres`           — connects to a PostgreSQL server via sqlx
//!
//! The backend is chosen at runtime from the database URL prefix:
//!   `sqlite://…`   → `SqliteStore`
//!   `postgres://…` → `PostgresStore`

pub mod model;
pub mod store;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use store::{new_store, ListParams, ResultStore};
