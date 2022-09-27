extern crate serde;
extern crate forensic_rs;
extern crate chrono;
extern crate uuid;
pub mod plugins;

pub mod prelude {
    pub use crate::plugins::*;
}