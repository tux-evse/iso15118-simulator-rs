#![doc(
    html_logo_url = "https://iot.bzh/images/defaults/company/512-479-max-transp.png",
    html_favicon_url = "https://iot.bzh/images/defaults/favicon.ico"
)]

#[cfg(not(afbv4))]
extern crate afbv4;

#[path = "iso2-jsonc/encoders-lib.rs"]
mod iso2_jsonc;

pub mod prelude {
    pub use crate::iso2_jsonc::prelude::*;
}