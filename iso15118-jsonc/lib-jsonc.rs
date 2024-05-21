#![doc(
    html_logo_url = "https://iot.bzh/images/defaults/company/512-479-max-transp.png",
    html_favicon_url = "https://iot.bzh/images/defaults/favicon.ico"
)]

#[cfg(not(afbv4))]
extern crate afbv4;

use afbv4::prelude::*;
pub trait IsoToJson {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError>;
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError>;
}

#[path = "din-jsonc/encoders-lib.rs"]
pub mod din_jsonc;

#[path = "iso2-jsonc/encoders-lib.rs"]
pub mod iso2_jsonc;

pub mod prelude {
    pub use crate::IsoToJson;
    pub use crate::din_jsonc::din_jsonc;
    pub use crate::iso2_jsonc::iso2_jsonc;
}