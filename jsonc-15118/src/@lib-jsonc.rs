#![doc(
    html_logo_url = "https://iot.bzh/images/defaults/company/512-479-max-transp.png",
    html_favicon_url = "https://iot.bzh/images/defaults/favicon.ico"
)]

#[cfg(not(afbv4))]
extern crate afbv4;

use afbv4::prelude::*;

use iso15118::prelude::PkiConfig;
pub trait IsoToJson {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError>;
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError>;
    fn from_jsonc_and_pki(
        jsonc: JsoncObj,
        pki_conf: &'static PkiConfig,
    ) -> Result<Box<Self>, AfbError> {
        Self::from_jsonc(jsonc)
    }
}

pub struct ApiMsgInfo {
    pub uid: &'static str,
    pub name: &'static str,
    pub info: &'static str,
    pub msg_id: u32,
    pub signed: bool,
    pub sample: Option<&'static str>,
}

#[path = "sdp-jsonc/encoders-lib.rs"]
pub mod sdp_jsonc;

#[path = "din-jsonc/encoders-lib.rs"]
pub mod din_jsonc;

#[path = "iso2-jsonc/encoders-lib.rs"]
pub mod iso2_jsonc;

pub mod prelude {
    pub use crate::din_jsonc::din_jsonc;
    pub use crate::iso2_jsonc::iso2_jsonc;
    pub use crate::sdp_jsonc::sdp_jsonc;
    pub use crate::{ApiMsgInfo, IsoToJson};
}
