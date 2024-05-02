/*
 * Copyright (C) 2015-2022 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#![doc(
    html_logo_url = "https://iot.bzh/images/defaults/company/512-479-max-transp.png",
    html_favicon_url = "https://iot.bzh/images/defaults/favicon.ico"
)]

#[cfg(not(afbv4))]
extern crate afbv4;

#[path = "verbs.rs"]
mod verbs;

#[path = "binding.rs"]
mod binding;

#[path = "controller.rs"]
mod ctrl;

#[path = "body-encoder.rs"]
mod body_encoder;

#[path = "json-encoders/sub-types.rs"]
mod sub_types;

#[path = "json-encoders/session-setup.rs"]
mod session_setup;

#[path = "json-encoders/service-discovery.rs"]
mod service_discovery;

#[path = "json-encoders/service-detail.rs"]
mod service_detail;

#[path = "json-encoders/authorization.rs"]
mod authorization;

#[path = "json-encoders/cable-check.rs"]
mod cable_check;

#[path ="json-encoders/certificate-install.rs"]
mod certificate_install ;

#[path = "json-encoders/certificate-update.rs"]
mod certificate_update;

#[path = "json-encoders/charging-status.rs"]
mod charging_status;

#[path = "json-encoders/current-demand.rs"]
mod current_demand;

#[path = "json-encoders/metering-receipt.rs"]
mod metering_receipt;

#[path = "json-encoders/param-discovery.rs"]
mod param_discovery;

#[path = "json-encoders/payment-details.rs"]
mod payment_details;

#[path = "json-encoders/payment-selection.rs"]
mod payment_selection;

#[path = "json-encoders/power-delivery.rs"]
mod power_delivery;

#[path = "json-encoders/pre-charge.rs"]
mod pre_charge;

#[path = "json-encoders/session-stop.rs"]
mod session_stop;

#[path = "json-encoders/welding-detection.rs"]
mod welding_detection;


pub(crate) mod prelude {
    pub use crate::binding::*;
    pub use crate::verbs::*;
    pub use crate::ctrl::*;
    pub use crate::sub_types::*;
    pub use crate::authorization::*;
    pub use crate::cable_check::*;
    pub use super::certificate_install::*;
    pub use super::certificate_update::*;
    pub use super::charging_status::*;
    pub use super::current_demand::*;
    pub use super::metering_receipt::*;
    pub use super::param_discovery::*;
    pub use super::payment_details::*;
    pub use super::payment_selection::*;
    pub use super::power_delivery::*;
    pub use super::pre_charge::*;
    pub use super::service_detail::*;
    pub use super::service_discovery::*;
    pub use super::session_setup::*;
    pub use super::session_stop::*;
    pub use super::welding_detection::*;
    pub use super::body_encoder::*;

}