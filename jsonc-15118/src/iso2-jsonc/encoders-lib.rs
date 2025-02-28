/*
 * Copyright (C) 2015-2024 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */


#[cfg(not(afbv4))]
extern crate afbv4;

#[path = "body-encoder.rs"]
mod body_encoder;

#[path = "sub-types.rs"]
mod sub_types;

#[path = "session-setup.rs"]
mod session_setup;

#[path = "service-discovery.rs"]
mod service_discovery;

#[path = "service-detail.rs"]
mod service_detail;

#[path = "authorization.rs"]
mod authorization;

#[path = "cable-check.rs"]
mod cable_check;

#[path = "certificate-install.rs"]
mod certificate_install;

#[path = "certificate-update.rs"]
mod certificate_update;

#[path = "charging-status.rs"]
mod charging_status;

#[path = "current-demand.rs"]
mod current_demand;

#[path = "metering-receipt.rs"]
mod metering_receipt;

#[path = "param-discovery.rs"]
mod param_discovery;

#[path = "payment-details.rs"]
mod payment_details;

#[path = "payment-selection.rs"]
mod payment_selection;

#[path = "power-delivery.rs"]
mod power_delivery;

#[path = "pre-charge.rs"]
mod pre_charge;

#[path = "session-stop.rs"]
mod session_stop;

#[path = "welding-detection.rs"]
mod welding_detection;

#[cfg(test)]
#[path = "encoders-test.rs"]
pub mod encoders_test;

pub mod iso2_jsonc {
    pub use super::sub_types::*;
    pub use super::authorization::*;
    pub use super::cable_check::*;
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