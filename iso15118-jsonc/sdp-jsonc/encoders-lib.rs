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

#[path = "sub-types.rs"]
mod sub_types;

pub mod sdp_jsonc {
    pub use super::sub_types::*;
}