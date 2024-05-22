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

use afbv4::prelude::*;
use crate::prelude::*;
use iso15118::prelude::v2g::SupportedAppProtocolConf;

impl IsoToJson for SupportedAppProtocolConf {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("name", self.get_name())?;
        jsonc.add("schema", self.get_schema().to_label())?;
        jsonc.add("major", self.get_major())?;
        jsonc.add("minor", self.get_minor())?;
        Ok(jsonc)
    }
    fn from_jsonc(_jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        return afb_error!("supported-app-protocol-conf", "from_jsonc not implemented");
    }
}
