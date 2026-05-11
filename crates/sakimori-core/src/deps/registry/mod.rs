pub mod crates;
pub mod npm;
pub mod nuget;
pub mod pypi;

use std::time::Duration;

pub(crate) fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(15))
        .build()
}
