#![no_main]
#![allow(unused_must_use)] // workaround for "error: unused `Result` that must be used"

use adblock::lists::{parse_filter, FilterFormat, ParseOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  if let Ok(filter) = ::str::from_utf8(data) {
    parse_filter(
      filter,
      true,
      ParseOptions {
        format: FilterFormat::Hosts,
        ..Default::default()
      },
    );
  }
});
