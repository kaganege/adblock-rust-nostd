//! Compiled regexes can take up large amounts of memory. To reduce the overall memory footprint of
//! the [`crate::Engine`], infrequently used regexes can be discarded. The [`RegexManager`] is
//! responsible for managing the storage of regexes used by filters.

use crate::filters::network::{compile_regex, CompiledRegex, NetworkFilter};
#[cfg(feature = "regex-debug-info")]
use crate::prelude::*;

use hashbrown::HashMap;

/// `*const NetworkFilter` could technically leak across threads through `RegexDebugEntry::id`, but
/// it's disguised as a unique identifier and not intended to be dereferenced.
unsafe impl Send for RegexManager {}

// We can't cleanup regexes in no_std environments.
// const DEFAULT_CLEAN_UP_INTERVAL: Duration = Duration::from_secs(30);
// const DEFAULT_DISCARD_UNUSED_TIME: Duration = Duration::from_secs(180);

/// Reports [`RegexManager`] metrics that may be useful for creating an optimized
/// [`RegexManagerDiscardPolicy`].
#[cfg(feature = "regex-debug-info")]
pub struct RegexDebugInfo {
  /// Information about each regex contained in the [`RegexManager`].
  pub regex_data: Vec<RegexDebugEntry>,
  /// Total count of compiled regexes.
  pub compiled_regex_count: usize,
}

/// Describes metrics about a single regex from the [`RegexManager`].
#[cfg(feature = "regex-debug-info")]
pub struct RegexDebugEntry {
  /// Id for this particular regex, which is constant and unique for its lifetime.
  ///
  /// Note that there are no guarantees about a particular id's constancy or uniqueness beyond
  /// the lifetime of a corresponding regex.
  pub id: u64,
  /// A string representation of this regex, if available. It may be `None` if the regex has been
  /// cleaned up to conserve memory.
  pub regex: Option<String>,
  /// How many times this regex has been used.
  pub usage_count: usize,
}

struct RegexEntry {
  regex: Option<CompiledRegex>,
  usage_count: usize,
}

type RandomState = core::hash::BuildHasherDefault<seahash::SeaHasher>;

/// A manager that creates and stores all regular expressions used by filters.
/// Rarely used entries are discarded to save memory.
///
/// The [`RegexManager`] is not thread safe, so any access to it must be
/// synchronized externally.
#[derive(Default)]
pub struct RegexManager {
  map: HashMap<*const NetworkFilter, RegexEntry, RandomState>,
  compiled_regex_count: usize,
}

fn make_regexp(filter: &NetworkFilter) -> CompiledRegex {
  compile_regex(
    &filter.filter,
    filter.is_right_anchor(),
    filter.is_left_anchor(),
    filter.is_complete_regex(),
  )
}

impl RegexManager {
  /// Check whether or not a regex network filter matches a certain URL pattern, using the
  /// [`RegexManager`]'s managed regex storage.
  pub fn matches(&mut self, filter: &NetworkFilter, pattern: &str) -> bool {
    if !filter.is_regex() && !filter.is_complete_regex() {
      return true;
    }
    let key = filter as *const NetworkFilter;
    use hashbrown::hash_map::Entry;
    match self.map.entry(key) {
      Entry::Occupied(mut e) => {
        let v = e.get_mut();
        v.usage_count += 1;
        if v.regex.is_none() {
          // A discarded entry, recreate it:
          v.regex = Some(make_regexp(filter));
          self.compiled_regex_count += 1;
        }
        return v.regex.as_ref().unwrap().is_match(pattern);
      }
      Entry::Vacant(e) => {
        self.compiled_regex_count += 1;
        let new_entry = RegexEntry {
          regex: Some(make_regexp(filter)),
          usage_count: 1,
        };
        return e
          .insert(new_entry)
          .regex
          .as_ref()
          .unwrap()
          .is_match(pattern);
      }
    };
  }

  // /// The [`RegexManager`] is just a struct and doesn't manage any worker threads, so this method
  // /// must be called periodically to ensure that it can track usage patterns of regexes over
  // /// time. This method will handle periodically discarding filters if necessary.
  // #[cfg(not(target_arch = "wasm32"))]
  // pub fn update_time(&mut self) {
  //   self.now = Instant::now();
  //   if !self.discard_policy.cleanup_interval.is_zero()
  //     && self.now - self.last_cleanup >= self.discard_policy.cleanup_interval
  //   {
  //     self.last_cleanup = self.now;
  //     self.cleanup();
  //   }
  // }

  // #[cfg(not(target_arch = "wasm32"))]
  // pub(crate) fn cleanup(&mut self) {
  //   let now = self.now;
  //   for v in self.map.values_mut() {
  //     if now - v.last_used >= self.discard_policy.discard_unused_time {
  //       // Discard the regex to save memory.
  //       v.regex = None;
  //     }
  //   }
  // }

  /// Discard one regex, identified by its id from a [`RegexDebugEntry`].
  #[cfg(feature = "regex-debug-info")]
  pub fn discard_regex(&mut self, regex_id: u64) {
    self
      .map
      .iter_mut()
      .filter(|(k, _)| **k as u64 == regex_id)
      .for_each(|(_, v)| {
        v.regex = None;
      });
  }

  #[cfg(feature = "regex-debug-info")]
  pub(crate) fn get_debug_regex_data(&self) -> Vec<RegexDebugEntry> {
    use itertools::Itertools;
    self
      .map
      .iter()
      .map(|(k, e)| RegexDebugEntry {
        id: *k as u64,
        regex: e.regex.as_ref().map(|x| x.to_string()),
        usage_count: e.usage_count,
      })
      .collect_vec()
  }

  #[cfg(feature = "regex-debug-info")]
  pub(crate) fn get_compiled_regex_count(&self) -> usize {
    self.compiled_regex_count
  }

  /// Collect metrics that may be useful for creating an optimized [`RegexManagerDiscardPolicy`].
  #[cfg(feature = "regex-debug-info")]
  pub fn get_debug_info(&self) -> RegexDebugInfo {
    RegexDebugInfo {
      regex_data: self.get_debug_regex_data(),
      compiled_regex_count: self.get_compiled_regex_count(),
    }
  }
}

#[cfg(all(test, feature = "regex-debug-info"))]
mod tests {
  use super::*;

  use crate::filters::network::NetworkMatchable;
  use crate::request;

  fn make_filter(line: &str) -> NetworkFilter {
    NetworkFilter::parse(line, true, Default::default()).unwrap()
  }

  fn make_request(url: &str) -> request::Request {
    request::Request::new(url, "https://example.com", "other").unwrap()
  }

  fn get_active_regex_count(regex_manager: &RegexManager) -> usize {
    regex_manager
      .get_debug_regex_data()
      .iter()
      .filter(|x| x.regex.is_some())
      .count()
  }

  #[test]
  fn simple_match() {
    let mut regex_manager = RegexManager::default();

    let filter = make_filter("||geo*.hltv.org^");
    assert!(filter.matches(&make_request("https://geo2.hltv.org/"), &mut regex_manager));
    assert_eq!(get_active_regex_count(&regex_manager), 1);
    assert_eq!(regex_manager.get_debug_regex_data().len(), 1);
  }

  #[test]
  fn discard_and_recreate() {
    let mut regex_manager = RegexManager::default();

    let filter = make_filter("||geo*.hltv.org^");
    assert!(filter.matches(&make_request("https://geo2.hltv.org/"), &mut regex_manager));
    assert_eq!(regex_manager.get_compiled_regex_count(), 1);
    assert_eq!(get_active_regex_count(&regex_manager), 1);

    let regex_id = regex_manager.get_debug_regex_data()[0].id;
    regex_manager.discard_regex(regex_id);
    assert_eq!(get_active_regex_count(&regex_manager), 0);

    // The entry is recreated, get_compiled_regex_count() increased +1.
    assert!(filter.matches(&make_request("https://geo2.hltv.org/"), &mut regex_manager));
    assert_eq!(regex_manager.get_compiled_regex_count(), 2);
    assert_eq!(get_active_regex_count(&regex_manager), 1);
  }
}
