use adblock::request::Request;
use adblock::Engine;

use serde::Deserialize;
use tokio::runtime::Runtime;

use std::fs::File;
use std::io::BufReader;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct RequestRuleMatch {
  url: String,
  sourceUrl: String,
  r#type: String,
  blocked: bool,
}

fn load_requests() -> Vec<RequestRuleMatch> {
  let f = File::open("data/regressions.tsv").expect("file not found");
  let reader = BufReader::new(f);
  let mut rdr = csv::ReaderBuilder::new()
    .delimiter(b'\t')
    .from_reader(reader);

  let mut reqs: Vec<RequestRuleMatch> = Vec::new();
  for result in rdr.deserialize() {
    if result.is_ok() {
      let record: RequestRuleMatch = result.unwrap();
      reqs.push(RequestRuleMatch {
        url: record.url.trim_matches('"').to_owned(),
        sourceUrl: record.sourceUrl.trim_matches('"').to_owned(),
        r#type: record.r#type.trim_matches('"').to_owned(),
        blocked: record.blocked,
      });
    } else {
      println!("Could not parse {:?}", result);
    }
  }

  reqs
}

/// Describes an entry from Brave's catalog of adblock lists.
/// https://github.com/brave/adblock-resources#filter-list-description-format
#[derive(serde::Deserialize, Debug)]
pub struct RemoteFilterCatalogEntry {
  pub title: String,
  pub sources: Vec<RemoteFilterSource>,
}

/// Describes an online source of adblock rules. Corresponds to a single entry of `sources` as
/// defined [here](https://github.com/brave/adblock-resources#filter-list-description-format).
#[derive(serde::Deserialize, Debug)]
pub struct RemoteFilterSource {
  pub url: String,
  pub title: Option<String>,
  pub format: adblock::lists::FilterFormat,
  pub support_url: String,
}

/// Fetch all filters once and store them in a lazy-loaded static variable to avoid unnecessary
/// network traffic.
static ALL_FILTERS: once_cell::sync::Lazy<std::sync::Mutex<adblock::lists::FilterSet>> =
  once_cell::sync::Lazy::new(|| {
    async fn get_all_filters() -> adblock::lists::FilterSet {
      use futures::FutureExt;

      const DEFAULT_LISTS_URL: &str = "https://raw.githubusercontent.com/brave/adblock-resources/master/filter_lists/list_catalog.json";

      println!(
        "Downloading list of filter lists from '{}'",
        DEFAULT_LISTS_URL
      );
      let default_catalog: Vec<RemoteFilterCatalogEntry> = async {
        let body = reqwest::get(DEFAULT_LISTS_URL)
          .await
          .unwrap()
          .text()
          .await
          .unwrap();
        serde_json::from_str(&body).unwrap()
      }
      .await;

      // 0th entry is the main default lists
      let default_lists = &default_catalog[0].sources;

      assert!(default_lists.len() > 10); // sanity check

      let filters_fut: Vec<_> = default_lists
            .iter()
            .map(|list| {
                println!("Starting download of filter, '{}'", list.url);
                reqwest::get(&list.url)
                    .then(move |resp| {
                        let response = resp.expect("Could not request rules");
                        if response.status() != 200 {
                            panic!("Failed download of filter, '{}'. Received status code {} when only 200 was expected", list.url.clone(), response.status());
                        }
                        response.text()
                    }).map(move |text| {
                        let text = text.expect("Could not get rules as text");
                        println!("Finished download of filter, '{}' ({} bytes)", list.url, text.len());
                        ( list.format, text )
                    })
            })
            .collect();

      let mut filter_set = adblock::lists::FilterSet::default();

      futures::future::join_all(filters_fut)
        .await
        .iter()
        .for_each(|(format, list)| {
          filter_set.add_filters(
            list.lines().map(|s| s.to_owned()).collect::<Vec<_>>(),
            adblock::lists::ParseOptions {
              format: *format,
              ..Default::default()
            },
          );
        });

      filter_set
    }

    let async_runtime = Runtime::new().expect("Could not start Tokio runtime");
    std::sync::Mutex::new(async_runtime.block_on(get_all_filters()))
  });

/// Example usage of this test:
///
/// cargo watch --clear -x "test --all-features --test live -- --show-output --nocapture --include-ignored 'troubleshoot'"
#[test]
#[ignore = "opt-in: used for troubleshooting issues with live tests"]
fn troubleshoot() {
  println!("Troubleshooting initiated. Safe journeys. ⛵");
  let _grabbed = ALL_FILTERS.lock().unwrap();
  println!("Troubleshooting complete. Welcome back! 🥳");
}

fn get_blocker_engine() -> Engine {
  let mut engine = Engine::from_filter_set(ALL_FILTERS.lock().unwrap().clone(), true);

  engine.use_tags(&["fb-embeds", "twitter-embeds"]);

  engine
}

fn get_blocker_engine_deserialized() -> Engine {
  use futures::FutureExt;
  let async_runtime = Runtime::new().expect("Could not start Tokio runtime");

  let brave_service_key = std::env::var("BRAVE_SERVICE_KEY")
    .expect("Must set the $BRAVE_SERVICE_KEY environment variable to execute live tests.");

  let dat_url = "https://adblock-data.s3.brave.com/ios/latest.dat";
  let download_client = reqwest::Client::new();
  let resp_bytes_fut = download_client
    .get(dat_url)
    .header("BraveServiceKey", brave_service_key)
    .send()
    .map(|e| e.expect("Could not request rules"))
    .then(|resp| {
      assert_eq!(
        resp.status(),
        200,
        "Downloading live DAT failed. Is the service key correct?"
      );
      resp.bytes()
    });
  let dat = async_runtime
    .block_on(resp_bytes_fut)
    .expect("Could not get response as bytes");

  let mut engine = Engine::default();
  engine.deserialize(&dat).expect("Deserialization failed");
  engine.use_tags(&["fb-embeds", "twitter-embeds"]);
  engine
}

#[test]
fn check_live_specific_urls() {
  let mut engine = get_blocker_engine();
  {
    let checked = engine.check_network_request(
      &Request::new(
        "https://static.scroll.com/js/scroll.js",
        "https://www.theverge.com/",
        "script",
      )
      .unwrap(),
    );
    assert!(
      !checked.matched,
      "Expected match, got filter {:?}, exception {:?}",
      checked.filter, checked.exception
    );
  }
  {
    engine.disable_tags(&["twitter-embeds"]);
    let checked = engine.check_network_request(
      &Request::new(
        "https://platform.twitter.com/widgets.js",
        "https://fmarier.github.io/brave-testing/social-widgets.html",
        "script",
      )
      .unwrap(),
    );
    assert!(
      checked.matched,
      "Expected no match, got filter {:?}, exception {:?}",
      checked.filter, checked.exception
    );
    engine.enable_tags(&["twitter-embeds"]);
  }
  {
    engine.disable_tags(&["twitter-embeds"]);
    let checked = engine.check_network_request(&Request::new(
            "https://imagesrv.adition.com/banners/1337/files/00/0e/6f/09/000000945929.jpg?PQgSgs13hf1fw.jpg",
            "https://spiegel.de",
            "image",
        ).unwrap());
    assert!(
      checked.matched,
      "Expected match, got filter {:?}, exception {:?}",
      checked.filter, checked.exception
    );
    engine.enable_tags(&["twitter-embeds"]);
  }
}

#[test]
#[ignore = "opt-in: requires BRAVE_SERVICE_KEY environment variable"]
fn check_live_brave_deserialized_specific_urls() {
  // Note: CI relies on part of this function's name
  let mut engine = get_blocker_engine_deserialized();
  {
    engine.disable_tags(&["twitter-embeds"]);
    let checked = engine.check_network_request(
      &Request::new(
        "https://platform.twitter.com/widgets.js",
        "https://fmarier.github.io/brave-testing/social-widgets.html",
        "script",
      )
      .unwrap(),
    );
    assert!(
      checked.matched,
      "Expected match, got filter {:?}, exception {:?}",
      checked.filter, checked.exception
    );
  }
  {
    engine.enable_tags(&["twitter-embeds"]);
    let checked = engine.check_network_request(
      &Request::new(
        "https://platform.twitter.com/widgets.js",
        "https://fmarier.github.io/brave-testing/social-widgets.html",
        "script",
      )
      .unwrap(),
    );
    assert!(
      !checked.matched,
      "Expected no match, got filter {:?}, exception {:?}",
      checked.filter, checked.exception
    );
  }
}

#[test]
fn check_live_from_filterlists() {
  let engine = get_blocker_engine();
  let requests = load_requests();

  for req in requests {
    let checked =
      engine.check_network_request(&Request::new(&req.url, &req.sourceUrl, &req.r#type).unwrap());
    assert_eq!(
      checked.matched, req.blocked,
      "Expected match {} for {} at {}, got filter {:?}, exception {:?}",
      req.blocked, req.url, req.sourceUrl, checked.filter, checked.exception
    );
  }
}

#[test]
#[ignore = "opt-in: requires BRAVE_SERVICE_KEY environment variable"]
fn check_live_brave_deserialized_file() {
  // Note: CI relies on part of this function's name
  let engine = get_blocker_engine_deserialized();
  let requests = load_requests();

  for req in requests {
    println!("Checking {:?}", req);
    let checked =
      engine.check_network_request(&Request::new(&req.url, &req.sourceUrl, &req.r#type).unwrap());
    assert_eq!(
      checked.matched, req.blocked,
      "Expected match {} for {} {} {}",
      req.blocked, req.url, req.sourceUrl, req.r#type
    );
  }
}

#[test]
/// Ensure that two different engines loaded from the same textual filter set serialize to
/// identical buffers.
fn stable_serialization() {
  let engine1 = Engine::from_filter_set(ALL_FILTERS.lock().unwrap().clone(), true);
  let ser1 = engine1.serialize_raw().unwrap();

  let engine2 = Engine::from_filter_set(ALL_FILTERS.lock().unwrap().clone(), true);
  let ser2 = engine2.serialize_raw().unwrap();

  assert_eq!(ser1, ser2);
}

#[test]
/// Ensure that one engine's serialization result can be exactly reproduced by another engine after
/// deserializing from it.
fn stable_serialization_through_load() {
  let engine1 = Engine::from_filter_set(ALL_FILTERS.lock().unwrap().clone(), true);
  let ser1 = engine1.serialize_raw().unwrap();

  let mut engine2 = Engine::new(true);
  engine2.deserialize(&ser1).unwrap();
  let ser2 = engine2.serialize_raw().unwrap();

  assert_eq!(ser1, ser2);
}
