use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

use crate::amount::{AssetAmount, CcAmount, NATIVE_MAX_UNITS};
use crate::asset::{AssetId, known_cc_assets};
use crate::error::{WalletError, WalletResult};
use crate::strict::{ProfileSchemaV1, StrictError, StrictObject};

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8001/";
pub const DEFAULT_WORKCHAIN: i8 = -1;
pub const DEFAULT_NETWORK_ID: i32 = 0;
pub const TYCHO_TESTNET_ENDPOINT: &str = "https://rpc-testnet.tychoprotocol.com/";
pub const DEFAULT_AUTOSIGN_MINS: u8 = 5;
pub const DEFAULT_SCREEN_LOCK_MINS: u8 = 5;

pub const PROFILE_SCHEMA_VERSION: u32 = 1;

fn redacted(seed: &str) -> String {
    let words = seed.split_whitespace().count();
    if words == 0 {
        "<empty>".to_owned()
    } else {
        format!("<redacted {words} words>")
    }
}

pub struct SeedPhrase {
    value: Zeroizing<String>,
    #[cfg(test)]
    drop_probe: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl PartialEq for SeedPhrase {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for SeedPhrase {}

impl SeedPhrase {
    pub fn new(value: String) -> Self {
        Self {
            value: Zeroizing::new(value),
            #[cfg(test)]
            drop_probe: None,
        }
    }

    pub fn shared(value: String) -> Arc<Self> {
        Arc::new(Self::new(value))
    }

    pub fn from_zeroizing(mut value: Zeroizing<String>) -> Self {
        Self::new(std::mem::take(&mut *value))
    }

    pub fn shared_zeroizing(value: Zeroizing<String>) -> Arc<Self> {
        Arc::new(Self::from_zeroizing(value))
    }

    pub fn empty_shared() -> Arc<Self> {
        Self::shared(String::new())
    }

    pub fn expose_secret(&self) -> &str {
        self.value.as_str()
    }

    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut *self.value))
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    #[cfg(test)]
    fn with_drop_probe(value: String, probe: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self {
            value: Zeroizing::new(value),
            drop_probe: Some(probe),
        }
    }
}

impl Drop for SeedPhrase {
    fn drop(&mut self) {
        self.value.zeroize();
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            probe.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl Deref for SeedPhrase {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.expose_secret()
    }
}

impl fmt::Debug for SeedPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SeedPhrase")
            .field(&redacted(self.expose_secret()))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookEntry {
    pub name: String,
    pub address: String,
    pub tag: String,
}

impl AddressBookEntry {
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            tag: String::new(),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct WalletProfile {
    pub network_id: i32,
    pub workchain: i8,
    pub seed: Arc<SeedPhrase>,
    pub visible_cc_assets: BTreeSet<u32>,
    pub address_book: Vec<AddressBookEntry>,
    pub autosign_mins: u8,
    pub screen_lock_mins: u8,
    pub custom_endpoints: Vec<String>,
    pub selected_endpoint: usize,
}

#[derive(Serialize)]
struct WalletProfileWire<'a> {
    schema_version: u32,
    network_id: i32,
    workchain: i8,
    seed: &'a str,
    visible_cc_assets: &'a BTreeSet<u32>,
    address_book: &'a [AddressBookEntry],
    autosign_mins: u8,
    screen_lock_mins: u8,
    custom_endpoints: &'a [String],
    selected_endpoint: usize,
}

impl Serialize for WalletProfile {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WalletProfileWire {
            schema_version: PROFILE_SCHEMA_VERSION,
            network_id: self.network_id,
            workchain: self.workchain,
            seed: self.seed.expose_secret(),
            visible_cc_assets: &self.visible_cc_assets,
            address_book: &self.address_book,
            autosign_mins: self.autosign_mins,
            screen_lock_mins: self.screen_lock_mins,
            custom_endpoints: &self.custom_endpoints,
            selected_endpoint: self.selected_endpoint,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WalletProfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <&RawValue>::deserialize(deserializer)?;
        Self::decode(raw.get().as_bytes()).map_err(de::Error::custom)
    }
}

impl WalletProfile {
    pub fn decode(bytes: &[u8]) -> Result<Self, StrictError> {
        let mut content = StrictObject::parse(bytes)?
            .require_schema::<ProfileSchemaV1>()?
            .into_profile_content();
        let seed = content.take_required_zeroizing_string("seed")?;
        let profile = Self {
            network_id: content.take_required("network_id")?,
            workchain: content.take_required("workchain")?,
            seed: SeedPhrase::shared_zeroizing(seed),
            visible_cc_assets: content.take_required("visible_cc_assets")?,
            address_book: content.take_required("address_book")?,
            autosign_mins: content.take_required("autosign_mins")?,
            screen_lock_mins: content.take_required("screen_lock_mins")?,
            custom_endpoints: content.take_required("custom_endpoints")?,
            selected_endpoint: content.take_required("selected_endpoint")?,
        };
        content.finish()?;
        Ok(profile)
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut writer = ZeroizingBuffer::with_capacity(1024);
        serde_json::to_writer(&mut writer, self).expect("a WalletProfile always serializes");
        writer.into_inner()
    }
}

struct ZeroizingBuffer {
    buf: Zeroizing<Vec<u8>>,
}

impl ZeroizingBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(capacity)),
        }
    }

    fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

impl std::io::Write for ZeroizingBuffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let needed = self.buf.len() + data.len();
        if needed > self.buf.capacity() {
            let new_capacity = needed.next_power_of_two().max(1024);
            let mut next = Zeroizing::new(Vec::with_capacity(new_capacity));
            next.extend_from_slice(&self.buf);
            self.buf = next;
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Default for WalletProfile {
    fn default() -> Self {
        Self {
            network_id: DEFAULT_NETWORK_ID,
            workchain: DEFAULT_WORKCHAIN,
            seed: SeedPhrase::empty_shared(),
            visible_cc_assets: BTreeSet::new(),
            address_book: Vec::new(),
            autosign_mins: DEFAULT_AUTOSIGN_MINS,
            screen_lock_mins: DEFAULT_SCREEN_LOCK_MINS,
            custom_endpoints: Vec::new(),
            selected_endpoint: 0,
        }
    }
}

impl fmt::Debug for WalletProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletProfile")
            .field("schema_version", &PROFILE_SCHEMA_VERSION)
            .field("network_id", &self.network_id)
            .field("workchain", &self.workchain)
            .field("seed", &redacted(self.seed.expose_secret()))
            .field("visible_cc_assets", &self.visible_cc_assets)
            .field("address_book", &self.address_book)
            .field("autosign_mins", &self.autosign_mins)
            .field("screen_lock_mins", &self.screen_lock_mins)
            .field("custom_endpoint_count", &self.custom_endpoints.len())
            .field("selected_endpoint", &self.selected_endpoint)
            .finish()
    }
}

impl WalletProfile {
    pub fn normalized(mut self) -> Self {
        let normalized_seed = Zeroizing::new(normalize_seed(self.seed.expose_secret()));
        if normalized_seed.as_str() != self.seed.expose_secret() {
            self.seed = SeedPhrase::shared_zeroizing(normalized_seed);
        }
        self.visible_cc_assets.retain(|id| {
            known_cc_assets()
                .iter()
                .any(|asset| asset.id.cc_id() == Some(*id))
        });
        self.address_book = self
            .address_book
            .into_iter()
            .filter_map(|entry| {
                let name = entry.name.trim().to_owned();
                let address = entry.address.trim().to_owned();
                if name.is_empty() || address.is_empty() {
                    None
                } else {
                    Some(AddressBookEntry {
                        tag: entry.tag.trim().to_owned(),
                        name,
                        address,
                    })
                }
            })
            .collect();
        let selected_url: Option<String> = (self.selected_endpoint > 0)
            .then(|| {
                self.custom_endpoints
                    .get(self.selected_endpoint - 1)
                    .map(|u| u.trim().to_owned())
            })
            .flatten()
            .filter(|u| !u.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        self.custom_endpoints = self
            .custom_endpoints
            .into_iter()
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty() && seen.insert(url.clone()))
            .collect();
        self.selected_endpoint = match selected_url {
            None => 0,
            Some(url) => self
                .custom_endpoints
                .iter()
                .position(|u| *u == url)
                .map(|p| p + 1)
                .unwrap_or(0),
        };
        self
    }

    pub fn wallet_inputs(
        &self,
        endpoint: String,
        require_signature_id: bool,
    ) -> WalletResult<WalletInputs> {
        validate_seed(self.seed.expose_secret())?;
        validate_workchain(self.workchain)?;
        Ok(WalletInputs {
            endpoint,
            network_id: self.network_id,
            workchain: self.workchain,
            seed: Arc::clone(&self.seed),
            require_signature_id,
        })
    }
}

#[derive(PartialEq, Eq)]
pub struct WalletInputs {
    pub endpoint: String,
    pub network_id: i32,
    pub workchain: i8,
    pub seed: Arc<SeedPhrase>,
    pub require_signature_id: bool,
}

impl fmt::Debug for WalletInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletInputs")
            .field("endpoint", &"<redacted endpoint identity>")
            .field("network_id", &self.network_id)
            .field("workchain", &self.workchain)
            .field("seed", &redacted(self.seed.expose_secret()))
            .field("require_signature_id", &self.require_signature_id)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EndpointAddressInputs {
    endpoint: String,
    address: String,
}

impl EndpointAddressInputs {
    pub fn new(endpoint: String, address: String) -> WalletResult<Self> {
        if endpoint.is_empty() || endpoint.trim() != endpoint {
            return Err(WalletError::validation(
                "endpoint/address inputs require a nonempty canonical endpoint",
            ));
        }
        let address = crate::address::canonicalize_recipient(&address)?;
        Ok(Self { endpoint, address })
    }
}

accessors!(EndpointAddressInputs {
    endpoint: ref str,
    address: ref str
});

impl fmt::Debug for EndpointAddressInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointAddressInputs")
            .field("endpoint", &"<redacted endpoint identity>")
            .field("address", &self.address)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObservedNetworkTime {
    value: u32,
    source_endpoint: String,
    request_id: String,
    observed_at_mono: Instant,
}

impl fmt::Debug for ObservedNetworkTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedNetworkTime")
            .field("value", &self.value)
            .field("source_endpoint", &"<redacted endpoint identity>")
            .field("request_id", &self.request_id)
            .field("observed_at_mono", &self.observed_at_mono)
            .finish()
    }
}

impl ObservedNetworkTime {
    pub fn new(
        value: u32,
        source_endpoint: impl Into<String>,
        request_id: impl Into<String>,
        observed_at_mono: Instant,
    ) -> WalletResult<Self> {
        let source_endpoint = source_endpoint.into();
        let request_id = request_id.into();
        if source_endpoint.trim() != source_endpoint
            || source_endpoint.is_empty()
            || request_id.trim() != request_id
            || request_id.is_empty()
        {
            return Err(WalletError::validation(
                "network-time source and request id must be nonempty canonical strings",
            ));
        }
        Ok(Self {
            value,
            source_endpoint,
            request_id,
            observed_at_mono,
        })
    }
}

accessors!(ObservedNetworkTime {
    value: copy u32,
    source_endpoint: ref str,
    request_id: ref str,
    observed_at_mono: copy Instant
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSnapshot {
    pub address: String,
    pub global_id: i32,
    pub status: String,
    native_balance: u128,
    extra_balance: BTreeMap<u32, CcAmount>,
    pub last_trans_lt: u64,
    last_message_ms: u64,
    observed_network_time: Option<ObservedNetworkTime>,
}

impl WalletSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: impl Into<String>,
        global_id: i32,
        status: impl Into<String>,
        native_balance: u128,
        extra_balance: BTreeMap<u32, CcAmount>,
        last_trans_lt: u64,
    ) -> WalletResult<Self> {
        Self::new_with_network_time(
            address,
            global_id,
            status,
            native_balance,
            extra_balance,
            last_trans_lt,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_network_time(
        address: impl Into<String>,
        global_id: i32,
        status: impl Into<String>,
        native_balance: u128,
        extra_balance: BTreeMap<u32, CcAmount>,
        last_trans_lt: u64,
        observed_network_time: Option<ObservedNetworkTime>,
    ) -> WalletResult<Self> {
        if native_balance > NATIVE_MAX_UNITS {
            return Err(WalletError::amount(
                "native snapshot balance exceeds the protocol maximum",
            ));
        }
        Ok(Self {
            address: address.into(),
            global_id,
            status: status.into(),
            native_balance,
            extra_balance,
            last_trans_lt,
            last_message_ms: 0,
            observed_network_time,
        })
    }

    #[must_use]
    pub fn with_last_message_ms(mut self, last_message_ms: u64) -> Self {
        self.last_message_ms = last_message_ms;
        self
    }

    pub fn empty(address: impl Into<String>) -> Self {
        Self::new(address, 0, "Unknown", 0, BTreeMap::new(), 0)
            .expect("the empty snapshot is in-domain")
    }

    pub fn replace_balances(
        &mut self,
        native_balance: u128,
        extra_balance: BTreeMap<u32, CcAmount>,
    ) -> WalletResult<()> {
        if native_balance > NATIVE_MAX_UNITS {
            return Err(WalletError::amount(
                "native snapshot balance exceeds the protocol maximum",
            ));
        }
        self.native_balance = native_balance;
        self.extra_balance = extra_balance;
        Ok(())
    }

    pub fn balance_for(&self, asset: AssetId) -> AssetAmount {
        match asset {
            AssetId::Native => AssetAmount::native(self.native_balance)
                .expect("WalletSnapshot construction keeps native balance in-domain"),
            AssetId::CurrencyCollection(id) => AssetAmount::currency_collection(
                id,
                self.extra_balance
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(CcAmount::zero),
            ),
        }
    }
}

accessors!(WalletSnapshot {
    last_message_ms: copy u64,
    native_balance: copy u128,
    extra_balance: ref BTreeMap<u32, CcAmount>,
    observed_network_time: opt ObservedNetworkTime
});

pub fn normalize_seed(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn validate_seed(seed: &str) -> WalletResult<()> {
    let words = seed.split_whitespace().count();
    if words == 0 {
        return Err(WalletError::validation("seed is empty"));
    }
    if words < 12 {
        return Err(WalletError::validation(format!(
            "seed looks too short: {words} words"
        )));
    }
    Ok(())
}

pub fn validate_workchain(workchain: i8) -> WalletResult<()> {
    if matches!(workchain, 0 | -1) {
        Ok(())
    } else {
        Err(WalletError::validation("workchain must be 0 or -1"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn final_shared_seed_owner_runs_the_zeroizing_drop_path_once() {
        let probe = Arc::new(AtomicUsize::new(0));
        let phrase = Arc::new(SeedPhrase::with_drop_probe(
            "instrumented recovery phrase".to_owned(),
            Arc::clone(&probe),
        ));
        let second_owner = Arc::clone(&phrase);
        drop(phrase);
        assert_eq!(probe.load(Ordering::SeqCst), 0);
        drop(second_owner);
        assert_eq!(probe.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn normalizes_seed_whitespace() {
        assert_eq!(normalize_seed(" one\n two\tthree  "), "one two three");
    }

    #[test]
    fn validates_seed_word_count() {
        assert!(validate_seed("").is_err());
        assert!(validate_seed("one two three").is_err());
        assert!(
            validate_seed("one two three four five six seven eight nine ten eleven twelve").is_ok()
        );
    }

    #[test]
    fn validates_workchain() {
        assert!(validate_workchain(0).is_ok());
        assert!(validate_workchain(-1).is_ok());
        assert!(validate_workchain(1).is_err());
        assert!(validate_workchain(2).is_err());
    }

    fn current_profile_json() -> String {
        String::from_utf8(serde_json::to_vec(&WalletProfile::default()).unwrap()).unwrap()
    }

    #[test]
    fn a_legacy_or_older_profile_is_rejected_not_migrated() {
        let legacy_testnet = r#"{
            "endpoint": "https://rpc-testnet.tychoprotocol.com",
            "workchain": 0, "seed": "one two three", "global_id": 2000,
            "visible_cc_assets": [], "address_book": []
        }"#;
        assert!(
            serde_json::from_str::<WalletProfile>(legacy_testnet).is_err(),
            "a legacy endpoint/global_id profile must not migrate"
        );
        let legacy_local = r#"{"endpoint":"http://127.0.0.1:8001","workchain":-1,"seed":"s"}"#;
        assert!(serde_json::from_str::<WalletProfile>(legacy_local).is_err());
    }

    #[test]
    fn only_the_exact_current_schema_is_accepted() {
        let default_profile = WalletProfile::default();
        assert_eq!(default_profile.screen_lock_mins, 5);
        let bytes = serde_json::to_vec(&default_profile).unwrap();
        let current: WalletProfile = serde_json::from_slice(&bytes).unwrap();
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .contains("\"schema_version\":1")
        );
        assert_eq!(current, WalletProfile::default());

        assert!(
            serde_json::from_str::<WalletProfile>(r#"{"workchain":-1,"seed":"s"}"#).is_err(),
            "an unstamped (schema 0) profile is unsupported, not editable"
        );

        let newer = current_profile_json().replace(
            "\"schema_version\":1",
            &format!("\"schema_version\":{}", PROFILE_SCHEMA_VERSION + 1),
        );
        assert!(
            serde_json::from_str::<WalletProfile>(&newer).is_err(),
            "a newer-schema profile must be refused, not opened read-only"
        );
    }

    #[test]
    fn schema_is_classified_before_nested_fields_are_typed() {
        let older_with_bad_nested = r#"{"schema_version":0,"network_id":0,"workchain":-1,"seed":"s",
                "visible_cc_assets":[],"address_book":[{"name":"a"}],"autosign_mins":5,
                "screen_lock_mins":10,"custom_endpoints":[],"selected_endpoint":0}"#;
        let err = serde_json::from_str::<WalletProfile>(older_with_bad_nested)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("schema 0 is not a supported format"),
            "the schema error must win over the nested-record error, got: {err}"
        );
    }

    #[test]
    fn duplicate_profile_members_refuse_before_a_malformed_tail() {
        assert_eq!(
            WalletProfile::decode(br#"{"schema_version":1,"schema_version":1,"later":@}"#),
            Err(StrictError::DuplicateKey("schema_version".to_owned()))
        );
        assert_eq!(
            WalletProfile::decode(
                br#"{"schema_version":1,"network_id":0,"network_id":1,"later":@}"#
            ),
            Err(StrictError::DuplicateKey("network_id".to_owned()))
        );
    }

    #[test]
    fn a_current_schema_nested_record_rejects_missing_and_unknown_fields() {
        let missing_tag = current_profile_json().replace(
            "\"address_book\":[]",
            "\"address_book\":[{\"name\":\"a\",\"address\":\"0:b\"}]",
        );
        assert!(
            serde_json::from_str::<WalletProfile>(&missing_tag).is_err(),
            "a nested AddressBookEntry missing `tag` is rejected"
        );
        let unknown_nested = current_profile_json().replace(
            "\"address_book\":[]",
            "\"address_book\":[{\"name\":\"a\",\"address\":\"0:b\",\"tag\":\"\",\"x\":1}]",
        );
        assert!(
            serde_json::from_str::<WalletProfile>(&unknown_nested).is_err(),
            "a nested AddressBookEntry with an unknown field is rejected"
        );
    }

    #[test]
    fn encode_matches_serde_json_to_vec_and_round_trips() {
        let profile = WalletProfile {
            seed: SeedPhrase::shared("all all all all all all all all all all all all".to_owned()),
            address_book: vec![
                AddressBookEntry::new("Alice", "0:aaa"),
                AddressBookEntry::new("Bob", "0:bbb"),
                AddressBookEntry::new("Carol", "0:ccc"),
            ],
            custom_endpoints: vec![
                "https://one:1".to_owned(),
                "https://two:2".to_owned(),
                "https://three:3".to_owned(),
            ],
            selected_endpoint: 2,
            visible_cc_assets: [1u32, 2, 3].into_iter().collect(),
            ..WalletProfile::default()
        };
        let encoded = profile.encode();
        assert_eq!(&*encoded, &serde_json::to_vec(&profile).unwrap());
        assert_eq!(WalletProfile::decode(&encoded).unwrap(), profile);
    }

    #[test]
    fn zeroizing_buffer_grows_within_capacity_and_preserves_content() {
        use std::io::Write as _;

        let mut writer = super::ZeroizingBuffer::with_capacity(16);
        let input: Vec<u8> = (0..3000u32).map(|value| value as u8).collect();
        for chunk in input.chunks(7) {
            writer.write_all(chunk).unwrap();
            assert!(writer.buf.len() <= writer.buf.capacity());
        }
        assert_eq!(&*writer.into_inner(), &input[..]);
    }

    #[test]
    fn a_current_schema_profile_rejects_missing_or_unexpected_fields() {
        let profile = WalletProfile {
            custom_endpoints: vec!["https://a:1".to_owned(), "https://b:2".to_owned()],
            selected_endpoint: 2,
            ..WalletProfile::default()
        };
        let bytes = serde_json::to_vec(&profile).unwrap();
        let back: WalletProfile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.custom_endpoints, profile.custom_endpoints);
        assert_eq!(back.selected_endpoint, 2);

        let missing = r#"{"schema_version":1,"workchain":-1,"seed":"s","network_id":0}"#;
        assert!(
            serde_json::from_str::<WalletProfile>(missing).is_err(),
            "a current profile missing required fields is rejected"
        );
        let stray = current_profile_json().replace(
            "\"selected_endpoint\":0",
            "\"selected_endpoint\":0,\"stray\":1",
        );
        assert!(
            serde_json::from_str::<WalletProfile>(&stray).is_err(),
            "an unexpected field on the current schema is rejected"
        );

        let messy = WalletProfile {
            custom_endpoints: vec![
                " https://a:1 ".to_owned(),
                "https://a:1".to_owned(),
                "".to_owned(),
            ],
            selected_endpoint: 9,
            ..WalletProfile::default()
        }
        .normalized();
        assert_eq!(messy.custom_endpoints, vec!["https://a:1".to_owned()]);
        assert_eq!(
            messy.selected_endpoint, 0,
            "an out-of-range selection resets"
        );
    }

    fn endpoints_profile(custom: &[&str], selected: usize) -> WalletProfile {
        WalletProfile {
            custom_endpoints: custom.iter().map(|s| (*s).to_owned()).collect(),
            selected_endpoint: selected,
            ..WalletProfile::default()
        }
    }

    #[test]
    fn normalized_keeps_selected_endpoint_identity_across_blank_removal() {
        let p = endpoints_profile(&["a", " ", "b", "c"], 3).normalized();
        assert_eq!(p.custom_endpoints, vec!["a", "b", "c"]);
        assert_eq!(p.selected_endpoint, 2, "still resolves to \"b\"");
    }

    #[test]
    fn normalized_keeps_selection_when_earlier_blank_is_dropped() {
        let p = endpoints_profile(&[" ", "a", "b"], 3).normalized();
        assert_eq!(p.custom_endpoints, vec!["a", "b"]);
        assert_eq!(p.selected_endpoint, 2, "follows \"b\" down, not reset to 0");
    }

    #[test]
    fn normalized_resets_selection_pointing_at_blank_or_out_of_range() {
        let at_blank = endpoints_profile(&["a", " ", "b"], 2).normalized();
        assert_eq!(at_blank.selected_endpoint, 0);
        let out_of_range = endpoints_profile(&["a", "b"], 99).normalized();
        assert_eq!(out_of_range.selected_endpoint, 0);
    }

    #[test]
    fn normalized_remaps_deduped_selection_to_surviving_copy() {
        let p = endpoints_profile(&["a", "a"], 2).normalized();
        assert_eq!(p.custom_endpoints, vec!["a"]);
        assert_eq!(p.selected_endpoint, 1);
    }

    #[test]
    fn normalizes_profile() {
        let mut profile = WalletProfile {
            network_id: 2000,
            workchain: 0,
            seed: SeedPhrase::shared(" one  two ".to_owned()),
            visible_cc_assets: [1_u32, 99].into_iter().collect(),
            address_book: vec![
                AddressBookEntry {
                    name: " Alice ".to_owned(),
                    address: " 0:abc ".to_owned(),
                    tag: " Friend ".to_owned(),
                },
                AddressBookEntry::new("", "0:def"),
            ],
            ..WalletProfile::default()
        };
        profile = profile.normalized();
        assert_eq!(profile.network_id, 2000);
        assert_eq!(profile.seed.expose_secret(), "one two");
        assert_eq!(profile.visible_cc_assets, [1_u32].into_iter().collect());
        assert_eq!(
            profile.address_book,
            vec![AddressBookEntry {
                name: "Alice".to_owned(),
                address: "0:abc".to_owned(),
                tag: "Friend".to_owned(),
            }]
        );
    }
}
