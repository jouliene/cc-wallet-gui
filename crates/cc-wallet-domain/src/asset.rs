use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssetId {
    Native,
    CurrencyCollection(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetTone {
    Coin,
    One,
    Two,
    Three,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetMeta {
    pub id: AssetId,
    pub display_name: &'static str,
    pub symbol: &'static str,
    pub mark: &'static str,
    pub tone: AssetTone,
    pub decimals: Option<u8>,
}

pub const COIN_ASSET: AssetMeta = AssetMeta {
    id: AssetId::Native,
    display_name: "CC Coin",
    symbol: "COIN",
    mark: "C",
    tone: AssetTone::Coin,
    decimals: Some(9),
};

pub const ONE_ASSET: AssetMeta = AssetMeta {
    id: AssetId::CurrencyCollection(1),
    display_name: "One Token",
    symbol: "ONE",
    mark: "1",
    tone: AssetTone::One,
    decimals: Some(9),
};

pub const TWO_ASSET: AssetMeta = AssetMeta {
    id: AssetId::CurrencyCollection(2),
    display_name: "Two Token",
    symbol: "TWO",
    mark: "2",
    tone: AssetTone::Two,
    decimals: Some(9),
};

pub const THREE_ASSET: AssetMeta = AssetMeta {
    id: AssetId::CurrencyCollection(3),
    display_name: "Three Token",
    symbol: "THREE",
    mark: "3",
    tone: AssetTone::Three,
    decimals: Some(9),
};

const UNKNOWN_CC_ASSET: AssetMeta = AssetMeta {
    id: AssetId::CurrencyCollection(0),
    display_name: "Currency Collection",
    symbol: "CC",
    mark: "#",
    tone: AssetTone::Unknown,
    decimals: Some(9),
};

pub fn known_cc_assets() -> [AssetMeta; 3] {
    [ONE_ASSET, TWO_ASSET, THREE_ASSET]
}

pub fn all_supported_assets() -> [AssetMeta; 4] {
    [COIN_ASSET, ONE_ASSET, TWO_ASSET, THREE_ASSET]
}

pub fn asset_meta(asset: AssetId) -> AssetMeta {
    match asset {
        AssetId::Native => COIN_ASSET,
        AssetId::CurrencyCollection(1) => ONE_ASSET,
        AssetId::CurrencyCollection(2) => TWO_ASSET,
        AssetId::CurrencyCollection(3) => THREE_ASSET,
        AssetId::CurrencyCollection(id) => AssetMeta {
            id: AssetId::CurrencyCollection(id),
            ..UNKNOWN_CC_ASSET
        },
    }
}

impl AssetId {
    pub fn cc_id(self) -> Option<u32> {
        match self {
            Self::Native => None,
            Self::CurrencyCollection(id) => Some(id),
        }
    }

    pub fn is_native(self) -> bool {
        matches!(self, Self::Native)
    }

    pub fn is_known_cc(self) -> bool {
        matches!(self, Self::CurrencyCollection(id) if known_cc_assets().iter().any(|meta| meta.id.cc_id() == Some(id)))
    }

    pub fn is_sendable(self) -> bool {
        self.is_native() || self.is_known_cc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_known_assets() {
        assert_eq!(asset_meta(AssetId::Native).symbol, "COIN");
        assert_eq!(asset_meta(AssetId::CurrencyCollection(1)).symbol, "ONE");
        assert_eq!(asset_meta(AssetId::CurrencyCollection(2)).symbol, "TWO");
        assert_eq!(asset_meta(AssetId::CurrencyCollection(3)).symbol, "THREE");
    }

    #[test]
    fn preserves_unknown_cc_id() {
        let meta = asset_meta(AssetId::CurrencyCollection(42));
        assert_eq!(meta.id, AssetId::CurrencyCollection(42));
        assert_eq!(meta.symbol, "CC");
        assert_eq!(meta.decimals, Some(9));
    }

    #[test]
    fn is_sendable_matches_known_cc_assets() {
        assert!(AssetId::Native.is_sendable());
        assert!(!AssetId::Native.is_known_cc());
        for id in 1..=3 {
            assert!(AssetId::CurrencyCollection(id).is_known_cc());
            assert!(AssetId::CurrencyCollection(id).is_sendable());
        }
        for id in [0, 4, 42, u32::MAX] {
            assert!(!AssetId::CurrencyCollection(id).is_known_cc());
            assert!(!AssetId::CurrencyCollection(id).is_sendable());
        }
        assert!(known_cc_assets().iter().all(|meta| meta.id.is_sendable()));
    }
}
