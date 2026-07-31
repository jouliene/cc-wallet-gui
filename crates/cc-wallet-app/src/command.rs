use cc_wallet_domain::AssetId;
use zeroize::{Zeroize, Zeroizing};

use crate::state::AppTab;

pub struct Password {
    value: Zeroizing<String>,
    #[cfg(test)]
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

pub struct SeedInput(Zeroizing<String>);

impl SeedInput {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn from_zeroizing(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    pub(crate) fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl From<Zeroizing<String>> for SeedInput {
    fn from(value: Zeroizing<String>) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for SeedInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SeedInput(<redacted>)")
    }
}

impl Password {
    pub fn new(value: String) -> Self {
        Self {
            value: Zeroizing::new(value),
            #[cfg(test)]
            drop_probe: None,
        }
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub(crate) fn char_count(&self) -> usize {
        self.value.chars().count()
    }

    #[cfg(test)]
    pub(crate) fn with_drop_probe(
        value: String,
        probe: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        Self {
            value: Zeroizing::new(value),
            drop_probe: Some(probe),
        }
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.value.zeroize();
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            probe.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Password(<redacted>)")
    }
}

pub enum AppCommand {
    Init,
    SelectWallet(String),
    NewWalletRequest,
    DeleteWalletFromPicker {
        name: String,
        pw: Password,
    },
    BackToPicker,
    CreateWallet {
        name: String,
        network_id: i32,
        workchain: i8,
        pw: Password,
        pw2: Password,
    },
    Unlock(Password),
    LockNow,
    SwitchWallet,
    SwitchToWallet(String),
    DeleteWallet,
    SelectTab(AppTab),
    GenerateSeed,
    OnboardImportSeed(SeedInput),
    SetSeedBackupConfirmed(bool),
    SaveSeed(SeedInput),
    ImportSeed(SeedInput),
    UseSeed,
    DiscardSeed,
    RevealSeed,
    HideSeed,
    CopySeed(SeedInput),
    CopyText(String),
    RefreshWallet,
    SaveContact {
        index: Option<usize>,
        name: String,
        address: String,
        tag: String,
    },
    DeleteContact(usize),
    ReorderContacts {
        from: usize,
        to: usize,
    },
    QuickSend(String),
    SetAssetVisibility {
        cc_id: u32,
        visible: bool,
    },
    SelectAsset(AssetId),
    SetSendDestination(String),
    SetSendAmount(String),
    SetMaxAmount,
    SetAllowUnbounced(bool),
    RequestSend,
    SetSwapFromToken(AssetId),
    SetSwapToToken(AssetId),
    SetSwapAmount(String),
    SetMaxSwapAmount,
    SetSwapSlippage(u16),
    StepSwapSlippage(bool),
    EditSwapSlippage(String),
    FlipSwap,
    RequestSwap,
    DismissSwapReceipt,
    RequestRiskOverride,
    SetRiskOverlap {
        index: usize,
        selected: bool,
    },
    ConfirmRiskOverride {
        typed_confirmation: String,
        acknowledge_both_may_debit: bool,
        acknowledge_duplicate: bool,
    },
    CancelRiskOverride,
    ChangePasswordRequest,
    AuthSubmit {
        pw: Password,
        pw2: Password,
        remember: bool,
    },
    AuthCancel,
    SetAutosign(u8),
    SetScreenLock(u8),
    InspectAccount(String),
    OpenInExplorer {
        address: String,
        transaction_hash: String,
    },
    TraceTransaction(String),
    CloseTrace,
    AddEndpoint(String),
    SelectEndpoint(usize),
    RemoveEndpoint(String),
    TestEndpoint(String),
    ClearError,
}

impl AppCommand {
    pub(crate) fn frozen_while_authorization_pending(&self) -> bool {
        match self {
            Self::RequestRiskOverride
            | Self::QuickSend(_)
            | Self::GenerateSeed
            | Self::SaveSeed(_)
            | Self::ImportSeed(_)
            | Self::UseSeed
            | Self::DiscardSeed
            | Self::ChangePasswordRequest
            | Self::RevealSeed
            | Self::DeleteWallet
            | Self::SetAssetVisibility { .. }
            | Self::SelectAsset(_)
            | Self::SetSendDestination(_)
            | Self::SetSendAmount(_)
            | Self::SetMaxAmount
            | Self::SetAllowUnbounced(_)
            | Self::SetSwapFromToken(_)
            | Self::SetSwapToToken(_)
            | Self::SetSwapAmount(_)
            | Self::SetMaxSwapAmount
            | Self::SetSwapSlippage(_)
            | Self::StepSwapSlippage(_)
            | Self::EditSwapSlippage(_)
            | Self::FlipSwap
            | Self::DismissSwapReceipt
            | Self::AddEndpoint(_)
            | Self::SelectEndpoint(_)
            | Self::RemoveEndpoint(_) => true,
            Self::Init
            | Self::SelectWallet(_)
            | Self::NewWalletRequest
            | Self::DeleteWalletFromPicker { .. }
            | Self::BackToPicker
            | Self::CreateWallet { .. }
            | Self::Unlock(_)
            | Self::LockNow
            | Self::SwitchWallet
            | Self::SwitchToWallet(_)
            | Self::SelectTab(_)
            | Self::OnboardImportSeed(_)
            | Self::SetSeedBackupConfirmed(_)
            | Self::HideSeed
            | Self::CopySeed(_)
            | Self::CopyText(_)
            | Self::RefreshWallet
            | Self::SaveContact { .. }
            | Self::DeleteContact(_)
            | Self::ReorderContacts { .. }
            | Self::RequestSend
            | Self::RequestSwap
            | Self::SetRiskOverlap { .. }
            | Self::ConfirmRiskOverride { .. }
            | Self::CancelRiskOverride
            | Self::AuthSubmit { .. }
            | Self::AuthCancel
            | Self::SetAutosign(_)
            | Self::SetScreenLock(_)
            | Self::TestEndpoint(_)
            | Self::InspectAccount(_)
            | Self::OpenInExplorer { .. }
            | Self::TraceTransaction(_)
            | Self::CloseTrace
            | Self::ClearError => false,
        }
    }

    pub(crate) fn changes_wallet_identity_or_endpoint(&self) -> bool {
        match self {
            Self::GenerateSeed
            | Self::SaveSeed(_)
            | Self::ImportSeed(_)
            | Self::UseSeed
            | Self::SelectEndpoint(_)
            | Self::RemoveEndpoint(_) => true,
            Self::Init
            | Self::SelectWallet(_)
            | Self::NewWalletRequest
            | Self::DeleteWalletFromPicker { .. }
            | Self::BackToPicker
            | Self::CreateWallet { .. }
            | Self::Unlock(_)
            | Self::LockNow
            | Self::SwitchWallet
            | Self::SwitchToWallet(_)
            | Self::DeleteWallet
            | Self::SelectTab(_)
            | Self::OnboardImportSeed(_)
            | Self::SetSeedBackupConfirmed(_)
            | Self::DiscardSeed
            | Self::RevealSeed
            | Self::HideSeed
            | Self::CopySeed(_)
            | Self::CopyText(_)
            | Self::RefreshWallet
            | Self::SaveContact { .. }
            | Self::DeleteContact(_)
            | Self::ReorderContacts { .. }
            | Self::QuickSend(_)
            | Self::SetAssetVisibility { .. }
            | Self::SelectAsset(_)
            | Self::SetSendDestination(_)
            | Self::SetSendAmount(_)
            | Self::SetMaxAmount
            | Self::SetAllowUnbounced(_)
            | Self::RequestSend
            | Self::SetSwapFromToken(_)
            | Self::SetSwapToToken(_)
            | Self::SetSwapAmount(_)
            | Self::SetMaxSwapAmount
            | Self::SetSwapSlippage(_)
            | Self::StepSwapSlippage(_)
            | Self::EditSwapSlippage(_)
            | Self::FlipSwap
            | Self::DismissSwapReceipt
            | Self::RequestSwap
            | Self::RequestRiskOverride
            | Self::SetRiskOverlap { .. }
            | Self::ConfirmRiskOverride { .. }
            | Self::CancelRiskOverride
            | Self::ChangePasswordRequest
            | Self::AuthSubmit { .. }
            | Self::AuthCancel
            | Self::SetAutosign(_)
            | Self::SetScreenLock(_)
            | Self::AddEndpoint(_)
            | Self::TestEndpoint(_)
            | Self::InspectAccount(_)
            | Self::OpenInExplorer { .. }
            | Self::TraceTransaction(_)
            | Self::CloseTrace
            | Self::ClearError => false,
        }
    }
}
