use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const DEFAULT: Self = Self {
        m_kib: 262_144,
        t: 3,
        p: 1,
    };

    pub const FLOOR: Self = Self {
        m_kib: 65_536,
        t: 3,
        p: 1,
    };

    const MIN_M_KIB: u32 = 8;
    const MAX_M_KIB: u32 = 1_048_576;
    const MIN_T: u32 = 1;
    const MAX_T: u32 = 16;

    pub fn validate(self) -> VaultResult<()> {
        if self.m_kib < Self::MIN_M_KIB || self.m_kib > Self::MAX_M_KIB {
            return Err(VaultError::ParamsRejected("memory cost out of range"));
        }
        if self.t < Self::MIN_T || self.t > Self::MAX_T {
            return Err(VaultError::ParamsRejected("time cost out of range"));
        }
        if self.p != 1 {
            return Err(VaultError::ParamsRejected("parallelism must be 1"));
        }
        Ok(())
    }

    pub fn weaker_than(self, current: KdfParams) -> bool {
        self.m_kib < current.m_kib || self.t < current.t
    }

    pub fn meets_floor(self) -> bool {
        !self.weaker_than(Self::FLOOR)
    }
}

#[cfg(debug_assertions)]
thread_local! {
    pub(crate) static KDF_INVOCATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub(crate) fn derive_kek(
    password: &[u8],
    salt: &[u8; 16],
    params: KdfParams,
) -> VaultResult<Zeroizing<[u8; 32]>> {
    #[cfg(debug_assertions)]
    KDF_INVOCATIONS.with(|count| count.set(count.get() + 1));
    params.validate()?;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_kib, params.t, params.p, Some(32))
            .map_err(|_| VaultError::ParamsRejected("invalid argon2 params"))?,
    );
    let mut kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, &mut kek[..])
        .map_err(|_| VaultError::Crypto("argon2 hashing failed (out of memory?)"))?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_defaults_and_floor() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
        assert!(KdfParams::FLOOR.validate().is_ok());
    }

    #[test]
    fn validate_rejects_allocation_bombs_and_bad_parallelism() {
        assert!(
            KdfParams {
                m_kib: 16_777_216,
                t: 3,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            KdfParams {
                m_kib: 1,
                t: 3,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            KdfParams {
                m_kib: 65_536,
                t: 100,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            KdfParams {
                m_kib: 65_536,
                t: 3,
                p: 4
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn weaker_than_detects_upgrades() {
        let weak = KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 1,
        };
        assert!(weak.weaker_than(KdfParams::DEFAULT));
        assert!(!KdfParams::DEFAULT.weaker_than(weak));
        assert!(!KdfParams::DEFAULT.weaker_than(KdfParams::DEFAULT));
    }

    #[test]
    fn floor_is_the_minimum_acceptable_strength() {
        assert!(
            KdfParams::DEFAULT.meets_floor(),
            "the default is above floor"
        );
        assert!(KdfParams::FLOOR.meets_floor(), "the floor meets itself");
        let below = KdfParams {
            m_kib: 32,
            t: 2,
            p: 1,
        };
        assert!(!below.meets_floor(), "sub-floor params are flagged");
    }
}
