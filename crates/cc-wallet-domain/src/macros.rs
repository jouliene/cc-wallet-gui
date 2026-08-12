macro_rules! accessors {
    ($owner:ty { $($name:ident : $kind:tt $ty:ty),* $(,)? }) => {
        impl $owner {
            $( accessors!(@one $name, $kind, $ty); )*
        }
    };
    (@one $n:ident, ref, $t:ty) => {
        pub fn $n(&self) -> &$t {
            &self.$n
        }
    };
    (@one $n:ident, copy, $t:ty) => {
        pub fn $n(&self) -> $t {
            self.$n
        }
    };
    (@one $n:ident, opt, $t:ty) => {
        pub fn $n(&self) -> Option<&$t> {
            self.$n.as_ref()
        }
    };
}

macro_rules! wire_deserialize {
    ($owner:ident via $wire:ident { $($field:ident),* $(,)? }) => {
        impl<'de> serde::Deserialize<'de> for $owner {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let wire = $wire::deserialize(deserializer)?;
                Self::new($( wire.$field ),*).map_err(serde::de::Error::custom)
            }
        }
    };
    ($owner:ident via $wire:ident infallible { $($field:ident),* $(,)? }) => {
        impl<'de> serde::Deserialize<'de> for $owner {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let wire = $wire::deserialize(deserializer)?;
                Ok(Self::new($( wire.$field ),*))
            }
        }
    };
}
