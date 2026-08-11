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
