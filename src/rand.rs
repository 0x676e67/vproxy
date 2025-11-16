macro_rules! rng_impl {
    ($name:ident, $type:ty, $seed_name:ident, $rng_name:ident, $shift1:expr, $shift2:expr, $shift3:expr, $multiplier:expr) => {
        pub(crate) fn $name() -> $type {
            use std::{
                cell::Cell,
                collections::hash_map::RandomState,
                hash::{BuildHasher, Hasher},
                num::Wrapping,
            };

            thread_local! {
                static $rng_name: Cell<Wrapping<$type>> = Cell::new(Wrapping($seed_name()));
            }

            fn $seed_name() -> $type {
                let seed = RandomState::new();
                let mut out = 0;
                let mut cnt = 0;
                while out == 0 {
                    cnt += 1;
                    let mut hasher = seed.build_hasher();
                    hasher.write_usize(cnt);
                    out = hasher.finish() as $type;
                }
                out
            }

            $rng_name.with(|rng| {
                let mut n = rng.get();
                debug_assert_ne!(n.0, 0);
                n ^= n >> $shift1;
                n ^= n << $shift2;
                n ^= n >> $shift3;
                rng.set(n);
                n.0.wrapping_mul($multiplier)
            })
        }
    };
}

rng_impl!(random_u32, u32, seed_u32, RNG_U32, 13, 17, 5, 0x85eb_ca6b);

rng_impl!(
    random_u64,
    u64,
    seed,
    RNG,
    12,
    25,
    27,
    0x2545_f491_4f6c_dd1d
);

rng_impl!(
    random_u128,
    u128,
    seed_u128,
    RNG_U128,
    19,
    23,
    31,
    0x9e3779b97f4a7c15f39cc0605cedc834_u128
);
