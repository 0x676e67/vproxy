use std::mem;

fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccdu64);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53u64);
    k ^= k >> 33;

    k
}

fn get_128_block(bytes: &[u8], index: usize) -> (u64, u64) {
    let b64: &[u64] = unsafe { mem::transmute(bytes) };

    (b64[index], b64[index + 1])
}

pub fn murmurhash3_x64_128(bytes: &[u8], seed: u64) -> (u64, u64) {
    let c1 = 0x87c37b91114253d5u64;
    let c2 = 0x4cf5ad432745937fu64;
    let read_size = 16;
    let len = bytes.len() as u64;
    let block_count = len / read_size;

    let (mut h1, mut h2) = (seed, seed);

    for i in 0..block_count as usize {
        let (mut k1, mut k2) = get_128_block(bytes, i * 2);

        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;

        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5);
        h1 = h1.wrapping_add(0x52dce729);

        k2 = k2.wrapping_mul(c2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(c1);
        h2 ^= k2;

        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5);
        h2 = h2.wrapping_add(0x38495ab5);
    }

    let (mut k1, mut k2) = (0u64, 0u64);

    if len & 15 == 15 {
        k2 ^= (bytes[(block_count * read_size) as usize + 14] as u64) << 48;
    }
    if len & 15 >= 14 {
        k2 ^= (bytes[(block_count * read_size) as usize + 13] as u64) << 40;
    }
    if len & 15 >= 13 {
        k2 ^= (bytes[(block_count * read_size) as usize + 12] as u64) << 32;
    }
    if len & 15 >= 12 {
        k2 ^= (bytes[(block_count * read_size) as usize + 11] as u64) << 24;
    }
    if len & 15 >= 11 {
        k2 ^= (bytes[(block_count * read_size) as usize + 10] as u64) << 16;
    }
    if len & 15 >= 10 {
        k2 ^= (bytes[(block_count * read_size) as usize + 9] as u64) << 8;
    }
    if len & 15 >= 9 {
        k2 ^= bytes[(block_count * read_size) as usize + 8] as u64;
        k2 = k2.wrapping_mul(c2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(c1);
        h2 ^= k2;
    }

    if len & 15 >= 8 {
        k1 ^= (bytes[(block_count * read_size) as usize + 7] as u64) << 56;
    }
    if len & 15 >= 7 {
        k1 ^= (bytes[(block_count * read_size) as usize + 6] as u64) << 48;
    }
    if len & 15 >= 6 {
        k1 ^= (bytes[(block_count * read_size) as usize + 5] as u64) << 40;
    }
    if len & 15 >= 5 {
        k1 ^= (bytes[(block_count * read_size) as usize + 4] as u64) << 32;
    }
    if len & 15 >= 4 {
        k1 ^= (bytes[(block_count * read_size) as usize + 3] as u64) << 24;
    }
    if len & 15 >= 3 {
        k1 ^= (bytes[(block_count * read_size) as usize + 2] as u64) << 16;
    }
    if len & 15 >= 2 {
        k1 ^= (bytes[(block_count * read_size) as usize + 1] as u64) << 8;
    }
    if len & 15 >= 1 {
        k1 ^= bytes[(block_count * read_size) as usize + 0] as u64;
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
    }

    h1 ^= bytes.len() as u64;
    h2 ^= bytes.len() as u64;

    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    (h1, h2)
}
