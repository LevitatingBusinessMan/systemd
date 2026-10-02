// SPDX-License-Identifier: CC0-1.0

//! SipHash-2-4, exported with the C API declared in siphash24.h.
//!
//! This is compiled to a bare object file without linking libcore, hence nothing in here may be able to
//! panic: any remaining panic path shows up as an undefined core::panicking symbol at link time.

#![no_std]

use core::ffi::{CStr, c_char, c_void};

/// Must match struct siphash in siphash24.h.
#[repr(C)]
pub struct Siphash {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    /* Input bytes not yet compressed, little endian. */
    padding: u64,
    inlen: usize,
}

/// Must match struct iovec.
#[repr(C)]
pub struct Iovec {
    iov_base: *const c_void,
    iov_len: usize,
}

impl Siphash {
    fn new(k: &[u8; 16]) -> Self {
        let k0 = u64::from_le_bytes(k[..8].try_into().unwrap_or_default());
        let k1 = u64::from_le_bytes(k[8..].try_into().unwrap_or_default());

        Siphash {
            /* "somepseudorandomlygeneratedbytes" */
            v0: 0x736f6d6570736575 ^ k0,
            v1: 0x646f72616e646f6d ^ k1,
            v2: 0x6c7967656e657261 ^ k0,
            v3: 0x7465646279746573 ^ k1,
            padding: 0,
            inlen: 0,
        }
    }

    #[inline(always)]
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    #[inline(always)]
    fn compress_word(&mut self, m: u64) {
        self.v3 ^= m;
        self.round();
        self.round();
        self.v0 ^= m;
    }

    fn compress(&mut self, mut data: &[u8]) {
        let mut left = self.inlen & 7;

        self.inlen = self.inlen.wrapping_add(data.len());

        /* If padding exists, fill it out */
        if left > 0 {
            let n = (8 - left).min(data.len());
            for &b in &data[..n] {
                self.padding |= u64::from(b) << (left * 8);
                left += 1;
            }
            data = &data[n..];

            if left < 8 {
                /* We did not have enough input to fill out the padding completely */
                return;
            }

            let m = self.padding;
            self.padding = 0;
            self.compress_word(m);
        }

        let mut words = data.chunks_exact(8);
        for word in &mut words {
            if let Ok(word) = word.try_into() {
                self.compress_word(u64::from_le_bytes(word));
            }
        }

        for (i, &b) in words.remainder().iter().enumerate() {
            self.padding |= u64::from(b) << (i * 8);
        }
    }

    fn finalize(&mut self) -> u64 {
        let b = self.padding | ((self.inlen as u64) << 56);

        self.compress_word(b);
        self.v2 ^= 0xff;
        self.round();
        self.round();
        self.round();
        self.round();

        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// Like slice::from_raw_parts(), but allows NULL if `len` is 0.
unsafe fn bytes<'a>(p: *const c_void, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }

    unsafe { core::slice::from_raw_parts(p.cast(), len) }
}

/// # Safety
/// `state` must be valid for writing and `k` must point to 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn siphash24_init(state: *mut Siphash, k: *const [u8; 16]) {
    unsafe { state.write(Siphash::new(&*k)) };
}

/// # Safety
/// `state` must have been initialized with siphash24_init() and `inp` must be valid for reading `inlen`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn siphash24_compress(inp: *const c_void, inlen: usize, state: *mut Siphash) {
    unsafe { (*state).compress(bytes(inp, inlen)) };
}

/// # Safety
/// `state` must have been initialized with siphash24_init() and `inp` must be NULL or a NUL-terminated
/// string. The terminating NUL is not hashed.
#[no_mangle]
pub unsafe extern "C" fn siphash24_compress_string(inp: *const c_char, state: *mut Siphash) {
    if inp.is_null() {
        return;
    }

    unsafe { (*state).compress(CStr::from_ptr(inp).to_bytes()) };
}

/// # Safety
/// `state` must have been initialized with siphash24_init() and `iov` must be NULL or a valid iovec.
#[no_mangle]
pub unsafe extern "C" fn siphash24_compress_iovec(iov: *const Iovec, state: *mut Siphash) {
    let Some(iov) = (unsafe { iov.as_ref() }) else {
        return;
    };

    if iov.iov_base.is_null() {
        return;
    }

    unsafe { (*state).compress(bytes(iov.iov_base, iov.iov_len)) };
}

/// # Safety
/// `state` must have been initialized with siphash24_init().
#[no_mangle]
pub unsafe extern "C" fn siphash24_finalize(state: *mut Siphash) -> u64 {
    unsafe { (*state).finalize() }
}

/// # Safety
/// `inp` must be valid for reading `inlen` bytes and `k` must point to 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn siphash24(inp: *const c_void, inlen: usize, k: *const [u8; 16]) -> u64 {
    let mut state = Siphash::new(unsafe { &*k });

    state.compress(unsafe { bytes(inp, inlen) });
    state.finalize()
}

/// # Safety
/// `s` must be a NUL-terminated string and `k` must point to 16 bytes. The terminating NUL is hashed too.
#[no_mangle]
pub unsafe extern "C" fn siphash24_string(s: *const c_char, k: *const [u8; 16]) -> u64 {
    let s = unsafe { CStr::from_ptr(s) }.to_bytes_with_nul();

    unsafe { siphash24(s.as_ptr().cast(), s.len(), k) }
}
