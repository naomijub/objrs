// This file and its contents are licensed by their authors and copyright holders under the Apache
// License (Version 2.0), MIT license, or Mozilla Public License (Version 2.0), at your option, and
// may not be copied, modified, or distributed except according to those terms. For copies of these
// licenses and more information, see the COPYRIGHT file in this distribution's top-level directory.

extern crate core;

// This is based on the reference C implementation, which is by Wang Yi and has been placed in the
// public domain. This isn't idiomatic Rust. It could be made a bit more idiomatic, but at the end
// of the day nontrivial hash functions are always a bit ugly, regardless of the language used or
// how idiomatic the code is. This is intentionally close to the reference C implementation because
// it makes it easier to verify the code. Things were cleaned up a bit though, so hopefully it's a
// little easier to read. The `seed` and `secret` parameters could easily be supported here, but we
// don't need them. The reference C implementation that was used is available at:
// https://github.com/wangyi-fudan/wyhash/blob/302ede147db807680863a9fd4f4a8e0a11ef01cc/wyhash.h

#[inline(always)]
unsafe fn read_u32_le(ptr: *const u8, offset: usize) -> u32 {
  debug_assert!(offset < 64);
  return core::ptr::read_unaligned(ptr.offset(offset as isize) as *const u32).to_le();
}

#[inline(always)]
unsafe fn read_u64_le(ptr: *const u8, offset: usize) -> u64 {
  debug_assert!(offset < 64);
  return core::ptr::read_unaligned(ptr.offset(offset as isize) as *const u64).to_le();
}

#[inline(always)]
fn mix(a: u64, b: u64) -> u64 {
  let r = (a as u128) * (b as u128);
  // wyhash's "blind multiplication" mode returns `a ^ b ^ (r as u64) ^ (r >> 64) as u64`. But we
  // only use the default mode. It's easy to change that if that's ever desired.
  return dbg!(dbg!(r as u64) ^ dbg!(r >> 64) as u64);
}

// This is a nonstandard version of wyhash. The only difference is the last step at the end.
// Normally wyhash mixes two u64 values by multiplying them into a u128, and then XORing the high
// and low halves. This skips that step, and instead returns the two u64 values directly.
pub fn wyhash128(bytes: &[u8]) -> [u64; 2] {
  const SECRET: [u64; 4] =
    [0xa0761d6478bd642f, 0xe7037ed1a0b428db, 0x8ebc6af09c88c6e3, 0x589965cc75374cc3];

  let mut p = bytes.as_ptr();
  let len = bytes.len();

  let mut seed = SECRET[0];

  let a: u64;
  let b: u64;
  if len <= 16 {
    if len <= 8 {
      if len >= 4 {
        a = unsafe { read_u32_le(p, 0) } as u64;
        b = unsafe { read_u32_le(p, len - 4) } as u64;
      } else if len != 0 {
        let high = unsafe { *p } as u64;
        let mid = unsafe { *p.add(len >> 1) } as u64;
        let low = unsafe { *p.add(len - 1) } as u64;
        a = high << 16 | mid << 8 | low;
        b = 0;
      } else {
        a = 0;
        b = 0;
      }
    } else {
      a = unsafe { read_u64_le(p, 0) };
      b = unsafe { read_u64_le(p, len - 8) };
    }
  } else {
    let mut i = len;
    if len > 48 {
      let mut s = [seed, seed, seed];
      loop {
        s[0] = mix(unsafe { read_u64_le(p, 0) } ^ SECRET[1], unsafe { read_u64_le(p, 8) } ^ s[0]);
        s[1] = mix(unsafe { read_u64_le(p, 16) } ^ SECRET[2], unsafe { read_u64_le(p, 24) } ^ s[1]);
        s[2] = mix(unsafe { read_u64_le(p, 32) } ^ SECRET[3], unsafe { read_u64_le(p, 40) } ^ s[2]);
        p = unsafe { p.offset(48) };
        i -= 48;
        if i <= 48 {
          break;
        }
      }
      seed = s[0] ^ s[1] ^ s[2];
    }
    while i > 16 {
      seed = mix(unsafe { read_u64_le(p, 0) } ^ SECRET[1], unsafe { read_u64_le(p, 8) } ^ seed);
      i -= 16;
      p = unsafe { p.offset(16) };
    }
    p = unsafe { p.offset(i as isize - 16) };
    a = unsafe { read_u64_le(p, 0) };
    b = unsafe { read_u64_le(p, 8) };
  }
  return [SECRET[1] ^ len as u64, mix(a ^ SECRET[1], b ^ seed)];
}

#[cfg(test)]
mod tests {
  use super::*;

  const BYTES: [u8; 128] = [
    0x60, 0x25, 0x06, 0x53, 0xab, 0x43, 0xf7, 0xf8, 0x79, 0xfc, 0x26, 0x75, 0x7e, 0x08, 0xd1, 0x49,
    0x66, 0xd7, 0xd8, 0x51, 0x8a, 0x67, 0x35, 0x8c, 0x74, 0xdb, 0x61, 0x51, 0xd3, 0xd9, 0x8d, 0x99,
    0xf5, 0xfa, 0xdc, 0xf6, 0x74, 0xe4, 0xda, 0xec, 0x00, 0x5d, 0x9b, 0x06, 0x30, 0x9f, 0x50, 0xfe,
    0x5f, 0x8b, 0x39, 0xc4, 0x17, 0xfa, 0x85, 0x70, 0x11, 0x9d, 0x1e, 0xaf, 0xf1, 0x34, 0x54, 0xc1,
    0xef, 0x22, 0x02, 0xbb, 0x39, 0x6b, 0x0e, 0xbc, 0x6a, 0x0b, 0x1d, 0x65, 0x77, 0x5d, 0xc4, 0xad,
    0x89, 0xd2, 0x4b, 0xeb, 0x3b, 0xf7, 0x67, 0x72, 0xa0, 0xd5, 0x5d, 0xe6, 0x2e, 0x52, 0x01, 0x75,
    0xfd, 0x0c, 0xf0, 0x3c, 0xe6, 0x9d, 0xd9, 0x34, 0xa1, 0xd5, 0x87, 0x11, 0x69, 0xc8, 0x0b, 0x8b,
    0xc8, 0xf7, 0x1f, 0xd5, 0x39, 0xd5, 0x09, 0xd4, 0x2f, 0x5d, 0x00, 0xc1, 0x88, 0xd8, 0x2c, 0xe2,
  ];

  // This is the "true" wyhash implementation. Its output should match the reference C
  // implementation.
  fn wyhash(bytes: &[u8]) -> u64 {
    let [a, b] = wyhash128(bytes);
    return mix(a, b);
  }

  #[test]
  fn test_wyhash() {
    assert_eq!(wyhash(&BYTES[..0]), 0x42bc986dc5eec4d3);
    assert_eq!(wyhash(&BYTES[..1]), 0x984f26700a622d12);
    assert_eq!(wyhash(&BYTES[..2]), 0x99ac13cf6121b548);
    assert_eq!(wyhash(&BYTES[..3]), 0x000540da42c50471);
    assert_eq!(wyhash(&BYTES[..4]), 0x2150ed1b0296a677);
    assert_eq!(wyhash(&BYTES[..5]), 0xcd47c7062410035a);
    assert_eq!(wyhash(&BYTES[..6]), 0xae77e01e55d936fe);
    assert_eq!(wyhash(&BYTES[..7]), 0x2f7d0ca42cc99ada);
    assert_eq!(wyhash(&BYTES[..8]), 0x0688d1657790d0a9);
    assert_eq!(wyhash(&BYTES[..9]), 0x4a0fa6357b4b24d0);
    assert_eq!(wyhash(&BYTES[..10]), 0xb65ff7bff834b1e3);
    assert_eq!(wyhash(&BYTES[..11]), 0x2078dd137924356c);
    assert_eq!(wyhash(&BYTES[..12]), 0xa70e75fe81b74a93);
    assert_eq!(wyhash(&BYTES[..13]), 0x1a5acfad1d7d2fa1);
    assert_eq!(wyhash(&BYTES[..14]), 0x4da9f19169391359);
    assert_eq!(wyhash(&BYTES[..15]), 0x199596b108e1483a);
    assert_eq!(wyhash(&BYTES[..16]), 0x859006a6386bec12);
    assert_eq!(wyhash(&BYTES[..17]), 0x0912899f7ad5e6b6);
    assert_eq!(wyhash(&BYTES[..18]), 0x468e79fbff0ec3de);
    assert_eq!(wyhash(&BYTES[..19]), 0x0683c5f2e6a06bf0);
    assert_eq!(wyhash(&BYTES[..20]), 0x4941818e2528aede);
    assert_eq!(wyhash(&BYTES[..21]), 0xf12139a580a69185);
    assert_eq!(wyhash(&BYTES[..22]), 0x8bfd46503be1d173);
    assert_eq!(wyhash(&BYTES[..23]), 0x236d713aa7c29060);
    assert_eq!(wyhash(&BYTES[..24]), 0x37b3de4ac7ff6f58);
    assert_eq!(wyhash(&BYTES[..25]), 0x48b9fbce34f541c2);
    assert_eq!(wyhash(&BYTES[..26]), 0x9b095e8e0905c030);
    assert_eq!(wyhash(&BYTES[..27]), 0x3b0daecadaa222a2);
    assert_eq!(wyhash(&BYTES[..28]), 0xb1e42aeae9739243);
    assert_eq!(wyhash(&BYTES[..29]), 0xaeea33a70a277060);
    assert_eq!(wyhash(&BYTES[..30]), 0xcd99176abe40f0a3);
    assert_eq!(wyhash(&BYTES[..31]), 0x9043e7e95442f25f);
    assert_eq!(wyhash(&BYTES[..32]), 0xa35105f0e56b95e7);
    assert_eq!(wyhash(&BYTES[..33]), 0xd5045ed7e2498401);
    assert_eq!(wyhash(&BYTES[..34]), 0x0ba6f5b2da09920b);
    assert_eq!(wyhash(&BYTES[..35]), 0xe7143c666356300f);
    assert_eq!(wyhash(&BYTES[..36]), 0xe3307ae6fe9b1c5d);
    assert_eq!(wyhash(&BYTES[..37]), 0xa0cf173cfee6eca1);
    assert_eq!(wyhash(&BYTES[..38]), 0x8c12a4fa9d0428c6);
    assert_eq!(wyhash(&BYTES[..39]), 0xc291080871d8bb25);
    assert_eq!(wyhash(&BYTES[..40]), 0xa8afea2434a22fd6);
    assert_eq!(wyhash(&BYTES[..41]), 0x3a74506d90567f09);
    assert_eq!(wyhash(&BYTES[..42]), 0x4c99009577481c75);
    assert_eq!(wyhash(&BYTES[..43]), 0xa2d0d3e85b6dacf0);
    assert_eq!(wyhash(&BYTES[..44]), 0xc6bb30e18a9abfb7);
    assert_eq!(wyhash(&BYTES[..45]), 0x10a46f2b9ddfad66);
    assert_eq!(wyhash(&BYTES[..46]), 0xb27312b9a12b682a);
    assert_eq!(wyhash(&BYTES[..47]), 0xe46c42f770486099);
    assert_eq!(wyhash(&BYTES[..48]), 0x96d81dc29a546c95);
    assert_eq!(wyhash(&BYTES[..49]), 0xb03a1e3f3a985b51);
    assert_eq!(wyhash(&BYTES[..50]), 0xfa6000ae2a0d65d7);
    assert_eq!(wyhash(&BYTES[..51]), 0xdd9ad4cd69a3443d);
    assert_eq!(wyhash(&BYTES[..52]), 0xcafcddf6ab282461);
    assert_eq!(wyhash(&BYTES[..53]), 0x1f46f97a8cda7d6f);
    assert_eq!(wyhash(&BYTES[..54]), 0xbfd479cc15f602db);
    assert_eq!(wyhash(&BYTES[..55]), 0x91fff850b3b5c5df);
    assert_eq!(wyhash(&BYTES[..56]), 0x1713983f5abd0afc);
    assert_eq!(wyhash(&BYTES[..57]), 0x3715c3002e61984d);
    assert_eq!(wyhash(&BYTES[..58]), 0xdef31afe87699bb8);
    assert_eq!(wyhash(&BYTES[..59]), 0x622d582ed1f2fcad);
    assert_eq!(wyhash(&BYTES[..60]), 0xbe20d4b93e6e3b34);
    assert_eq!(wyhash(&BYTES[..61]), 0xc864facfa638e1df);
    assert_eq!(wyhash(&BYTES[..62]), 0x8cb43b40b46346bc);
    assert_eq!(wyhash(&BYTES[..63]), 0xb4e98851aee8eb11);
    assert_eq!(wyhash(&BYTES[..64]), 0x256674eb57a744fb);
    assert_eq!(wyhash(&BYTES[..65]), 0x9fe67b4dee226b79);
    assert_eq!(wyhash(&BYTES[..66]), 0xa365456f5988d357);
    assert_eq!(wyhash(&BYTES[..67]), 0xc96d5f18f0a378d2);
    assert_eq!(wyhash(&BYTES[..68]), 0xf43f181204f92114);
    assert_eq!(wyhash(&BYTES[..69]), 0x3c12d42c79d09bb3);
    assert_eq!(wyhash(&BYTES[..70]), 0x7249564fe713539d);
    assert_eq!(wyhash(&BYTES[..71]), 0xb1efd4bf9fb7e5d1);
    assert_eq!(wyhash(&BYTES[..72]), 0xdc127acba7f59393);
    assert_eq!(wyhash(&BYTES[..73]), 0xb5ea7a0e0de5f01d);
    assert_eq!(wyhash(&BYTES[..74]), 0xe48fb5fe4196fc27);
    assert_eq!(wyhash(&BYTES[..75]), 0x9770411d7f04e2f0);
    assert_eq!(wyhash(&BYTES[..76]), 0x540fa468d9c67710);
    assert_eq!(wyhash(&BYTES[..77]), 0xc3448b06195283e3);
    assert_eq!(wyhash(&BYTES[..78]), 0xd2a098fd3c0e4057);
    assert_eq!(wyhash(&BYTES[..79]), 0x75feb112943def8d);
    assert_eq!(wyhash(&BYTES[..80]), 0x00b8ccfe15ecf5be);
    assert_eq!(wyhash(&BYTES[..81]), 0xe862ebbe63a2665e);
    assert_eq!(wyhash(&BYTES[..82]), 0x326fd885b712e124);
    assert_eq!(wyhash(&BYTES[..83]), 0xd71ce4c3009b8563);
    assert_eq!(wyhash(&BYTES[..84]), 0x56fbb0508487e0f6);
    assert_eq!(wyhash(&BYTES[..85]), 0x7ea3cebcd579b903);
    assert_eq!(wyhash(&BYTES[..86]), 0x7df2ead61f0ba280);
    assert_eq!(wyhash(&BYTES[..87]), 0xe05b7bb8c7460d33);
    assert_eq!(wyhash(&BYTES[..88]), 0xf02028fd36ab8fa4);
    assert_eq!(wyhash(&BYTES[..89]), 0x02e9e1e7936c27ae);
    assert_eq!(wyhash(&BYTES[..90]), 0x5f930f05b7c23018);
    assert_eq!(wyhash(&BYTES[..91]), 0x71e6bcfb836ca565);
    assert_eq!(wyhash(&BYTES[..92]), 0x9ed03b3541f92fb6);
    assert_eq!(wyhash(&BYTES[..93]), 0x72e55f879800ef34);
    assert_eq!(wyhash(&BYTES[..94]), 0x709aba3afc7fdc9e);
    assert_eq!(wyhash(&BYTES[..95]), 0xf91af734f5aacaff);
    assert_eq!(wyhash(&BYTES[..96]), 0xb7ec97bc667b2fe1);
    assert_eq!(wyhash(&BYTES[..97]), 0x7b4cdd461e73fc18);
    assert_eq!(wyhash(&BYTES[..98]), 0xd3bf3dca6dbd9799);
    assert_eq!(wyhash(&BYTES[..99]), 0x6ebae18b76c1d634);
    assert_eq!(wyhash(&BYTES[..100]), 0xdee9df48bd3b977c);
    assert_eq!(wyhash(&BYTES[..101]), 0x99f8f4568546f9b8);
    assert_eq!(wyhash(&BYTES[..102]), 0x48b36b89f30c595b);
    assert_eq!(wyhash(&BYTES[..103]), 0x6c4bcd6ee8071577);
    assert_eq!(wyhash(&BYTES[..104]), 0xb884f49f35642551);
    assert_eq!(wyhash(&BYTES[..105]), 0x94bff7aecf9d7cb4);
    assert_eq!(wyhash(&BYTES[..106]), 0x952e03ad79fb215f);
    assert_eq!(wyhash(&BYTES[..107]), 0x869df711519ab89b);
    assert_eq!(wyhash(&BYTES[..108]), 0xb53b029c329ce567);
    assert_eq!(wyhash(&BYTES[..109]), 0x4aef85cf24cad2aa);
    assert_eq!(wyhash(&BYTES[..110]), 0x7366badede039714);
    assert_eq!(wyhash(&BYTES[..111]), 0x9e31bf5ab1321d4d);
    assert_eq!(wyhash(&BYTES[..112]), 0x0cf067d306b29d57);
    assert_eq!(wyhash(&BYTES[..113]), 0x1421f035384bb8e5);
    assert_eq!(wyhash(&BYTES[..114]), 0x024a01795339f6ed);
    assert_eq!(wyhash(&BYTES[..115]), 0x37a282cf5d57be6e);
    assert_eq!(wyhash(&BYTES[..116]), 0xf6302429b6e44a03);
    assert_eq!(wyhash(&BYTES[..117]), 0x3dd1d292a9515f1a);
    assert_eq!(wyhash(&BYTES[..118]), 0xdc42c9ccbd546fed);
    assert_eq!(wyhash(&BYTES[..119]), 0xab7e506dda034f2d);
    assert_eq!(wyhash(&BYTES[..120]), 0xe9d027b0d0a89204);
    assert_eq!(wyhash(&BYTES[..121]), 0x0192ed2a17e7ff53);
    assert_eq!(wyhash(&BYTES[..122]), 0x17e437c7bb8aef04);
    assert_eq!(wyhash(&BYTES[..123]), 0xc2aa899ea3b6a24c);
    assert_eq!(wyhash(&BYTES[..124]), 0x63b67883170de9c7);
    assert_eq!(wyhash(&BYTES[..125]), 0x35b4fb3f33a338aa);
    assert_eq!(wyhash(&BYTES[..126]), 0xf5d3a7ede4d82950);
    assert_eq!(wyhash(&BYTES[..127]), 0xbbde7788d8e71c4e);
    assert_eq!(wyhash(&BYTES[..128]), 0x25936fb7495f116a);
  }
}
