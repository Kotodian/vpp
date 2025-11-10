#ifndef __included_siphash_h__
#define __included_siphash_h__

#define HSIPHASH_PERMUTATION(a, b, c, d)                                      \
  ((a) += (b), (b) = rol32 ((b), 5), (b) ^= (a), (a) = rol32 ((a), 16),       \
   (c) += (d), (d) = rol32 ((d), 8), (d) ^= (c), (a) += (d),                  \
   (d) = rol32 ((d), 7), (d) ^= (a), (c) += (b), (b) = rol32 ((b), 13),       \
   (b) ^= (c), (c) = rol32 ((c), 16))

#define HSIPHASH_CONST_0 0U
#define HSIPHASH_CONST_1 0U
#define HSIPHASH_CONST_2 0x6c796765U
#define HSIPHASH_CONST_3 0x74656462U

#define HSIPROUND HSIPHASH_PERMUTATION (v0, v1, v2, v3)

#define HPREAMBLE(len)                                                        \
  u32 v0 = HSIPHASH_CONST_0;                                                  \
  u32 v1 = HSIPHASH_CONST_1;                                                  \
  u32 v2 = HSIPHASH_CONST_2;                                                  \
  u32 v3 = HSIPHASH_CONST_3;                                                  \
  u32 b = ((u32) (len)) << 24;                                                \
  v3 ^= key->key[1];                                                          \
  v2 ^= key->key[0];                                                          \
  v1 ^= key->key[1];                                                          \
  v0 ^= key->key[0];

#define HPOSTAMBLE                                                            \
  v3 ^= b;                                                                    \
  HSIPROUND;                                                                  \
  v0 ^= b;                                                                    \
  v2 ^= 0xff;                                                                 \
  HSIPROUND;                                                                  \
  HSIPROUND;                                                                  \
  HSIPROUND;                                                                  \
  return v1 ^ v3;

typedef struct
{
  u64 key[2];
} hsiphash_key_t;

/**
 * rol64 - rotate a 64-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u64
rol64 (u64 word, unsigned int shift)
{
  return (word << (shift & 63)) | (word >> ((-shift) & 63));
}

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u32
rol32 (u32 word, unsigned int shift)
{
  return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

u32
hsiphash_3u32 (const u32 first, const u32 second, const u32 third,
	       const hsiphash_key_t *key)
{
  u64 combined = (u64) second << 32 | first;
  HPREAMBLE (12)
  v3 ^= combined;
  HSIPROUND;
  v0 ^= combined;
  b |= third;
  HPOSTAMBLE
}

#endif /* __included_siphash_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
