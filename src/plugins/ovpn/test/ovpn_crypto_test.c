/*
 * ovpn_crypto_test.c - OpenVPN crypto unit tests
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_packet.h>

/*
 * Test macros
 */
#define OVPN_TEST_I(_cond, _comment, _args...)                                \
  ({                                                                          \
    int _evald = (_cond);                                                     \
    if (!(_evald))                                                            \
      {                                                                       \
	vlib_cli_output (vm, "FAIL:%d: " _comment "\n", __LINE__, ##_args);   \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	vlib_cli_output (vm, "PASS:%d: " _comment "\n", __LINE__, ##_args);   \
      }                                                                       \
    _evald;                                                                   \
  })

#define OVPN_TEST(_cond, _comment, _args...)                                  \
  {                                                                           \
    if (!OVPN_TEST_I (_cond, _comment, ##_args))                              \
      {                                                                       \
	return 1;                                                             \
      }                                                                       \
  }

/*
 * Test cipher algorithm name parsing
 */
static int
ovpn_test_cipher_alg_from_name (vlib_main_t *vm)
{
  ovpn_cipher_alg_t alg;

  vlib_cli_output (vm, "=== Test Cipher Algorithm Name Parsing ===\n");

  /* Test AES-128-GCM */
  alg = ovpn_crypto_cipher_alg_from_name ("AES-128-GCM");
  OVPN_TEST (alg == OVPN_CIPHER_ALG_AES_128_GCM,
	     "AES-128-GCM should parse correctly");

  /* Test case insensitivity */
  alg = ovpn_crypto_cipher_alg_from_name ("aes-128-gcm");
  OVPN_TEST (alg == OVPN_CIPHER_ALG_AES_128_GCM,
	     "aes-128-gcm (lowercase) should parse correctly");

  /* Test AES-256-GCM */
  alg = ovpn_crypto_cipher_alg_from_name ("AES-256-GCM");
  OVPN_TEST (alg == OVPN_CIPHER_ALG_AES_256_GCM,
	     "AES-256-GCM should parse correctly");

  /* Test ChaCha20-Poly1305 */
  alg = ovpn_crypto_cipher_alg_from_name ("CHACHA20-POLY1305");
  OVPN_TEST (alg == OVPN_CIPHER_ALG_CHACHA20_POLY1305,
	     "CHACHA20-POLY1305 should parse correctly");

  /* Test invalid cipher */
  alg = ovpn_crypto_cipher_alg_from_name ("INVALID-CIPHER");
  OVPN_TEST (alg == OVPN_CIPHER_ALG_NONE,
	     "Invalid cipher should return NONE");

  /* Test NULL input */
  alg = ovpn_crypto_cipher_alg_from_name (NULL);
  OVPN_TEST (alg == OVPN_CIPHER_ALG_NONE, "NULL should return NONE");

  /* Test empty string */
  alg = ovpn_crypto_cipher_alg_from_name ("");
  OVPN_TEST (alg == OVPN_CIPHER_ALG_NONE, "Empty string should return NONE");

  vlib_cli_output (vm, "Cipher algorithm name parsing test PASSED\n");
  return 0;
}

/*
 * Test key size functions
 */
static int
ovpn_test_key_sizes (vlib_main_t *vm)
{
  u8 size;

  vlib_cli_output (vm, "=== Test Key Sizes ===\n");

  /* AES-128-GCM should use 16-byte key */
  size = ovpn_crypto_key_size (OVPN_CIPHER_ALG_AES_128_GCM);
  OVPN_TEST (size == OVPN_KEY_SIZE_128, "AES-128-GCM key size should be 16");

  /* AES-256-GCM should use 32-byte key */
  size = ovpn_crypto_key_size (OVPN_CIPHER_ALG_AES_256_GCM);
  OVPN_TEST (size == OVPN_KEY_SIZE_256, "AES-256-GCM key size should be 32");

  /* ChaCha20-Poly1305 should use 32-byte key */
  size = ovpn_crypto_key_size (OVPN_CIPHER_ALG_CHACHA20_POLY1305);
  OVPN_TEST (size == OVPN_KEY_SIZE_256,
	     "CHACHA20-POLY1305 key size should be 32");

  /* NONE should return 0 */
  size = ovpn_crypto_key_size (OVPN_CIPHER_ALG_NONE);
  OVPN_TEST (size == 0, "NONE cipher key size should be 0");

  /* Verify constants */
  OVPN_TEST (OVPN_KEY_SIZE_128 == 16, "OVPN_KEY_SIZE_128 should be 16");
  OVPN_TEST (OVPN_KEY_SIZE_256 == 32, "OVPN_KEY_SIZE_256 should be 32");
  OVPN_TEST (OVPN_KEY_SIZE_MAX == 32, "OVPN_KEY_SIZE_MAX should be 32");

  vlib_cli_output (vm, "Key sizes test PASSED\n");
  return 0;
}

/*
 * Test crypto context initialization
 */
static int
ovpn_test_crypto_context_init (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;
  int rv;

  vlib_cli_output (vm, "=== Test Crypto Context Init ===\n");

  /* Initialize key material */
  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;

  /* Fill with test data */
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }
  for (int i = 0; i < OVPN_IMPLICIT_IV_LEN; i++)
    {
      keys.encrypt_implicit_iv[i] = i + 0x10;
      keys.decrypt_implicit_iv[i] = i + 0x20;
    }

  /* Test successful initialization with AES-256-GCM */
  rv = ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 0);
  OVPN_TEST (rv == 0, "Context init with AES-256-GCM should succeed");
  OVPN_TEST (ctx.is_valid == 1, "Context should be valid");
  OVPN_TEST (ctx.cipher_alg == OVPN_CIPHER_ALG_AES_256_GCM,
	     "Cipher alg should be AES-256-GCM");
  OVPN_TEST (ctx.packet_id_send == 1, "Initial packet_id_send should be 1");
  OVPN_TEST (ctx.replay_packet_id_floor == 0, "Initial floor should be 0");
  OVPN_TEST (ctx.replay_bitmap == 0, "Initial bitmap should be 0");
  OVPN_TEST (ctx.replay_window_size == OVPN_REPLAY_WINDOW_SIZE_DEFAULT,
	     "Default window size should be %u", OVPN_REPLAY_WINDOW_SIZE_DEFAULT);
  OVPN_TEST (ctx.replay_bitmap_ext == NULL,
	     "Extended bitmap should be NULL for default window");

  /* Verify implicit IVs were copied */
  OVPN_TEST (clib_memcmp (ctx.encrypt_implicit_iv, keys.encrypt_implicit_iv,
			  OVPN_IMPLICIT_IV_LEN) == 0,
	     "Encrypt implicit IV should be copied");
  OVPN_TEST (clib_memcmp (ctx.decrypt_implicit_iv, keys.decrypt_implicit_iv,
			  OVPN_IMPLICIT_IV_LEN) == 0,
	     "Decrypt implicit IV should be copied");

  ovpn_crypto_context_free (&ctx);

  /* Test with NONE cipher - should fail */
  rv = ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_NONE, &keys, 0);
  OVPN_TEST (rv < 0, "Context init with NONE cipher should fail");

  /* Test with wrong key length */
  keys.key_len = 8; /* Wrong length for AES-256 */
  rv = ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 0);
  OVPN_TEST (rv < 0, "Context init with wrong key length should fail");

  /* Test AES-128-GCM */
  keys.key_len = OVPN_KEY_SIZE_128;
  rv = ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_128_GCM, &keys, 0);
  OVPN_TEST (rv == 0, "Context init with AES-128-GCM should succeed");
  OVPN_TEST (ctx.cipher_alg == OVPN_CIPHER_ALG_AES_128_GCM,
	     "Cipher alg should be AES-128-GCM");

  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm, "Crypto context init test PASSED\n");
  return 0;
}

/*
 * Test crypto context free
 */
static int
ovpn_test_crypto_context_free (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;

  vlib_cli_output (vm, "=== Test Crypto Context Free ===\n");

  /* Initialize key material */
  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }

  /* Initialize context */
  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 0);
  OVPN_TEST (ctx.is_valid == 1, "Context should be valid before free");

  /* Free context */
  ovpn_crypto_context_free (&ctx);
  OVPN_TEST (ctx.is_valid == 0, "Context should be invalid after free");

  /* Free again should be safe (is_valid check) */
  ovpn_crypto_context_free (&ctx);
  OVPN_TEST (ctx.is_valid == 0, "Double free should be safe");

  vlib_cli_output (vm, "Crypto context free test PASSED\n");
  return 0;
}

/*
 * Test replay protection with default window (64)
 */
static int
ovpn_test_replay_default_window (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;

  vlib_cli_output (vm, "=== Test Replay Protection (Default Window) ===\n");

  /* Initialize context */
  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }

  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 64);

  OVPN_TEST (ctx.replay_window_size == 64, "Window size should be 64");
  OVPN_TEST (ctx.replay_bitmap_ext == NULL,
	     "Extended bitmap should be NULL for 64-bit window");

  /* Packet ID 0 is always invalid */
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 0),
	     "Packet ID 0 should be rejected");

  /* First packet should be valid */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 1),
	     "Packet ID 1 should be valid");
  ovpn_crypto_update_replay (&ctx, 1);

  /* Replay should be detected */
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 1),
	     "Replay of packet ID 1 should be detected");

  /* Packet ahead of window should be valid */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 100),
	     "Packet ID 100 (ahead of window) should be valid");

  /* Out of order within window */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 2),
	     "Packet ID 2 should be valid");
  ovpn_crypto_update_replay (&ctx, 2);
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 2),
	     "Replay of packet ID 2 should be detected");

  /* Advance window significantly */
  ovpn_crypto_update_replay (&ctx, 100);
  OVPN_TEST (ctx.replay_packet_id_floor > 0, "Floor should have advanced");

  /* Old packet should now be rejected */
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 1),
	     "Old packet ID 1 should be rejected after window advance");

  /* Packet just inside new window should work */
  u32 new_valid_id = ctx.replay_packet_id_floor + 10;
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, new_valid_id),
	     "Packet at floor+10 should be valid");

  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm, "Replay protection (default window) test PASSED\n");
  return 0;
}

/*
 * Test replay protection with extended window (128)
 */
static int
ovpn_test_replay_extended_window (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;

  vlib_cli_output (vm, "=== Test Replay Protection (Extended Window 128) ===\n");

  /* Initialize context with larger window */
  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }

  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 128);

  OVPN_TEST (ctx.replay_window_size == 128, "Window size should be 128");
  OVPN_TEST (ctx.replay_bitmap_ext != NULL,
	     "Extended bitmap should be allocated");
  OVPN_TEST (vec_len (ctx.replay_bitmap_ext) == 2,
	     "Extended bitmap should have 2 words");

  /* Basic replay tests with extended window */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 1),
	     "Packet ID 1 should be valid");
  ovpn_crypto_update_replay (&ctx, 1);
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 1),
	     "Replay of packet ID 1 should be detected");

  /* Test packet in second 64-bit word */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 70),
	     "Packet ID 70 (in second word) should be valid");
  ovpn_crypto_update_replay (&ctx, 70);
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 70),
	     "Replay of packet ID 70 should be detected");

  /* Test packet at window boundary */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 127),
	     "Packet ID 127 (at window boundary) should be valid");
  ovpn_crypto_update_replay (&ctx, 127);

  /* Advance window */
  ovpn_crypto_update_replay (&ctx, 200);
  OVPN_TEST (ctx.replay_packet_id_floor > 0, "Floor should have advanced");

  /* Old packets should be rejected */
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 1),
	     "Old packet should be rejected after advance");

  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm,
		   "Replay protection (extended window 128) test PASSED\n");
  return 0;
}

/*
 * Test replay protection with large window (1024)
 */
static int
ovpn_test_replay_large_window (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;

  vlib_cli_output (vm, "=== Test Replay Protection (Large Window 1024) ===\n");

  /* Initialize context with large window */
  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }

  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 1024);

  OVPN_TEST (ctx.replay_window_size == 1024, "Window size should be 1024");
  OVPN_TEST (ctx.replay_bitmap_ext != NULL,
	     "Extended bitmap should be allocated");
  OVPN_TEST (vec_len (ctx.replay_bitmap_ext) == 16,
	     "Extended bitmap should have 16 words for 1024-bit window");

  /* Test packets across the large window */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 1), "Packet 1 should be valid");
  ovpn_crypto_update_replay (&ctx, 1);

  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 500),
	     "Packet 500 should be valid");
  ovpn_crypto_update_replay (&ctx, 500);

  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 1000),
	     "Packet 1000 should be valid");
  ovpn_crypto_update_replay (&ctx, 1000);

  /* Replays should be detected */
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 1),
	     "Replay of 1 should be detected");
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 500),
	     "Replay of 500 should be detected");
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 1000),
	     "Replay of 1000 should be detected");

  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm, "Replay protection (large window 1024) test PASSED\n");
  return 0;
}

/*
 * Test replay window size clamping
 */
static int
ovpn_test_replay_window_clamping (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;

  vlib_cli_output (vm, "=== Test Replay Window Size Clamping ===\n");

  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }

  /* Test minimum clamping */
  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 10);
  OVPN_TEST (ctx.replay_window_size >= OVPN_REPLAY_WINDOW_SIZE_MIN,
	     "Window size should be clamped to minimum");
  ovpn_crypto_context_free (&ctx);

  /* Test maximum clamping */
  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 100000);
  OVPN_TEST (ctx.replay_window_size <= OVPN_REPLAY_WINDOW_SIZE_MAX,
	     "Window size should be clamped to maximum");
  ovpn_crypto_context_free (&ctx);

  /* Test rounding to 64-bit boundary */
  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 100);
  OVPN_TEST (ctx.replay_window_size == 128,
	     "Window size 100 should round up to 128");
  ovpn_crypto_context_free (&ctx);

  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 65);
  OVPN_TEST (ctx.replay_window_size == 128,
	     "Window size 65 should round up to 128");
  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm, "Replay window size clamping test PASSED\n");
  return 0;
}

/*
 * Test static key setup
 */
static int
ovpn_test_static_key (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  u8 key[OVPN_KEY_SIZE_256];
  u8 iv[OVPN_IMPLICIT_IV_LEN];
  int rv;

  vlib_cli_output (vm, "=== Test Static Key Setup ===\n");

  /* Initialize test key and IV */
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    key[i] = i;
  for (int i = 0; i < OVPN_IMPLICIT_IV_LEN; i++)
    iv[i] = i + 0x30;

  /* Test static key setup */
  rv = ovpn_crypto_set_static_key (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, key,
				   OVPN_KEY_SIZE_256, iv);
  OVPN_TEST (rv == 0, "Static key setup should succeed");
  OVPN_TEST (ctx.is_valid == 1, "Context should be valid");
  OVPN_TEST (ctx.cipher_alg == OVPN_CIPHER_ALG_AES_256_GCM,
	     "Cipher should be AES-256-GCM");

  /* Verify IVs are set */
  OVPN_TEST (clib_memcmp (ctx.encrypt_implicit_iv, iv, OVPN_IMPLICIT_IV_LEN) ==
	       0,
	     "Encrypt IV should be set");
  OVPN_TEST (clib_memcmp (ctx.decrypt_implicit_iv, iv, OVPN_IMPLICIT_IV_LEN) ==
	       0,
	     "Decrypt IV should be set");

  ovpn_crypto_context_free (&ctx);

  /* Test static key without IV */
  rv = ovpn_crypto_set_static_key (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, key,
				   OVPN_KEY_SIZE_256, NULL);
  OVPN_TEST (rv == 0, "Static key setup without IV should succeed");

  ovpn_crypto_context_free (&ctx);

  /* Test with AES-128-GCM */
  rv = ovpn_crypto_set_static_key (&ctx, OVPN_CIPHER_ALG_AES_128_GCM, key,
				   OVPN_KEY_SIZE_128, iv);
  OVPN_TEST (rv == 0, "Static key setup with AES-128-GCM should succeed");
  OVPN_TEST (ctx.cipher_alg == OVPN_CIPHER_ALG_AES_128_GCM,
	     "Cipher should be AES-128-GCM");

  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm, "Static key setup test PASSED\n");
  return 0;
}

/*
 * Test packet ID counter
 */
static int
ovpn_test_packet_id_counter (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;
  u32 id1, id2, id3;

  vlib_cli_output (vm, "=== Test Packet ID Counter ===\n");

  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }

  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 0);

  /* Initial packet ID should be 1 */
  OVPN_TEST (ctx.packet_id_send == 1, "Initial packet_id_send should be 1");

  /* Get next packet IDs */
  id1 = ovpn_crypto_get_next_packet_id (&ctx);
  OVPN_TEST (id1 == 1, "First packet ID should be 1");

  id2 = ovpn_crypto_get_next_packet_id (&ctx);
  OVPN_TEST (id2 == 2, "Second packet ID should be 2");

  id3 = ovpn_crypto_get_next_packet_id (&ctx);
  OVPN_TEST (id3 == 3, "Third packet ID should be 3");

  /* Counter should have advanced */
  OVPN_TEST (ctx.packet_id_send == 4, "Counter should be at 4");

  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm, "Packet ID counter test PASSED\n");
  return 0;
}

/*
 * Test AEAD nonce construction
 */
static int
ovpn_test_aead_nonce (vlib_main_t *vm)
{
  ovpn_aead_nonce_t nonce;
  u8 implicit_iv[OVPN_IMPLICIT_IV_LEN] = { 0x01, 0x02, 0x03, 0x04,
					   0x05, 0x06, 0x07, 0x08 };
  u32 packet_id = 0x12345678;

  vlib_cli_output (vm, "=== Test AEAD Nonce Construction ===\n");

  /* Build nonce */
  ovpn_aead_nonce_build (&nonce, packet_id, implicit_iv);

  /* Nonce should be 12 bytes */
  OVPN_TEST (sizeof (nonce) == OVPN_NONCE_SIZE,
	     "Nonce size should be %u bytes", OVPN_NONCE_SIZE);

  /* First 4 bytes should be packet_id in network order */
  OVPN_TEST (nonce.packet_id == clib_host_to_net_u32 (packet_id),
	     "Nonce should start with packet_id in network order");

  /* Remaining 8 bytes should be implicit IV */
  OVPN_TEST (clib_memcmp (nonce.implicit_iv, implicit_iv, OVPN_IMPLICIT_IV_LEN) == 0,
	     "Nonce should contain implicit IV");

  /* Test with packet_id 0 */
  ovpn_aead_nonce_build (&nonce, 0, implicit_iv);
  OVPN_TEST (nonce.packet_id == 0, "Nonce with packet_id 0 should start with 0");

  /* Test with max packet_id */
  ovpn_aead_nonce_build (&nonce, 0xFFFFFFFF, implicit_iv);
  OVPN_TEST (nonce.packet_id == clib_host_to_net_u32 (0xFFFFFFFF),
	     "Nonce with max packet_id should work");

  vlib_cli_output (vm, "AEAD nonce construction test PASSED\n");
  return 0;
}

/*
 * Test crypto constants
 */
static int
ovpn_test_crypto_constants (vlib_main_t *vm)
{
  vlib_cli_output (vm, "=== Test Crypto Constants ===\n");

  /* Verify IV/nonce sizes */
  OVPN_TEST (OVPN_IV_SIZE == 16, "OVPN_IV_SIZE should be 16");
  OVPN_TEST (OVPN_NONCE_SIZE == 12, "OVPN_NONCE_SIZE should be 12");
  OVPN_TEST (OVPN_IMPLICIT_IV_LEN == 8, "OVPN_IMPLICIT_IV_LEN should be 8");

  /* Verify tag size */
  OVPN_TEST (OVPN_TAG_SIZE == 16, "OVPN_TAG_SIZE should be 16");

  /* Verify replay window constants */
  OVPN_TEST (OVPN_REPLAY_WINDOW_SIZE_DEFAULT == 64,
	     "Default window should be 64");
  OVPN_TEST (OVPN_REPLAY_WINDOW_SIZE_MIN == 64, "Min window should be 64");
  OVPN_TEST (OVPN_REPLAY_WINDOW_SIZE_MAX == 65536, "Max window should be 65536");

  /* Verify AEAD nonce structure */
  ovpn_aead_nonce_t nonce;
  OVPN_TEST (sizeof (nonce) == OVPN_NONCE_SIZE,
	     "ovpn_aead_nonce_t should be %u bytes", OVPN_NONCE_SIZE);

  /* Verify packet ID is 4 bytes + implicit IV is 8 bytes = 12 bytes */
  OVPN_TEST (4 + OVPN_IMPLICIT_IV_LEN == OVPN_NONCE_SIZE,
	     "packet_id + implicit_iv should equal nonce size");

  vlib_cli_output (vm, "Crypto constants test PASSED\n");
  return 0;
}

/*
 * Test replay edge cases
 */
static int
ovpn_test_replay_edge_cases (vlib_main_t *vm)
{
  ovpn_crypto_context_t ctx;
  ovpn_key_material_t keys;

  vlib_cli_output (vm, "=== Test Replay Edge Cases ===\n");

  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = OVPN_KEY_SIZE_256;
  for (int i = 0; i < OVPN_KEY_SIZE_256; i++)
    {
      keys.encrypt_key[i] = i;
      keys.decrypt_key[i] = i + 0x80;
    }

  ovpn_crypto_context_init (&ctx, OVPN_CIPHER_ALG_AES_256_GCM, &keys, 64);

  /* Test window floor exactly */
  ctx.replay_packet_id_floor = 100;
  ctx.replay_bitmap = 0;

  /* Packet at floor should be valid (not yet seen) */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 100),
	     "Packet at floor should be valid if not seen");

  /* Packet below floor should be rejected */
  OVPN_TEST (!ovpn_crypto_check_replay (&ctx, 99),
	     "Packet below floor should be rejected");

  /* Large jump ahead */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 1000000),
	     "Large packet ID should be valid");

  /* Process several packets to fill bitmap */
  for (u32 i = 100; i < 164; i++)
    {
      ovpn_crypto_update_replay (&ctx, i);
    }

  /* All processed packets should be replays */
  for (u32 i = 100; i < 164; i++)
    {
      OVPN_TEST (!ovpn_crypto_check_replay (&ctx, i),
		 "Processed packet %u should be replay", i);
    }

  /* Next packet should be valid */
  OVPN_TEST (ovpn_crypto_check_replay (&ctx, 164),
	     "Next packet after filled window should be valid");

  ovpn_crypto_context_free (&ctx);

  vlib_cli_output (vm, "Replay edge cases test PASSED\n");
  return 0;
}

/*
 * Run all crypto tests
 */
static int
ovpn_crypto_test_all (vlib_main_t *vm)
{
  int rv = 0;

  vlib_cli_output (vm, "\n========================================\n");
  vlib_cli_output (vm, "OpenVPN Crypto Unit Tests\n");
  vlib_cli_output (vm, "========================================\n\n");

  rv |= ovpn_test_cipher_alg_from_name (vm);
  rv |= ovpn_test_key_sizes (vm);
  rv |= ovpn_test_crypto_context_init (vm);
  rv |= ovpn_test_crypto_context_free (vm);
  rv |= ovpn_test_replay_default_window (vm);
  rv |= ovpn_test_replay_extended_window (vm);
  rv |= ovpn_test_replay_large_window (vm);
  rv |= ovpn_test_replay_window_clamping (vm);
  rv |= ovpn_test_static_key (vm);
  rv |= ovpn_test_packet_id_counter (vm);
  rv |= ovpn_test_aead_nonce (vm);
  rv |= ovpn_test_crypto_constants (vm);
  rv |= ovpn_test_replay_edge_cases (vm);

  vlib_cli_output (vm, "\n========================================\n");
  if (rv == 0)
    {
      vlib_cli_output (vm, "ALL TESTS PASSED\n");
    }
  else
    {
      vlib_cli_output (vm, "SOME TESTS FAILED\n");
    }
  vlib_cli_output (vm, "========================================\n");

  return rv;
}

/*
 * CLI command to run crypto tests
 */
static clib_error_t *
ovpn_crypto_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  int rv;

  rv = ovpn_crypto_test_all (vm);

  if (rv)
    return clib_error_return (0, "Tests failed");

  return 0;
}

VLIB_CLI_COMMAND (ovpn_crypto_test_command, static) = {
  .path = "test ovpn crypto",
  .short_help = "test ovpn crypto - run OpenVPN crypto unit tests",
  .function = ovpn_crypto_test_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
