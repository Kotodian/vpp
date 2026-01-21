/*
 * ovpn_tls_crypt_v2_test.c - OpenVPN TLS-Crypt-V2 unit tests
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
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_handshake.h>
#include <ovpn/ovpn_crypto.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

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
 * Sample OpenVPN static key in PEM format (for testing only)
 * This is a test key - DO NOT USE IN PRODUCTION
 */
static const char *test_static_key_pem =
  "-----BEGIN OpenVPN Static key V1-----\n"
  "00000000000000000000000000000001\n"
  "00000000000000000000000000000002\n"
  "00000000000000000000000000000003\n"
  "00000000000000000000000000000004\n"
  "00000000000000000000000000000005\n"
  "00000000000000000000000000000006\n"
  "00000000000000000000000000000007\n"
  "00000000000000000000000000000008\n"
  "00000000000000000000000000000009\n"
  "0000000000000000000000000000000a\n"
  "0000000000000000000000000000000b\n"
  "0000000000000000000000000000000c\n"
  "0000000000000000000000000000000d\n"
  "0000000000000000000000000000000e\n"
  "0000000000000000000000000000000f\n"
  "00000000000000000000000000000010\n"
  "-----END OpenVPN Static key V1-----\n";

/*
 * Test TLS-Crypt-V2 server key parsing
 */
static int
ovpn_test_tls_crypt_v2_parse_server_key (vlib_main_t *vm)
{
  ovpn_tls_crypt_v2_t ctx;
  int rv;

  vlib_cli_output (vm, "=== Test TLS-Crypt-V2 Server Key Parsing ===\n");

  clib_memset (&ctx, 0, sizeof (ctx));

  /* Test with valid PEM key */
  rv = ovpn_tls_crypt_v2_parse_server_key ((const u8 *) test_static_key_pem,
					   strlen (test_static_key_pem), &ctx);
  OVPN_TEST (rv == 0, "Should parse valid PEM key successfully");
  OVPN_TEST (ctx.enabled == 1, "Context should be enabled after parsing");

  /* Verify server key is populated (not all zeros) */
  int has_nonzero = 0;
  for (int i = 0; i < 32; i++)
    {
      if (ctx.server_key.encrypt_key[i] != 0 ||
	  ctx.server_key.auth_key[i] != 0)
	{
	  has_nonzero = 1;
	  break;
	}
    }
  OVPN_TEST (has_nonzero, "Server key should have non-zero values");

  /* Test with NULL parameters */
  rv = ovpn_tls_crypt_v2_parse_server_key (NULL, 0, &ctx);
  OVPN_TEST (rv < 0, "Should fail with NULL key data");

  rv = ovpn_tls_crypt_v2_parse_server_key ((const u8 *) test_static_key_pem,
					   strlen (test_static_key_pem), NULL);
  OVPN_TEST (rv < 0, "Should fail with NULL context");

  /* Test with too short key */
  rv = ovpn_tls_crypt_v2_parse_server_key ((const u8 *) "short", 5, &ctx);
  OVPN_TEST (rv < 0, "Should fail with too short key data");

  /* Test with invalid PEM format */
  const char *invalid_pem =
    "-----BEGIN INVALID-----\ndata\n-----END INVALID-----\n";
  rv = ovpn_tls_crypt_v2_parse_server_key ((const u8 *) invalid_pem,
					   strlen (invalid_pem), &ctx);
  OVPN_TEST (rv < 0, "Should fail with invalid PEM format");

  vlib_cli_output (vm, "TLS-Crypt-V2 server key parsing test PASSED\n");
  return 0;
}

/*
 * Test TLS-Crypt-V2 client key to TLS-Crypt conversion
 */
static int
ovpn_test_tls_crypt_v2_client_key_to_tls_crypt (vlib_main_t *vm)
{
  ovpn_tls_crypt_v2_client_key_t client_key;
  ovpn_tls_crypt_t tls_crypt;
  int rv;

  vlib_cli_output (vm, "=== Test TLS-Crypt-V2 Client Key Conversion ===\n");

  /* Initialize client key with test data */
  clib_memset (&client_key, 0, sizeof (client_key));
  for (int i = 0; i < 256; i++)
    {
      client_key.key[i] = (u8) (i & 0xff);
    }
  client_key.metadata = NULL;
  client_key.metadata_len = 0;

  clib_memset (&tls_crypt, 0, sizeof (tls_crypt));

  /* Test server mode conversion */
  rv = ovpn_tls_crypt_v2_client_key_to_tls_crypt (&client_key, &tls_crypt, 1);
  OVPN_TEST (rv == 0, "Should convert client key for server mode");
  OVPN_TEST (tls_crypt.enabled == 1, "TLS-Crypt should be enabled");
  OVPN_TEST (tls_crypt.packet_id_send == 1, "packet_id_send should be 1");

  /* Verify key material is set */
  int has_key = 0;
  for (int i = 0; i < 32; i++)
    {
      if (tls_crypt.encrypt_cipher_key[i] != 0 ||
	  tls_crypt.decrypt_cipher_key[i] != 0)
	{
	  has_key = 1;
	  break;
	}
    }
  OVPN_TEST (has_key, "Should have key material set");

  /* Test client mode conversion */
  clib_memset (&tls_crypt, 0, sizeof (tls_crypt));
  rv = ovpn_tls_crypt_v2_client_key_to_tls_crypt (&client_key, &tls_crypt, 0);
  OVPN_TEST (rv == 0, "Should convert client key for client mode");
  OVPN_TEST (tls_crypt.enabled == 1, "TLS-Crypt should be enabled");

  /* Test with NULL parameters */
  rv = ovpn_tls_crypt_v2_client_key_to_tls_crypt (NULL, &tls_crypt, 1);
  OVPN_TEST (rv < 0, "Should fail with NULL client key");

  rv = ovpn_tls_crypt_v2_client_key_to_tls_crypt (&client_key, NULL, 1);
  OVPN_TEST (rv < 0, "Should fail with NULL tls_crypt");

  vlib_cli_output (vm, "TLS-Crypt-V2 client key conversion test PASSED\n");
  return 0;
}

/*
 * Test TLS-Crypt-V2 WKc extraction
 */
static int
ovpn_test_tls_crypt_v2_extract_wkc (vlib_main_t *vm)
{
  int rv;
  const u8 *wkc;
  u32 wkc_len;
  u32 wrapped_len;

  vlib_cli_output (vm, "=== Test TLS-Crypt-V2 WKc Extraction ===\n");

  /*
   * Build a mock packet with WKc at the end
   * Format: [wrapped_packet_data] [WKc] [length(2 bytes)]
   * Minimum WKc size is 290 bytes (32 tag + 256 key + 2 length)
   *
   * The length field stores the WKc size WITHOUT the 2-byte length field.
   * So for a total WKc of 290 bytes, we encode 288 (290-2).
   */
  u8 mock_packet[400];
  clib_memset (mock_packet, 0x55, sizeof (mock_packet));

  /* Set WKc length at the end (288 in big-endian, for total 290 bytes) */
  u32 test_wkc_len_encoded = 288; /* WKc size excluding length field */
  u32 test_wkc_len_total = 290;	  /* Total WKc size including length field */
  mock_packet[398] = (test_wkc_len_encoded >> 8) & 0xff;
  mock_packet[399] = test_wkc_len_encoded & 0xff;

  /* Test extraction */
  rv = ovpn_tls_crypt_v2_extract_wkc (mock_packet, sizeof (mock_packet), &wkc,
				      &wkc_len, &wrapped_len);
  OVPN_TEST (rv == 0, "Should extract WKc successfully");
  OVPN_TEST (wkc_len == test_wkc_len_total, "WKc length should match (total)");
  OVPN_TEST (wrapped_len == sizeof (mock_packet) - test_wkc_len_total,
	     "Wrapped packet length should be correct");

  /* Test with NULL parameters */
  rv = ovpn_tls_crypt_v2_extract_wkc (NULL, 100, &wkc, &wkc_len, &wrapped_len);
  OVPN_TEST (rv < 0, "Should fail with NULL packet");

  rv = ovpn_tls_crypt_v2_extract_wkc (mock_packet, sizeof (mock_packet), NULL,
				      &wkc_len, &wrapped_len);
  OVPN_TEST (rv < 0, "Should fail with NULL wkc output");

  /* Test with packet too short */
  rv = ovpn_tls_crypt_v2_extract_wkc (mock_packet, 10, &wkc, &wkc_len,
				      &wrapped_len);
  OVPN_TEST (rv < 0, "Should fail with packet too short");

  /* Test with invalid WKc length (too large) */
  mock_packet[398] = 0x10; /* 4096+ */
  mock_packet[399] = 0x00;
  rv = ovpn_tls_crypt_v2_extract_wkc (mock_packet, sizeof (mock_packet), &wkc,
				      &wkc_len, &wrapped_len);
  OVPN_TEST (rv < 0, "Should fail with WKc length too large");

  /* Test with invalid WKc length (too small) */
  mock_packet[398] = 0x00;
  mock_packet[399] = 0x10; /* 16 bytes - too small */
  rv = ovpn_tls_crypt_v2_extract_wkc (mock_packet, sizeof (mock_packet), &wkc,
				      &wkc_len, &wrapped_len);
  OVPN_TEST (rv < 0, "Should fail with WKc length too small");

  vlib_cli_output (vm, "TLS-Crypt-V2 WKc extraction test PASSED\n");
  return 0;
}

static int
ovpn_test_tls_crypt_v2_unwrap_client_key (vlib_main_t *vm)
{
  vlib_cli_output (vm, "=== Test TLS-Crypt-V2 WKc unwrap (HMAC/len) ===\n");

  /* Build a deterministic server context */
  ovpn_tls_crypt_v2_t ctx;
  clib_memset (&ctx, 0, sizeof (ctx));
  ctx.enabled = 1;
  for (int i = 0; i < 32; i++)
    {
      ctx.server_key.encrypt_key[i] = (u8) (0x10 + i);
      ctx.server_key.auth_key[i] = (u8) (0x80 + i);
    }

  /*
   * Plaintext is client key (256) + metadata (16)
   */
  const u32 metadata_len = 16;
  const u32 plaintext_len = OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN + metadata_len;
  u8 plaintext[OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN + metadata_len];
  for (u32 i = 0; i < plaintext_len; i++)
    plaintext[i] = (u8) (i & 0xff);

  /*
   * WKc format:
   *   [tag:32] [ciphertext:plaintext_len] [len:2]
   *
   * The length field stores stored_len = tag+ciphertext length,
   * excluding the 2-byte length field itself.
   */
  const u16 stored_len = (u16) (OVPN_TLS_CRYPT_V2_TAG_SIZE + plaintext_len);
  const u32 wkc_len = (u32) stored_len + 2;

  u8 hmac_input[2 + sizeof (plaintext)];
  hmac_input[0] = (stored_len >> 8) & 0xff;
  hmac_input[1] = stored_len & 0xff;
  clib_memcpy_fast (hmac_input + 2, plaintext, plaintext_len);

  u8 tag[OVPN_TLS_CRYPT_V2_TAG_SIZE];
  unsigned int tag_len = 0;
  OVPN_TEST (HMAC (EVP_sha256 (), ctx.server_key.auth_key,
		   sizeof (ctx.server_key.auth_key), hmac_input,
		   2 + plaintext_len, tag, &tag_len) != NULL,
	     "HMAC() should succeed");
  OVPN_TEST (tag_len == OVPN_TLS_CRYPT_V2_TAG_SIZE,
	     "HMAC length should be 32");

  /* Ciphertext = AES-256-CTR(Ke, iv=tag[0:16], plaintext) */
  u8 ciphertext[sizeof (plaintext)];
  EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new ();
  OVPN_TEST (cctx != NULL, "EVP_CIPHER_CTX_new() should succeed");
  int outl = 0;
  int finl = 0;
  OVPN_TEST (EVP_EncryptInit_ex (cctx, EVP_aes_256_ctr (), NULL,
				 ctx.server_key.encrypt_key, tag) == 1,
	     "EVP_EncryptInit_ex(AES-256-CTR) should succeed");
  OVPN_TEST (
    EVP_EncryptUpdate (cctx, ciphertext, &outl, plaintext, plaintext_len) == 1,
    "EVP_EncryptUpdate() should succeed");
  OVPN_TEST (EVP_EncryptFinal_ex (cctx, ciphertext + outl, &finl) == 1,
	     "EVP_EncryptFinal_ex() should succeed");
  EVP_CIPHER_CTX_free (cctx);
  OVPN_TEST ((u32) (outl + finl) == plaintext_len,
	     "ciphertext length should equal plaintext length");

  /* Assemble WKc */
  u8 wkc[OVPN_TLS_CRYPT_V2_TAG_SIZE + sizeof (plaintext) + 2];
  clib_memcpy_fast (wkc, tag, OVPN_TLS_CRYPT_V2_TAG_SIZE);
  clib_memcpy_fast (wkc + OVPN_TLS_CRYPT_V2_TAG_SIZE, ciphertext,
		    plaintext_len);
  wkc[wkc_len - 2] = (stored_len >> 8) & 0xff;
  wkc[wkc_len - 1] = stored_len & 0xff;

  /* Unwrap should succeed */
  ovpn_tls_crypt_v2_client_key_t client_key;
  int rv =
    ovpn_tls_crypt_v2_unwrap_client_key (&ctx, wkc, wkc_len, &client_key);
  OVPN_TEST (rv == 0, "unwrap_client_key should succeed");
  OVPN_TEST (
    memcmp (client_key.key, plaintext, OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN) == 0,
    "client key bytes should match");
  OVPN_TEST (client_key.metadata_len == metadata_len,
	     "metadata length should match");
  OVPN_TEST (memcmp (client_key.metadata,
		     plaintext + OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN,
		     metadata_len) == 0,
	     "metadata bytes should match");
  ovpn_tls_crypt_v2_client_key_free (&client_key);

  /* Wrong length field should fail */
  u8 wkc_bad_len[sizeof (wkc)];
  clib_memcpy_fast (wkc_bad_len, wkc, wkc_len);
  wkc_bad_len[wkc_len - 2] = ((stored_len + 1) >> 8) & 0xff;
  wkc_bad_len[wkc_len - 1] = (stored_len + 1) & 0xff;
  rv = ovpn_tls_crypt_v2_unwrap_client_key (&ctx, wkc_bad_len, wkc_len,
					    &client_key);
  OVPN_TEST (rv < 0, "unwrap_client_key should fail with wrong length");

  /*
   * Wrong tag computation (using total_len instead of stored_len)
   * should fail HMAC verification.
   */
  const u16 wrong_len_prefix = (u16) wkc_len;
  hmac_input[0] = (wrong_len_prefix >> 8) & 0xff;
  hmac_input[1] = wrong_len_prefix & 0xff;
  clib_memcpy_fast (hmac_input + 2, plaintext, plaintext_len);

  u8 tag_wrong[OVPN_TLS_CRYPT_V2_TAG_SIZE];
  tag_len = 0;
  OVPN_TEST (HMAC (EVP_sha256 (), ctx.server_key.auth_key,
		   sizeof (ctx.server_key.auth_key), hmac_input,
		   2 + plaintext_len, tag_wrong, &tag_len) != NULL,
	     "HMAC() should succeed (wrong tag)");
  OVPN_TEST (tag_len == OVPN_TLS_CRYPT_V2_TAG_SIZE,
	     "wrong tag length should be 32");

  /* Encrypt with iv derived from tag_wrong so decryption yields the same
   * plaintext */
  cctx = EVP_CIPHER_CTX_new ();
  OVPN_TEST (cctx != NULL, "EVP_CIPHER_CTX_new() should succeed (wrong tag)");
  outl = finl = 0;
  OVPN_TEST (EVP_EncryptInit_ex (cctx, EVP_aes_256_ctr (), NULL,
				 ctx.server_key.encrypt_key, tag_wrong) == 1,
	     "EVP_EncryptInit_ex() should succeed (wrong tag)");
  OVPN_TEST (
    EVP_EncryptUpdate (cctx, ciphertext, &outl, plaintext, plaintext_len) == 1,
    "EVP_EncryptUpdate() should succeed (wrong tag)");
  OVPN_TEST (EVP_EncryptFinal_ex (cctx, ciphertext + outl, &finl) == 1,
	     "EVP_EncryptFinal_ex() should succeed (wrong tag)");
  EVP_CIPHER_CTX_free (cctx);

  u8 wkc_wrong_tag[sizeof (wkc)];
  clib_memcpy_fast (wkc_wrong_tag, tag_wrong, OVPN_TLS_CRYPT_V2_TAG_SIZE);
  clib_memcpy_fast (wkc_wrong_tag + OVPN_TLS_CRYPT_V2_TAG_SIZE, ciphertext,
		    plaintext_len);
  /* Keep the length field as stored_len (spec) */
  wkc_wrong_tag[wkc_len - 2] = (stored_len >> 8) & 0xff;
  wkc_wrong_tag[wkc_len - 1] = stored_len & 0xff;

  rv = ovpn_tls_crypt_v2_unwrap_client_key (&ctx, wkc_wrong_tag, wkc_len,
					    &client_key);
  OVPN_TEST (rv < 0, "unwrap_client_key should fail with wrong tag input");

  vlib_cli_output (vm, "TLS-Crypt-V2 WKc unwrap test PASSED\n");
  return 0;
}

/*
 * Test TLS-Crypt-V2 client key free
 */
static int
ovpn_test_tls_crypt_v2_client_key_free (vlib_main_t *vm)
{
  ovpn_tls_crypt_v2_client_key_t client_key;

  vlib_cli_output (vm, "=== Test TLS-Crypt-V2 Client Key Free ===\n");

  /* Initialize with test data */
  clib_memset (&client_key, 0xaa, sizeof (client_key));
  client_key.metadata = clib_mem_alloc (64);
  clib_memset (client_key.metadata, 0xbb, 64);
  client_key.metadata_len = 64;

  /* Free should not crash and should clear data */
  ovpn_tls_crypt_v2_client_key_free (&client_key);

  OVPN_TEST (client_key.metadata == NULL,
	     "Metadata should be NULL after free");
  OVPN_TEST (client_key.metadata_len == 0,
	     "Metadata length should be 0 after free");

  /* Key data should be zeroed */
  int all_zero = 1;
  for (int i = 0; i < 256; i++)
    {
      if (client_key.key[i] != 0)
	{
	  all_zero = 0;
	  break;
	}
    }
  OVPN_TEST (all_zero, "Key data should be zeroed after free");

  /* Test with NULL metadata (should not crash) */
  clib_memset (&client_key, 0, sizeof (client_key));
  client_key.metadata = NULL;
  ovpn_tls_crypt_v2_client_key_free (&client_key);
  OVPN_TEST (1, "Should handle NULL metadata without crash");

  vlib_cli_output (vm, "TLS-Crypt-V2 client key free test PASSED\n");
  return 0;
}

/*
 * Test TLS-Crypt-V2 structure sizes
 */
static int
ovpn_test_tls_crypt_v2_structures (vlib_main_t *vm)
{
  vlib_cli_output (vm, "=== Test TLS-Crypt-V2 Structure Sizes ===\n");

  OVPN_TEST (sizeof (ovpn_tls_crypt_v2_server_key_t) >= 64,
	     "Server key structure should be at least 64 bytes");

  OVPN_TEST (OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN == 256,
	     "Client key length should be 256 bytes");

  OVPN_TEST (OVPN_TLS_CRYPT_V2_TAG_SIZE == 32,
	     "Tag size should be 32 bytes (HMAC-SHA256)");

  OVPN_TEST (OVPN_TLS_CRYPT_V2_MIN_WKC_LEN == 290,
	     "Min WKc length should be 290 (tag+key+len)");

  OVPN_TEST (OVPN_TLS_CRYPT_V2_MAX_WKC_LEN == 1024,
	     "Max WKc length should be 1024");

  vlib_cli_output (vm, "TLS-Crypt-V2 structure sizes test PASSED\n");
  return 0;
}

/*
 * Main test command handler
 */
static clib_error_t *
ovpn_test_tls_crypt_v2_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  int failed = 0;

  vlib_cli_output (vm, "\n========================================\n");
  vlib_cli_output (vm, "OpenVPN TLS-Crypt-V2 Unit Tests\n");
  vlib_cli_output (vm, "========================================\n\n");

  if (ovpn_test_tls_crypt_v2_structures (vm))
    failed++;
  if (ovpn_test_tls_crypt_v2_parse_server_key (vm))
    failed++;
  if (ovpn_test_tls_crypt_v2_client_key_to_tls_crypt (vm))
    failed++;
  if (ovpn_test_tls_crypt_v2_extract_wkc (vm))
    failed++;
  if (ovpn_test_tls_crypt_v2_unwrap_client_key (vm))
    failed++;
  if (ovpn_test_tls_crypt_v2_client_key_free (vm))
    failed++;

  vlib_cli_output (vm, "\n========================================\n");
  if (failed)
    vlib_cli_output (vm, "%d TEST(S) FAILED\n", failed);
  else
    vlib_cli_output (vm, "ALL TESTS PASSED\n");
  vlib_cli_output (vm, "========================================\n\n");

  return NULL;
}

VLIB_CLI_COMMAND (ovpn_test_tls_crypt_v2_command, static) = {
  .path = "test ovpn tls-crypt-v2",
  .short_help = "test ovpn tls-crypt-v2",
  .function = ovpn_test_tls_crypt_v2_command_fn,
};
