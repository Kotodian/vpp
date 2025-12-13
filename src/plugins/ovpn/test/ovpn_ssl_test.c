/*
 * ovpn_ssl_test.c - OpenVPN SSL/key derivation unit tests
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
#include <ovpn/ovpn_ssl.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_session_id.h>

/*
 * Test macros (same as reliable test)
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
 * Helper to check if buffer is all zeros
 */
static int
is_all_zeros (const u8 *buf, u32 len)
{
  for (u32 i = 0; i < len; i++)
    {
      if (buf[i] != 0)
	return 0;
    }
  return 1;
}

/*
 * Helper to check if two buffers are equal
 */
static int
buffers_equal (const u8 *a, const u8 *b, u32 len)
{
  return clib_memcmp (a, b, len) == 0;
}

/*
 * Test ovpn_prf() function
 */
static int
ovpn_test_prf (vlib_main_t *vm)
{
  u8 secret[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
  u8 seed1[8] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
  u8 seed2[8] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
  u8 output1[32];
  u8 output2[32];
  int rv;

  vlib_cli_output (vm, "=== Test PRF ===\n");

  /* Test with valid parameters */
  clib_memset (output1, 0, sizeof (output1));
  rv = ovpn_prf (secret, sizeof (secret), "test label", seed1, sizeof (seed1),
		 NULL, 0, NULL, 0, NULL, 0, output1, sizeof (output1));
  OVPN_TEST (rv == 0, "PRF should succeed with valid params");
  OVPN_TEST (!is_all_zeros (output1, sizeof (output1)),
	     "PRF output should not be all zeros");

  /* Same inputs should produce same output (deterministic) */
  clib_memset (output2, 0, sizeof (output2));
  rv = ovpn_prf (secret, sizeof (secret), "test label", seed1, sizeof (seed1),
		 NULL, 0, NULL, 0, NULL, 0, output2, sizeof (output2));
  OVPN_TEST (rv == 0, "PRF should succeed again");
  OVPN_TEST (buffers_equal (output1, output2, sizeof (output1)),
	     "Same inputs should produce same output");

  /* Different label should produce different output */
  clib_memset (output2, 0, sizeof (output2));
  rv = ovpn_prf (secret, sizeof (secret), "different label", seed1,
		 sizeof (seed1), NULL, 0, NULL, 0, NULL, 0, output2,
		 sizeof (output2));
  OVPN_TEST (rv == 0, "PRF with different label should succeed");
  OVPN_TEST (!buffers_equal (output1, output2, sizeof (output1)),
	     "Different label should produce different output");

  /* Different seed should produce different output */
  clib_memset (output2, 0, sizeof (output2));
  rv = ovpn_prf (secret, sizeof (secret), "test label", seed2, sizeof (seed2),
		 NULL, 0, NULL, 0, NULL, 0, output2, sizeof (output2));
  OVPN_TEST (rv == 0, "PRF with different seed should succeed");
  OVPN_TEST (!buffers_equal (output1, output2, sizeof (output1)),
	     "Different seed should produce different output");

  /* Test with multiple seeds */
  clib_memset (output1, 0, sizeof (output1));
  rv = ovpn_prf (secret, sizeof (secret), "multi seed", seed1, sizeof (seed1),
		 seed2, sizeof (seed2), NULL, 0, NULL, 0, output1,
		 sizeof (output1));
  OVPN_TEST (rv == 0, "PRF with two seeds should succeed");
  OVPN_TEST (!is_all_zeros (output1, sizeof (output1)),
	     "PRF with two seeds should produce non-zero output");

  /* Test with NULL parameters - should fail */
  rv = ovpn_prf (NULL, 0, "test", seed1, sizeof (seed1), NULL, 0, NULL, 0,
		 NULL, 0, output1, sizeof (output1));
  OVPN_TEST (rv < 0, "PRF should fail with NULL secret");

  rv = ovpn_prf (secret, sizeof (secret), NULL, seed1, sizeof (seed1), NULL, 0,
		 NULL, 0, NULL, 0, output1, sizeof (output1));
  OVPN_TEST (rv < 0, "PRF should fail with NULL label");

  rv = ovpn_prf (secret, sizeof (secret), "test", NULL, 0, NULL, 0, NULL, 0,
		 NULL, 0, output1, sizeof (output1));
  OVPN_TEST (rv < 0, "PRF should fail with NULL seed1");

  vlib_cli_output (vm, "PRF test PASSED\n");
  return 0;
}

/*
 * Test ovpn_key_source_randomize()
 */
static int
ovpn_test_key_source_randomize (vlib_main_t *vm)
{
  ovpn_key_source_t ks1, ks2;
  int rv;

  vlib_cli_output (vm, "=== Test Key Source Randomize ===\n");

  /* Test without pre_master */
  clib_memset (&ks1, 0, sizeof (ks1));
  rv = ovpn_key_source_randomize (&ks1, 0 /* no pre_master */);
  OVPN_TEST (rv == 0, "Key source randomize should succeed");
  OVPN_TEST (!is_all_zeros (ks1.random1, OVPN_RANDOM_SIZE),
	     "random1 should not be zeros");
  OVPN_TEST (!is_all_zeros (ks1.random2, OVPN_RANDOM_SIZE),
	     "random2 should not be zeros");
  /* pre_master should remain zeros */
  OVPN_TEST (is_all_zeros (ks1.pre_master, OVPN_PRE_MASTER_SIZE),
	     "pre_master should still be zeros");

  /* Test with pre_master (client mode) */
  clib_memset (&ks2, 0, sizeof (ks2));
  rv = ovpn_key_source_randomize (&ks2, 1 /* include pre_master */);
  OVPN_TEST (rv == 0, "Key source randomize with pre_master should succeed");
  OVPN_TEST (!is_all_zeros (ks2.pre_master, OVPN_PRE_MASTER_SIZE),
	     "pre_master should not be zeros");
  OVPN_TEST (!is_all_zeros (ks2.random1, OVPN_RANDOM_SIZE),
	     "random1 should not be zeros");
  OVPN_TEST (!is_all_zeros (ks2.random2, OVPN_RANDOM_SIZE),
	     "random2 should not be zeros");

  /* Two randomizations should produce different values */
  OVPN_TEST (!buffers_equal (ks1.random1, ks2.random1, OVPN_RANDOM_SIZE),
	     "Two randomizations should produce different random1");

  /* Test NULL parameter */
  rv = ovpn_key_source_randomize (NULL, 0);
  OVPN_TEST (rv < 0, "Should fail with NULL key source");

  vlib_cli_output (vm, "Key source randomize test PASSED\n");
  return 0;
}

/*
 * Test ovpn_key_source2_alloc/free
 */
static int
ovpn_test_key_source2_alloc (vlib_main_t *vm)
{
  ovpn_key_source2_t *ks2;

  vlib_cli_output (vm, "=== Test Key Source2 Alloc/Free ===\n");

  /* Allocate */
  ks2 = ovpn_key_source2_alloc ();
  OVPN_TEST (ks2 != NULL, "Key source2 allocation should succeed");

  /* Should be zero-initialized */
  OVPN_TEST (is_all_zeros ((u8 *) &ks2->client, sizeof (ks2->client)),
	     "Client portion should be zeros");
  OVPN_TEST (is_all_zeros ((u8 *) &ks2->server, sizeof (ks2->server)),
	     "Server portion should be zeros");

  /* Free */
  ovpn_key_source2_free (ks2);

  vlib_cli_output (vm, "Key source2 alloc/free test PASSED\n");
  return 0;
}

/*
 * Test ovpn_key_method_2_write() and ovpn_key_method_2_read() round-trip
 */
static int
ovpn_test_key_method_2_roundtrip (vlib_main_t *vm)
{
  ovpn_key_source2_t *ks2_client, *ks2_server;
  ovpn_session_id_t client_sid, server_sid;
  u8 client_buf[512], server_buf[512];
  char *options_out = NULL;
  int client_len, server_len, rv;

  vlib_cli_output (vm, "=== Test Key Method 2 Round-trip ===\n");

  /* Allocate key sources */
  ks2_client = ovpn_key_source2_alloc ();
  ks2_server = ovpn_key_source2_alloc ();
  OVPN_TEST (ks2_client != NULL && ks2_server != NULL,
	     "Key source allocation should succeed");

  /* Generate session IDs */
  ovpn_session_id_generate (&client_sid);
  ovpn_session_id_generate (&server_sid);

  /* Client writes (includes pre_master) */
  client_len = ovpn_key_method_2_write (client_buf, sizeof (client_buf),
					ks2_client, client_sid.id,
					0 /* is_server=0 */, "V4,cipher");
  OVPN_TEST (client_len > 0, "Client write should succeed, len=%d",
	     client_len);

  /* Verify client buffer has pre_master + randoms */
  OVPN_TEST (!is_all_zeros (ks2_client->client.pre_master, OVPN_PRE_MASTER_SIZE),
	     "Client pre_master should be set");
  OVPN_TEST (!is_all_zeros (ks2_client->client.random1, OVPN_RANDOM_SIZE),
	     "Client random1 should be set");
  OVPN_TEST (!is_all_zeros (ks2_client->client.random2, OVPN_RANDOM_SIZE),
	     "Client random2 should be set");

  /* Server reads client data */
  rv = ovpn_key_method_2_read (client_buf, client_len, ks2_server,
			       1 /* is_server=1 */, &options_out);
  OVPN_TEST (rv > 0, "Server read of client data should succeed");

  /* Verify server received client's random material */
  OVPN_TEST (buffers_equal (ks2_server->client.pre_master,
			    ks2_client->client.pre_master, OVPN_PRE_MASTER_SIZE),
	     "Server should have client's pre_master");
  OVPN_TEST (buffers_equal (ks2_server->client.random1,
			    ks2_client->client.random1, OVPN_RANDOM_SIZE),
	     "Server should have client's random1");
  OVPN_TEST (buffers_equal (ks2_server->client.random2,
			    ks2_client->client.random2, OVPN_RANDOM_SIZE),
	     "Server should have client's random2");

  if (options_out)
    clib_mem_free (options_out);
  options_out = NULL;

  /* Server writes (no pre_master) */
  server_len = ovpn_key_method_2_write (server_buf, sizeof (server_buf),
					ks2_server, server_sid.id,
					1 /* is_server=1 */, "V4,cipher");
  OVPN_TEST (server_len > 0, "Server write should succeed, len=%d",
	     server_len);
  OVPN_TEST (server_len < client_len,
	     "Server write should be shorter (no pre_master)");

  /* Verify server buffer has randoms */
  OVPN_TEST (!is_all_zeros (ks2_server->server.random1, OVPN_RANDOM_SIZE),
	     "Server random1 should be set");
  OVPN_TEST (!is_all_zeros (ks2_server->server.random2, OVPN_RANDOM_SIZE),
	     "Server random2 should be set");

  /* Client reads server data */
  rv = ovpn_key_method_2_read (server_buf, server_len, ks2_client,
			       0 /* is_server=0 */, &options_out);
  OVPN_TEST (rv > 0, "Client read of server data should succeed");

  /* Verify client received server's random material */
  OVPN_TEST (buffers_equal (ks2_client->server.random1,
			    ks2_server->server.random1, OVPN_RANDOM_SIZE),
	     "Client should have server's random1");
  OVPN_TEST (buffers_equal (ks2_client->server.random2,
			    ks2_server->server.random2, OVPN_RANDOM_SIZE),
	     "Client should have server's random2");

  if (options_out)
    clib_mem_free (options_out);

  /* Clean up */
  ovpn_key_source2_free (ks2_client);
  ovpn_key_source2_free (ks2_server);

  vlib_cli_output (vm, "Key Method 2 round-trip test PASSED\n");
  return 0;
}

/*
 * Test ovpn_generate_key_expansion_prf()
 */
static int
ovpn_test_key_expansion_prf (vlib_main_t *vm)
{
  ovpn_key_source2_t *ks2;
  ovpn_key2_t key2_server, key2_client;
  ovpn_session_id_t client_sid, server_sid;
  int rv;

  vlib_cli_output (vm, "=== Test Key Expansion PRF ===\n");

  /* Allocate and populate key source */
  ks2 = ovpn_key_source2_alloc ();
  OVPN_TEST (ks2 != NULL, "Key source allocation should succeed");

  /* Generate random material for both sides */
  rv = ovpn_key_source_randomize (&ks2->client, 1 /* include pre_master */);
  OVPN_TEST (rv == 0, "Client key source randomize should succeed");
  rv = ovpn_key_source_randomize (&ks2->server, 0 /* no pre_master */);
  OVPN_TEST (rv == 0, "Server key source randomize should succeed");

  /* Generate session IDs */
  ovpn_session_id_generate (&client_sid);
  ovpn_session_id_generate (&server_sid);

  /* Generate key expansion - server side */
  rv = ovpn_generate_key_expansion_prf (ks2, client_sid.id, server_sid.id,
					1 /* is_server */, &key2_server);
  OVPN_TEST (rv == 0, "Server key expansion should succeed");
  OVPN_TEST (key2_server.n == 2, "Should have 2 keys");
  OVPN_TEST (!is_all_zeros (key2_server.keys[0].cipher, 32),
	     "keys[0].cipher should not be zeros");
  OVPN_TEST (!is_all_zeros (key2_server.keys[1].cipher, 32),
	     "keys[1].cipher should not be zeros");

  /* Generate key expansion - client side with same source */
  rv = ovpn_generate_key_expansion_prf (ks2, client_sid.id, server_sid.id,
					0 /* is_server */, &key2_client);
  OVPN_TEST (rv == 0, "Client key expansion should succeed");
  OVPN_TEST (key2_client.n == 2, "Should have 2 keys");

  /* Server and client should derive the same key material */
  OVPN_TEST (buffers_equal ((u8 *) &key2_server.keys, (u8 *) &key2_client.keys,
			    sizeof (key2_server.keys)),
	     "Server and client should derive same keys");

  /* Test NULL parameters */
  rv = ovpn_generate_key_expansion_prf (NULL, client_sid.id, server_sid.id, 1,
					&key2_server);
  OVPN_TEST (rv < 0, "Should fail with NULL key source");

  rv = ovpn_generate_key_expansion_prf (ks2, client_sid.id, server_sid.id, 1,
					NULL);
  OVPN_TEST (rv < 0, "Should fail with NULL key2 output");

  /* Clean up */
  ovpn_key_source2_free (ks2);

  vlib_cli_output (vm, "Key expansion PRF test PASSED\n");
  return 0;
}

/*
 * Test ovpn_derive_data_channel_keys_v2() with PRF method
 */
static int
ovpn_test_derive_data_channel_keys (vlib_main_t *vm)
{
  ovpn_key_source2_t *ks2;
  ovpn_key_material_t server_keys, client_keys;
  ovpn_session_id_t client_sid, server_sid;
  int rv;

  vlib_cli_output (vm, "=== Test Derive Data Channel Keys ===\n");

  /* Allocate and populate key source */
  ks2 = ovpn_key_source2_alloc ();
  OVPN_TEST (ks2 != NULL, "Key source allocation should succeed");

  /* Generate random material for both sides */
  rv = ovpn_key_source_randomize (&ks2->client, 1 /* include pre_master */);
  OVPN_TEST (rv == 0, "Client key source randomize should succeed");
  rv = ovpn_key_source_randomize (&ks2->server, 0 /* no pre_master */);
  OVPN_TEST (rv == 0, "Server key source randomize should succeed");

  /* Generate session IDs */
  ovpn_session_id_generate (&client_sid);
  ovpn_session_id_generate (&server_sid);

  /* Derive keys for server (AES-256-GCM) */
  rv = ovpn_derive_data_channel_keys_v2 (NULL /* no TLS */, ks2, client_sid.id,
					 server_sid.id, &server_keys,
					 OVPN_CIPHER_ALG_AES_256_GCM,
					 1 /* is_server */, 0 /* use_prf */);
  OVPN_TEST (rv == 0, "Server key derivation should succeed");
  OVPN_TEST (server_keys.key_len == OVPN_KEY_SIZE_256,
	     "Key length should be 32 for AES-256-GCM");
  OVPN_TEST (!is_all_zeros (server_keys.encrypt_key, server_keys.key_len),
	     "Server encrypt_key should not be zeros");
  OVPN_TEST (!is_all_zeros (server_keys.decrypt_key, server_keys.key_len),
	     "Server decrypt_key should not be zeros");

  /* Derive keys for client (AES-256-GCM) */
  rv = ovpn_derive_data_channel_keys_v2 (NULL /* no TLS */, ks2, client_sid.id,
					 server_sid.id, &client_keys,
					 OVPN_CIPHER_ALG_AES_256_GCM,
					 0 /* is_server */, 0 /* use_prf */);
  OVPN_TEST (rv == 0, "Client key derivation should succeed");
  OVPN_TEST (client_keys.key_len == OVPN_KEY_SIZE_256,
	     "Key length should be 32 for AES-256-GCM");

  /*
   * Server's encrypt key should equal client's decrypt key
   * Server's decrypt key should equal client's encrypt key
   */
  OVPN_TEST (buffers_equal (server_keys.encrypt_key, client_keys.decrypt_key,
			    server_keys.key_len),
	     "Server encrypt = Client decrypt");
  OVPN_TEST (buffers_equal (server_keys.decrypt_key, client_keys.encrypt_key,
			    server_keys.key_len),
	     "Server decrypt = Client encrypt");

  /* Test with AES-128-GCM */
  rv = ovpn_derive_data_channel_keys_v2 (NULL, ks2, client_sid.id,
					 server_sid.id, &server_keys,
					 OVPN_CIPHER_ALG_AES_128_GCM,
					 1 /* is_server */, 0);
  OVPN_TEST (rv == 0, "Key derivation with AES-128-GCM should succeed");
  OVPN_TEST (server_keys.key_len == OVPN_KEY_SIZE_128,
	     "Key length should be 16 for AES-128-GCM");

  /* Test with invalid cipher */
  rv = ovpn_derive_data_channel_keys_v2 (NULL, ks2, client_sid.id,
					 server_sid.id, &server_keys,
					 OVPN_CIPHER_ALG_NONE, 1, 0);
  OVPN_TEST (rv < 0, "Should fail with NONE cipher");

  /* Clean up */
  ovpn_key_source2_free (ks2);

  vlib_cli_output (vm, "Derive data channel keys test PASSED\n");
  return 0;
}

/*
 * Test key method write with buffer boundary conditions
 */
static int
ovpn_test_key_method_buffer_boundaries (vlib_main_t *vm)
{
  ovpn_key_source2_t *ks2;
  ovpn_session_id_t sid;
  u8 tiny_buf[10];
  int rv;

  vlib_cli_output (vm, "=== Test Key Method Buffer Boundaries ===\n");

  ks2 = ovpn_key_source2_alloc ();
  OVPN_TEST (ks2 != NULL, "Key source allocation should succeed");

  ovpn_session_id_generate (&sid);

  /* Client write needs minimum: 4 + 1 + 48 + 32 + 32 = 117 bytes */
  rv = ovpn_key_method_2_write (tiny_buf, sizeof (tiny_buf), ks2, sid.id,
				0 /* client */, NULL);
  OVPN_TEST (rv < 0, "Client write should fail with tiny buffer");

  /* Server write needs minimum: 4 + 1 + 32 + 32 = 69 bytes */
  rv = ovpn_key_method_2_write (tiny_buf, sizeof (tiny_buf), ks2, sid.id,
				1 /* server */, NULL);
  OVPN_TEST (rv < 0, "Server write should fail with tiny buffer");

  /* Test NULL parameters */
  rv = ovpn_key_method_2_write (NULL, 512, ks2, sid.id, 0, NULL);
  OVPN_TEST (rv < 0, "Should fail with NULL buffer");

  rv = ovpn_key_method_2_write (tiny_buf, sizeof (tiny_buf), NULL, sid.id, 0,
				NULL);
  OVPN_TEST (rv < 0, "Should fail with NULL key source");

  ovpn_key_source2_free (ks2);

  vlib_cli_output (vm, "Key method buffer boundaries test PASSED\n");
  return 0;
}

/*
 * Test key method read with invalid data
 */
static int
ovpn_test_key_method_read_invalid (vlib_main_t *vm)
{
  ovpn_key_source2_t *ks2;
  u8 invalid_buf[128];
  int rv;

  vlib_cli_output (vm, "=== Test Key Method Read Invalid ===\n");

  ks2 = ovpn_key_source2_alloc ();
  OVPN_TEST (ks2 != NULL, "Key source allocation should succeed");

  /* Buffer too small */
  clib_memset (invalid_buf, 0, sizeof (invalid_buf));
  rv = ovpn_key_method_2_read (invalid_buf, 10, ks2, 1 /* server */, NULL);
  OVPN_TEST (rv < 0, "Should fail with too small buffer");

  /* Wrong key method */
  clib_memset (invalid_buf, 0, sizeof (invalid_buf));
  invalid_buf[4] = 1; /* Key method 1 instead of 2 */
  rv = ovpn_key_method_2_read (invalid_buf, sizeof (invalid_buf), ks2, 1,
			       NULL);
  OVPN_TEST (rv < 0, "Should fail with wrong key method");

  /* NULL parameters */
  rv = ovpn_key_method_2_read (NULL, sizeof (invalid_buf), ks2, 1, NULL);
  OVPN_TEST (rv < 0, "Should fail with NULL buffer");

  rv = ovpn_key_method_2_read (invalid_buf, sizeof (invalid_buf), NULL, 1,
			       NULL);
  OVPN_TEST (rv < 0, "Should fail with NULL key source");

  ovpn_key_source2_free (ks2);

  vlib_cli_output (vm, "Key method read invalid test PASSED\n");
  return 0;
}

/*
 * Run all tests
 */
static int
ovpn_ssl_test_all (vlib_main_t *vm)
{
  int rv = 0;

  vlib_cli_output (vm, "\n========================================\n");
  vlib_cli_output (vm, "OpenVPN SSL/Key Derivation Unit Tests\n");
  vlib_cli_output (vm, "========================================\n\n");

  rv |= ovpn_test_prf (vm);
  rv |= ovpn_test_key_source_randomize (vm);
  rv |= ovpn_test_key_source2_alloc (vm);
  rv |= ovpn_test_key_method_2_roundtrip (vm);
  rv |= ovpn_test_key_expansion_prf (vm);
  rv |= ovpn_test_derive_data_channel_keys (vm);
  rv |= ovpn_test_key_method_buffer_boundaries (vm);
  rv |= ovpn_test_key_method_read_invalid (vm);

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
 * CLI command to run tests
 */
static clib_error_t *
ovpn_ssl_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  int rv;

  rv = ovpn_ssl_test_all (vm);

  if (rv)
    return clib_error_return (0, "Tests failed");

  return 0;
}

VLIB_CLI_COMMAND (ovpn_ssl_test_command, static) = {
  .path = "test ovpn ssl",
  .short_help = "test ovpn ssl - run OpenVPN SSL/key derivation unit tests",
  .function = ovpn_ssl_test_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
