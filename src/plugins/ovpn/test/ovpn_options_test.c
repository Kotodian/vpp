/*
 * ovpn_options_test.c - OpenVPN options unit tests
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
#include <ovpn/ovpn_options.h>
#include <vnet/ip/ip.h>

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
 * Test push options
 */
static int
ovpn_test_push_options (vlib_main_t *vm)
{
  ovpn_options_t opts;
  int rv;

  vlib_cli_output (vm, "=== Test Push Options ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Test adding push options */
  rv = ovpn_options_add_push (&opts, "route 10.0.0.0 255.0.0.0");
  OVPN_TEST (rv == 0, "Adding first push option should succeed");
  OVPN_TEST (opts.n_push_options == 1, "Should have 1 push option");

  rv = ovpn_options_add_push (&opts, "dhcp-option DNS 8.8.8.8");
  OVPN_TEST (rv == 0, "Adding second push option should succeed");
  OVPN_TEST (opts.n_push_options == 2, "Should have 2 push options");

  rv = ovpn_options_add_push (&opts, "redirect-gateway def1");
  OVPN_TEST (rv == 0, "Adding third push option should succeed");
  OVPN_TEST (opts.n_push_options == 3, "Should have 3 push options");

  /* Verify content */
  OVPN_TEST (
    strcmp ((char *) opts.push_options[0], "route 10.0.0.0 255.0.0.0") == 0,
    "First push option content should match");
  OVPN_TEST (
    strcmp ((char *) opts.push_options[1], "dhcp-option DNS 8.8.8.8") == 0,
    "Second push option content should match");
  OVPN_TEST (strcmp ((char *) opts.push_options[2], "redirect-gateway def1") ==
	       0,
	     "Third push option content should match");

  /* Test NULL inputs */
  rv = ovpn_options_add_push (NULL, "test");
  OVPN_TEST (rv == -1, "NULL opts should return -1");

  rv = ovpn_options_add_push (&opts, NULL);
  OVPN_TEST (rv == -1, "NULL option should return -1");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);
  OVPN_TEST (opts.n_push_options == 0, "After cleanup, should have 0 options");

  vlib_cli_output (vm, "Push options test PASSED\n");
  return 0;
}

/*
 * Test DHCP options
 */
static int
ovpn_test_dhcp_options (vlib_main_t *vm)
{
  ovpn_options_t opts;
  ip_address_t dns_ip;
  int rv;

  vlib_cli_output (vm, "=== Test DHCP Options ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Test adding DNS server */
  ip4_address_t dns4 = { .as_u8 = { 8, 8, 8, 8 } };
  ip_address_set (&dns_ip, &dns4, AF_IP4);

  rv = ovpn_options_add_dns (&opts, &dns_ip);
  OVPN_TEST (rv == 0, "Adding DNS server should succeed");
  OVPN_TEST (opts.n_dhcp_options == 1, "Should have 1 DHCP option");
  OVPN_TEST (opts.dhcp_options[0].type == OVPN_DHCP_OPTION_DNS,
	     "Option type should be DNS");

  /* Test adding another DNS */
  dns4.as_u8[3] = 4; /* 8.8.8.4 */
  ip_address_set (&dns_ip, &dns4, AF_IP4);
  rv = ovpn_options_add_dns (&opts, &dns_ip);
  OVPN_TEST (rv == 0, "Adding second DNS server should succeed");
  OVPN_TEST (opts.n_dhcp_options == 2, "Should have 2 DHCP options");

  /* Test adding domain */
  rv = ovpn_options_set_domain (&opts, "example.com");
  OVPN_TEST (rv == 0, "Setting domain should succeed");
  OVPN_TEST (opts.n_dhcp_options == 3, "Should have 3 DHCP options");
  OVPN_TEST (opts.dhcp_options[2].type == OVPN_DHCP_OPTION_DOMAIN,
	     "Option type should be DOMAIN");
  OVPN_TEST (strcmp ((char *) opts.dhcp_options[2].string, "example.com") == 0,
	     "Domain should match");

  /* Test WINS */
  ip4_address_t wins4 = { .as_u8 = { 192, 168, 1, 1 } };
  ip_address_t wins_ip;
  ip_address_set (&wins_ip, &wins4, AF_IP4);
  rv = ovpn_options_add_dhcp_option (&opts, OVPN_DHCP_OPTION_WINS, &wins_ip);
  OVPN_TEST (rv == 0, "Adding WINS should succeed");
  OVPN_TEST (opts.n_dhcp_options == 4, "Should have 4 DHCP options");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);
  OVPN_TEST (opts.n_dhcp_options == 0, "After cleanup, should have 0 options");

  vlib_cli_output (vm, "DHCP options test PASSED\n");
  return 0;
}

/*
 * Test data ciphers
 */
static int
ovpn_test_data_ciphers (vlib_main_t *vm)
{
  ovpn_options_t opts;
  int rv;

  vlib_cli_output (vm, "=== Test Data Ciphers ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Test adding individual ciphers */
  rv = ovpn_options_add_data_cipher (&opts, "AES-256-GCM");
  OVPN_TEST (rv == 0, "Adding AES-256-GCM should succeed");
  OVPN_TEST (opts.n_data_ciphers == 1, "Should have 1 cipher");
  OVPN_TEST (strcmp ((char *) opts.data_ciphers[0], "AES-256-GCM") == 0,
	     "Cipher name should match");

  rv = ovpn_options_add_data_cipher (&opts, "AES-128-GCM");
  OVPN_TEST (rv == 0, "Adding AES-128-GCM should succeed");
  OVPN_TEST (opts.n_data_ciphers == 2, "Should have 2 ciphers");

  /* Clean up for next test */
  ovpn_options_free_dynamic (&opts);

  /* Test setting ciphers from string (colon-separated) */
  clib_memset (&opts, 0, sizeof (opts));
  rv = ovpn_options_set_data_ciphers (
    &opts, "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305");
  OVPN_TEST (rv == 0, "Setting cipher list should succeed");
  OVPN_TEST (opts.n_data_ciphers == 3, "Should have 3 ciphers");
  OVPN_TEST (strcmp ((char *) opts.data_ciphers[0], "AES-256-GCM") == 0,
	     "First cipher should be AES-256-GCM");
  OVPN_TEST (strcmp ((char *) opts.data_ciphers[1], "AES-128-GCM") == 0,
	     "Second cipher should be AES-128-GCM");
  OVPN_TEST (strcmp ((char *) opts.data_ciphers[2], "CHACHA20-POLY1305") == 0,
	     "Third cipher should be CHACHA20-POLY1305");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);

  /* Test comma-separated format */
  clib_memset (&opts, 0, sizeof (opts));
  rv = ovpn_options_set_data_ciphers (&opts, "AES-256-GCM,AES-128-GCM");
  OVPN_TEST (rv == 0, "Setting comma-separated cipher list should succeed");
  OVPN_TEST (opts.n_data_ciphers == 2, "Should have 2 ciphers");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);

  vlib_cli_output (vm, "Data ciphers test PASSED\n");
  return 0;
}

/*
 * Test cipher negotiation
 */
static int
ovpn_test_cipher_negotiation (vlib_main_t *vm)
{
  ovpn_options_t opts;
  const char *result;

  vlib_cli_output (vm, "=== Test Cipher Negotiation ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Set server's preferred ciphers */
  ovpn_options_set_data_ciphers (&opts,
				 "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305");

  /* Test with client that supports first cipher */
  result = ovpn_options_negotiate_cipher (&opts, "AES-256-GCM:AES-128-CBC");
  OVPN_TEST (result != NULL, "Negotiation should succeed");
  OVPN_TEST (strcmp (result, "AES-256-GCM") == 0,
	     "Should negotiate to AES-256-GCM");

  /* Test with client that only supports second cipher */
  result = ovpn_options_negotiate_cipher (&opts, "AES-128-CBC:AES-128-GCM");
  OVPN_TEST (result != NULL, "Negotiation should succeed");
  OVPN_TEST (strcmp (result, "AES-128-GCM") == 0,
	     "Should negotiate to AES-128-GCM");

  /* Test with client that only supports third cipher */
  result = ovpn_options_negotiate_cipher (&opts, "CHACHA20-POLY1305");
  OVPN_TEST (result != NULL, "Negotiation should succeed");
  OVPN_TEST (strcmp (result, "CHACHA20-POLY1305") == 0,
	     "Should negotiate to CHACHA20-POLY1305");

  /* Test with client that supports no matching ciphers - should use first */
  result = ovpn_options_negotiate_cipher (&opts, "BLOWFISH-CBC:DES-CBC");
  OVPN_TEST (result != NULL, "Should return fallback cipher");
  OVPN_TEST (strcmp (result, "AES-256-GCM") == 0,
	     "Should fallback to first server cipher");

  /* Set fallback cipher */
  ovpn_options_free_dynamic (&opts);
  clib_memset (&opts, 0, sizeof (opts));
  ovpn_options_set_data_ciphers (&opts, "AES-256-GCM:AES-128-GCM");
  opts.data_ciphers_fallback = (u8 *) format (0, "AES-256-CBC%c", 0);

  result = ovpn_options_negotiate_cipher (&opts, "BLOWFISH-CBC");
  OVPN_TEST (result != NULL, "Should return explicit fallback");
  OVPN_TEST (strcmp (result, "AES-256-CBC") == 0,
	     "Should use explicit fallback cipher");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);

  vlib_cli_output (vm, "Cipher negotiation test PASSED\n");
  return 0;
}

/*
 * Test push routes
 */
static int
ovpn_test_push_routes (vlib_main_t *vm)
{
  ovpn_options_t opts;
  fib_prefix_t route;
  int rv;

  vlib_cli_output (vm, "=== Test Push Routes ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Add IPv4 route */
  clib_memset (&route, 0, sizeof (route));
  route.fp_proto = FIB_PROTOCOL_IP4;
  route.fp_len = 24;
  route.fp_addr.ip4.as_u8[0] = 10;
  route.fp_addr.ip4.as_u8[1] = 0;
  route.fp_addr.ip4.as_u8[2] = 0;
  route.fp_addr.ip4.as_u8[3] = 0;

  rv = ovpn_options_add_push_route (&opts, &route);
  OVPN_TEST (rv == 0, "Adding IPv4 route should succeed");
  OVPN_TEST (opts.n_push_routes == 1, "Should have 1 route");
  OVPN_TEST (opts.push_routes[0].fp_proto == FIB_PROTOCOL_IP4,
	     "Route should be IPv4");
  OVPN_TEST (opts.push_routes[0].fp_len == 24, "Prefix length should be 24");

  /* Add IPv6 route */
  clib_memset (&route, 0, sizeof (route));
  route.fp_proto = FIB_PROTOCOL_IP6;
  route.fp_len = 64;
  route.fp_addr.ip6.as_u16[0] = clib_host_to_net_u16 (0x2001);
  route.fp_addr.ip6.as_u16[1] = clib_host_to_net_u16 (0xdb8);

  rv = ovpn_options_add_push_route (&opts, &route);
  OVPN_TEST (rv == 0, "Adding IPv6 route should succeed");
  OVPN_TEST (opts.n_push_routes == 2, "Should have 2 routes");
  OVPN_TEST (opts.push_routes[1].fp_proto == FIB_PROTOCOL_IP6,
	     "Second route should be IPv6");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);
  OVPN_TEST (opts.n_push_routes == 0, "After cleanup, should have 0 routes");

  vlib_cli_output (vm, "Push routes test PASSED\n");
  return 0;
}

/*
 * Test build push reply
 */
static int
ovpn_test_build_push_reply (vlib_main_t *vm)
{
  ovpn_options_t opts;
  char buf[1024];
  int len;
  ip_address_t dns_ip;
  fib_prefix_t route;

  vlib_cli_output (vm, "=== Test Build Push Reply ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Add some options */
  ip4_address_t dns4 = { .as_u8 = { 8, 8, 8, 8 } };
  ip_address_set (&dns_ip, &dns4, AF_IP4);
  ovpn_options_add_dns (&opts, &dns_ip);

  ovpn_options_set_domain (&opts, "example.com");

  clib_memset (&route, 0, sizeof (route));
  route.fp_proto = FIB_PROTOCOL_IP4;
  route.fp_len = 24;
  route.fp_addr.ip4.as_u8[0] = 10;
  route.fp_addr.ip4.as_u8[1] = 0;
  route.fp_addr.ip4.as_u8[2] = 0;
  route.fp_addr.ip4.as_u8[3] = 0;
  ovpn_options_add_push_route (&opts, &route);

  ovpn_options_add_push (&opts, "persist-tun");

  /* Build push reply */
  len = ovpn_options_build_push_reply (&opts, buf, sizeof (buf));
  OVPN_TEST (len > 0, "Build push reply should succeed");

  /* Check content */
  OVPN_TEST (strstr (buf, "dhcp-option DNS 8.8.8.8") != NULL,
	     "Push reply should contain DNS option");
  OVPN_TEST (strstr (buf, "dhcp-option DOMAIN example.com") != NULL,
	     "Push reply should contain DOMAIN option");
  OVPN_TEST (strstr (buf, "route 10.0.0.0 255.255.255.0") != NULL,
	     "Push reply should contain route");
  OVPN_TEST (strstr (buf, "persist-tun") != NULL,
	     "Push reply should contain custom push option");

  vlib_cli_output (vm, "Push reply: %s\n", buf);

  /* Clean up */
  ovpn_options_free_dynamic (&opts);

  vlib_cli_output (vm, "Build push reply test PASSED\n");
  return 0;
}

/*
 * Test redirect-gateway
 */
static int
ovpn_test_redirect_gateway (vlib_main_t *vm)
{
  ovpn_options_t opts;
  char buf[1024];
  int len;

  vlib_cli_output (vm, "=== Test Redirect Gateway ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Set redirect-gateway with def1 flag */
  opts.redirect_gateway = 1;
  opts.redirect_gateway_flags = 0x01; /* def1 */

  /* Build push reply */
  len = ovpn_options_build_push_reply (&opts, buf, sizeof (buf));
  OVPN_TEST (len > 0, "Build push reply should succeed");
  OVPN_TEST (strstr (buf, "redirect-gateway") != NULL,
	     "Should contain redirect-gateway");
  OVPN_TEST (strstr (buf, "def1") != NULL, "Should contain def1 flag");

  vlib_cli_output (vm, "Redirect gateway output: %s\n", buf);

  vlib_cli_output (vm, "Redirect gateway test PASSED\n");
  return 0;
}

/*
 * Test max limits
 */
static int
ovpn_test_max_limits (vlib_main_t *vm)
{
  ovpn_options_t opts;
  int rv;
  char option_name[64];

  vlib_cli_output (vm, "=== Test Max Limits ===\n");

  clib_memset (&opts, 0, sizeof (opts));

  /* Add push options up to max */
  for (u32 i = 0; i < OVPN_MAX_PUSH_OPTIONS; i++)
    {
      snprintf (option_name, sizeof (option_name), "test-option-%u", i);
      rv = ovpn_options_add_push (&opts, option_name);
      if (rv != 0)
	{
	  vlib_cli_output (vm, "Failed to add push option %u\n", i);
	  ovpn_options_free_dynamic (&opts);
	  return 1;
	}
    }

  OVPN_TEST (opts.n_push_options == OVPN_MAX_PUSH_OPTIONS,
	     "Should have max push options");

  /* Try to add one more - should fail */
  rv = ovpn_options_add_push (&opts, "overflow-option");
  OVPN_TEST (rv == -2, "Adding beyond max should fail with -2");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);

  /* Test max data ciphers */
  clib_memset (&opts, 0, sizeof (opts));

  for (u32 i = 0; i < OVPN_MAX_DATA_CIPHERS; i++)
    {
      snprintf (option_name, sizeof (option_name), "CIPHER-%u", i);
      rv = ovpn_options_add_data_cipher (&opts, option_name);
      if (rv != 0)
	{
	  vlib_cli_output (vm, "Failed to add cipher %u\n", i);
	  ovpn_options_free_dynamic (&opts);
	  return 1;
	}
    }

  OVPN_TEST (opts.n_data_ciphers == OVPN_MAX_DATA_CIPHERS,
	     "Should have max data ciphers");

  rv = ovpn_options_add_data_cipher (&opts, "OVERFLOW-CIPHER");
  OVPN_TEST (rv == -2, "Adding beyond max ciphers should fail with -2");

  /* Clean up */
  ovpn_options_free_dynamic (&opts);

  vlib_cli_output (vm, "Max limits test PASSED\n");
  return 0;
}

/*
 * CLI command to run all options tests
 */
static clib_error_t *
ovpn_test_options_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  int failed = 0;

  vlib_cli_output (vm, "\n=========================================\n"
		       "       OpenVPN Options Unit Tests\n"
		       "=========================================\n\n");

  if (ovpn_test_push_options (vm))
    failed++;

  if (ovpn_test_dhcp_options (vm))
    failed++;

  if (ovpn_test_data_ciphers (vm))
    failed++;

  if (ovpn_test_cipher_negotiation (vm))
    failed++;

  if (ovpn_test_push_routes (vm))
    failed++;

  if (ovpn_test_build_push_reply (vm))
    failed++;

  if (ovpn_test_redirect_gateway (vm))
    failed++;

  if (ovpn_test_max_limits (vm))
    failed++;

  vlib_cli_output (vm,
		   "\n=========================================\n"
		   "  Options Tests Complete: %d failed\n"
		   "=========================================\n\n",
		   failed);

  return 0;
}

VLIB_CLI_COMMAND (ovpn_test_options_command, static) = {
  .path = "test ovpn options",
  .short_help = "test ovpn options - Run OpenVPN options unit tests",
  .function = ovpn_test_options_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
