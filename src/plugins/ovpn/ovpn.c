/*
 * ovpn.c - ovpn source file
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

#include <ovpn/ovpn.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_handshake.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/error.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_types.h>
#include <vppinfra/unix.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp.h>
#include <vnet/ip/ip.h>
#include <stddef.h>
#include <vpp/app/version.h>
#include <picotls/openssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

ovpn_main_t ovpn_main;

/* Picotls key exchange algorithms */
static ptls_key_exchange_algorithm_t *ovpn_key_exchange[] = {
#ifdef PTLS_OPENSSL_HAVE_X25519
  &ptls_openssl_x25519,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP256R1
  &ptls_openssl_secp256r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP384R1
  &ptls_openssl_secp384r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP521R1
  &ptls_openssl_secp521r1,
#endif
  NULL
};

/* Picotls cipher suites */
static ptls_cipher_suite_t *ovpn_cipher_suites[] = {
  &ptls_openssl_aes128gcmsha256, &ptls_openssl_aes256gcmsha384,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
  &ptls_openssl_chacha20poly1305sha256,
#endif
  NULL
};

static clib_error_t *
ovpn_read_file_contents (char *file_path, u8 **result)
{
  clib_error_t *error;

  if (!file_path)
    return clib_error_return (0, "file path is NULL");

  error = clib_file_contents (file_path, result);
  if (error)
    return clib_error_return (0, "failed to read file '%s': %U", file_path,
			      format_clib_error, error);

  return 0;
}

static int
ovpn_load_certificates (ptls_context_t *ctx, u8 *cert_data, u8 *key_data)
{
  BIO *key_bio = NULL;
  BIO *cert_bio = NULL;
  EVP_PKEY *pkey = NULL;
  X509 *x509 = NULL;
  ptls_openssl_sign_certificate_t *sign_cert = NULL;
  u8 *der_cert = NULL;
  int der_len = 0;
  int ret = -1;

  if (!cert_data || !key_data)
    return -1;

  /* Load private key */
  key_bio = BIO_new_mem_buf (key_data, vec_len (key_data));
  if (!key_bio)
    goto done;

  pkey = PEM_read_bio_PrivateKey (key_bio, NULL, NULL, NULL);
  if (!pkey)
    goto done;

  /* Load certificate from PEM and convert to DER */
  cert_bio = BIO_new_mem_buf (cert_data, vec_len (cert_data));
  if (!cert_bio)
    goto done;

  x509 = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL);
  if (!x509)
    goto done;

  /* Get DER encoding length */
  der_len = i2d_X509 (x509, NULL);
  if (der_len <= 0)
    goto done;

  /* Allocate and convert to DER */
  der_cert = clib_mem_alloc (der_len);
  if (!der_cert)
    goto done;

  {
    u8 *der_ptr = der_cert;
    if (i2d_X509 (x509, &der_ptr) != der_len)
      goto done;
  }

  /* Allocate and setup sign certificate */
  sign_cert =
    (ptls_openssl_sign_certificate_t *) clib_mem_alloc (sizeof (*sign_cert));
  if (!sign_cert)
    goto done;

  clib_memset (sign_cert, 0, sizeof (*sign_cert));

  if (ptls_openssl_init_sign_certificate (sign_cert, pkey) != 0)
    {
      clib_mem_free (sign_cert);
      sign_cert = NULL;
      /* pkey was not transferred to sign_cert, so we must free it */
      EVP_PKEY_free (pkey);
      pkey = NULL;
      goto done;
    }

  ctx->sign_certificate = &sign_cert->super;

  /* Setup certificates - use DER-encoded certificate */
  ptls_iovec_t *certs = clib_mem_alloc (2 * sizeof (ptls_iovec_t));
  if (!certs)
    {
      /* ptls_openssl_init_sign_certificate succeeded, so pkey may have been
       * transferred to sign_cert. We clear ctx->sign_certificate and free
       * sign_cert. The done label will check ctx->sign_certificate to
       * determine if pkey needs freeing. */
      ctx->sign_certificate = NULL;
      clib_mem_free (sign_cert);
      sign_cert = NULL;
      goto done;
    }
  certs[0].base = der_cert;
  certs[0].len = der_len;
  certs[1].base = NULL;
  certs[1].len = 0;
  der_cert = NULL; /* Transfer ownership to ctx */

  ctx->certificates.list = certs;
  ctx->certificates.count = 1;

  ret = 0;

done:
  if (key_bio)
    BIO_free (key_bio);
  if (cert_bio)
    BIO_free (cert_bio);
  if (x509)
    X509_free (x509);
  if (der_cert)
    clib_mem_free (der_cert);
  /* Note: pkey is only owned by sign_cert if
   * ptls_openssl_init_sign_certificate succeeded AND ctx->sign_certificate is
   * still set. We check ctx->sign_certificate to determine if pkey was
   * transferred. If ctx->sign_certificate is NULL, pkey was not transferred
   * (or sign_cert was freed) and must be freed. */
  if (pkey && !ctx->sign_certificate)
    EVP_PKEY_free (pkey);

  return ret;
}

static void
ovpn_free_options (ovpn_options_t *opt)
{
  vec_free (opt->dev_name);
  vec_free (opt->ca_cert);
  vec_free (opt->server_cert);
  vec_free (opt->server_key);
  vec_free (opt->dh_params);
  vec_free (opt->tls_crypt_key);
  vec_free (opt->tls_crypt_v2_key);
  vec_free (opt->tls_auth_key);
  vec_free (opt->cipher_name);
  vec_free (opt->auth_name);
  clib_memset (opt, 0, sizeof (*opt));
  opt->sw_if_index = ~0;
}

static clib_error_t *
ovpn_init_picotls_context (ovpn_main_t *omp)
{
  ptls_context_t *ctx;

  /* Allocate and initialize picotls context */
  ctx = clib_mem_alloc (sizeof (ptls_context_t));
  if (!ctx)
    return clib_error_return (0, "failed to allocate picotls context");

  clib_memset (ctx, 0, sizeof (ptls_context_t));

  /* Setup basic context */
  ctx->random_bytes = ptls_openssl_random_bytes;
  ctx->key_exchanges = ovpn_key_exchange;
  ctx->cipher_suites = ovpn_cipher_suites;
  ctx->get_time = &ptls_get_time;
  ctx->require_dhe_on_psk = 1;
  ctx->max_early_data_size = 0;

  /* Load certificates if provided */
  if (omp->options.server_cert && omp->options.server_key)
    {
      if (ovpn_load_certificates (ctx, omp->options.server_cert,
				  omp->options.server_key) != 0)
	{
	  clib_mem_free (ctx);
	  return clib_error_return (0, "failed to load certificates");
	}
    }

  omp->ptls_ctx = ctx;
  return 0;
}

static void
ovpn_cleanup_picotls_context (ovpn_main_t *omp)
{
  ptls_openssl_sign_certificate_t *sign_cert;

  if (!omp->ptls_ctx)
    return;

  /* Free sign_certificate structure if it exists */
  if (omp->ptls_ctx->sign_certificate)
    {
      /* ctx->sign_certificate points to sign_cert->super, so we need to
       * get the containing structure */
      sign_cert = (ptls_openssl_sign_certificate_t
		     *) ((char *) omp->ptls_ctx->sign_certificate -
			 offsetof (ptls_openssl_sign_certificate_t, super));
      clib_mem_free (sign_cert);
    }

  if (omp->ptls_ctx->certificates.list)
    clib_mem_free ((void *) omp->ptls_ctx->certificates.list);

  clib_mem_free (omp->ptls_ctx);
  omp->ptls_ctx = NULL;
}

static clib_error_t *
ovpn_show_command_fn (vlib_main_t *vm,
		      unformat_input_t *input __attribute__ ((unused)),
		      vlib_cli_command_t *cmd __attribute__ ((unused)))
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_options_t *opt = &omp->options;

  vlib_cli_output (vm, "OpenVPN Configuration:");
  vlib_cli_output (vm, "  Status: %s",
		   omp->is_enabled ? "Enabled" : "Disabled");
  vlib_cli_output (vm, "  Mode: %s",
		   opt->static_key_mode ? "Static Key" : "TLS");
  vlib_cli_output (vm, "  Listen Port: %u", opt->listen_port);
  vlib_cli_output (vm, "  Protocol: %s",
		   opt->proto == IP_PROTOCOL_UDP ? "UDP" : "Unknown");
  if (opt->static_key_mode)
    vlib_cli_output (vm, "  Static Key Direction: %u",
		     opt->static_key_direction);
  else
    vlib_cli_output (vm, "  Picotls Context: %s",
		     omp->ptls_ctx ? "Initialized" : "Not initialized");

  if (opt->dev_name)
    {
      vlib_cli_output (vm, "  Device Name: %s", opt->dev_name);
      vlib_cli_output (vm, "  Device Mode: %s",
		       opt->is_tun ? "TUN (L3)" : "TAP (L2)");
      vlib_cli_output (vm, "  MTU: %u", opt->mtu);
      if (opt->sw_if_index != ~0)
	vlib_cli_output (vm, "  SW Interface Index: %u", opt->sw_if_index);
    }

  if (opt->server_addr.fp_proto != 0)
    vlib_cli_output (vm, "  Server Address: %U/%d", format_fib_prefix,
		     &opt->server_addr);

  if (opt->ca_cert)
    vlib_cli_output (vm, "  CA Certificate: loaded (%u bytes)",
		     vec_len (opt->ca_cert));
  if (opt->server_cert)
    vlib_cli_output (vm, "  Server Certificate: loaded (%u bytes)",
		     vec_len (opt->server_cert));
  if (opt->server_key)
    vlib_cli_output (vm, "  Server Key: loaded (%u bytes)",
		     vec_len (opt->server_key));
  if (opt->dh_params)
    vlib_cli_output (vm, "  DH Parameters: loaded (%u bytes)",
		     vec_len (opt->dh_params));
  if (opt->cipher_name)
    vlib_cli_output (vm, "  Cipher: %s", opt->cipher_name);
  vlib_cli_output (
    vm, "  Cipher Algorithm: %s",
    omp->cipher_alg == OVPN_CIPHER_ALG_AES_128_GCM	? "AES-128-GCM" :
    omp->cipher_alg == OVPN_CIPHER_ALG_AES_256_GCM	? "AES-256-GCM" :
    omp->cipher_alg == OVPN_CIPHER_ALG_CHACHA20_POLY1305 ? "CHACHA20-POLY1305" :
    omp->cipher_alg == OVPN_CIPHER_ALG_AES_256_CBC	? "AES-256-CBC" :
							  "NONE");
  if (opt->tls_crypt_key)
    vlib_cli_output (vm, "  TLS-Crypt Key: loaded (%u bytes)",
		     vec_len (opt->tls_crypt_key));
  if (opt->tls_crypt_v2_key)
    vlib_cli_output (vm, "  TLS-Crypt-V2 Server Key: loaded (%u bytes)",
		     vec_len (opt->tls_crypt_v2_key));
  if (omp->tls_crypt_v2.enabled)
    vlib_cli_output (vm, "  TLS-Crypt-V2: enabled (per-client keys)");
  if (opt->tls_auth_key)
    vlib_cli_output (vm, "  TLS-Auth Key: loaded (%u bytes)",
		     vec_len (opt->tls_auth_key));

  if (opt->pool_start.version != 0)
    vlib_cli_output (vm, "  Pool Start: %U", format_ip_address,
		     &opt->pool_start);
  if (opt->pool_end.version != 0)
    vlib_cli_output (vm, "  Pool End: %U", format_ip_address, &opt->pool_end);

  vlib_cli_output (vm, "  Max Clients: %u", opt->max_clients);
  vlib_cli_output (vm, "  Keepalive Ping: %u seconds", opt->keepalive_ping);
  vlib_cli_output (vm, "  Keepalive Timeout: %u seconds",
		   opt->keepalive_timeout);
  vlib_cli_output (vm, "  Handshake Window: %u seconds",
		   opt->handshake_window);
  vlib_cli_output (vm, "  TLS Timeout: %u seconds", opt->tls_timeout);
  vlib_cli_output (vm, "  Renegotiate Seconds: %u", opt->renegotiate_seconds);
  if (opt->renegotiate_bytes > 0)
    vlib_cli_output (vm, "  Renegotiate Bytes: %lu", opt->renegotiate_bytes);
  else
    vlib_cli_output (vm, "  Renegotiate Bytes: disabled");
  if (opt->renegotiate_packets > 0)
    vlib_cli_output (vm, "  Renegotiate Packets: %lu", opt->renegotiate_packets);
  else
    vlib_cli_output (vm, "  Renegotiate Packets: disabled");
  vlib_cli_output (vm, "  Replay Protection: %s",
		   opt->replay_protection ? "Enabled" : "Disabled");
  vlib_cli_output (vm, "  Replay Window: %u", opt->replay_window);
  vlib_cli_output (vm, "  Replay Time: %u seconds", opt->replay_time);
  vlib_cli_output (vm, "  Transition Window: %u seconds",
		   opt->transition_window);

  return 0;
}

/*?
 * Show OpenVPN configuration
 *
 * @cliexpar
 * @cliexstart{show ovpn}
 * show ovpn
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (ovpn_show_command, static) = {
  .path = "show ovpn",
  .short_help = "show ovpn",
  .function = ovpn_show_command_fn,
};

/* External node declarations */
extern vlib_node_registration_t ovpn4_input_node;
extern vlib_node_registration_t ovpn6_input_node;
extern vlib_node_registration_t ovpn4_output_node;
extern vlib_node_registration_t ovpn6_output_node;

/*
 * CLI: ovpn create local <ip> port <port> [options...]
 * Creates an OpenVPN interface with full configuration options.
 */
static clib_error_t *
ovpn_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  ip_address_t local_addr = { 0 };
  u32 port = 1194;
  u8 *dev_name = 0;
  u8 *ca_cert = 0;
  u8 *server_cert = 0;
  u8 *server_key = 0;
  u8 *dh_params = 0;
  u8 *cipher = 0;
  u8 *auth = 0;
  u8 *tls_crypt_key = 0;
  u8 *tls_crypt_v2_key = 0;
  u8 *tls_auth_key = 0;
  u8 *secret_key = 0;
  ip_address_t pool_start, pool_end;
  fib_prefix_t server_addr;
  int got_local = 0;
  /* OpenVPN defaults */
  u32 max_clients = 1024;
  u32 keepalive_ping = 10;
  u32 keepalive_timeout = 120;
  u32 handshake_timeout = 60;
  u32 renegotiate_seconds = 3600;
  u32 tls_timeout = 2;
  u8 replay_protection = 1;
  u32 replay_window = 64;
  u32 replay_time = 15;
  u32 transition_window = 3600;
  u16 mtu = 1500;
  u8 is_tun = 1;

  clib_memset (&pool_start, 0, sizeof (pool_start));
  clib_memset (&pool_end, 0, sizeof (pool_end));
  clib_memset (&server_addr, 0, sizeof (server_addr));

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U", unformat_ip_address, &local_addr))
	got_local = 1;
      else if (unformat (line_input, "port %u", &port))
	;
      else if (unformat (line_input, "dev %s", &dev_name))
	;
      else if (unformat (line_input, "ca %s", &ca_cert))
	;
      else if (unformat (line_input, "cert %s", &server_cert))
	;
      else if (unformat (line_input, "key %s", &server_key))
	;
      else if (unformat (line_input, "dh %s", &dh_params))
	;
      else if (unformat (line_input, "cipher %s", &cipher))
	;
      else if (unformat (line_input, "auth %s", &auth))
	;
      else if (unformat (line_input, "tls-crypt %s", &tls_crypt_key))
	;
      else if (unformat (line_input, "tls-crypt-v2 %s", &tls_crypt_v2_key))
	;
      else if (unformat (line_input, "tls-auth %s", &tls_auth_key))
	;
      else if (unformat (line_input, "secret %s", &secret_key))
	;
      else if (unformat (line_input, "server %U/%d", unformat_ip4_address,
			 &server_addr.fp_addr.ip4, &server_addr.fp_len))
	server_addr.fp_proto = FIB_PROTOCOL_IP4;
      else if (unformat (line_input, "server %U/%d", unformat_ip6_address,
			 &server_addr.fp_addr.ip6, &server_addr.fp_len))
	server_addr.fp_proto = FIB_PROTOCOL_IP6;
      else if (unformat (line_input, "ifconfig-pool %U %U",
			 unformat_ip4_address, &pool_start.ip.ip4,
			 unformat_ip4_address, &pool_end.ip.ip4))
	{
	  pool_start.version = AF_IP4;
	  pool_end.version = AF_IP4;
	}
      else if (unformat (line_input, "max-clients %u", &max_clients))
	;
      else if (unformat (line_input, "keepalive %u %u", &keepalive_ping,
			 &keepalive_timeout))
	;
      else if (unformat (line_input, "hand-window %u", &handshake_timeout))
	;
      else if (unformat (line_input, "reneg-sec %u", &renegotiate_seconds))
	;
      else if (unformat (line_input, "tls-timeout %u", &tls_timeout))
	;
      else if (unformat (line_input, "replay-window %u %u", &replay_window,
			 &replay_time))
	;
      else if (unformat (line_input, "replay-window %u", &replay_window))
	;
      else if (unformat (line_input, "tun-mtu %u", &mtu))
	;
      else if (unformat (line_input, "dev-type tun"))
	is_tun = 1;
      else if (unformat (line_input, "dev-type tap"))
	is_tun = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!got_local)
    {
      error = clib_error_return (0, "local address required");
      goto done;
    }

  if (omp->is_enabled)
    {
      error = clib_error_return (0, "OpenVPN already enabled");
      goto done;
    }

  /* Configure options */
  omp->options.listen_port = (u16) port;
  omp->options.proto = IP_PROTOCOL_UDP;
  omp->options.mtu = mtu;
  omp->options.is_tun = is_tun;

  /* Store local address */
  if (ip_addr_version (&local_addr) == AF_IP6)
    {
      server_addr.fp_proto = FIB_PROTOCOL_IP6;
      server_addr.fp_len = 128;
      clib_memcpy (&server_addr.fp_addr.ip6, &local_addr.ip.ip6,
		   sizeof (ip6_address_t));
    }
  else
    {
      server_addr.fp_proto = FIB_PROTOCOL_IP4;
      server_addr.fp_len = 32;
      server_addr.fp_addr.ip4.as_u32 = local_addr.ip.ip4.as_u32;
    }
  omp->options.server_addr = server_addr;

  /* Set device name */
  if (dev_name)
    {
      omp->options.dev_name = (char *) dev_name;
      dev_name = 0;
    }
  else
    omp->options.dev_name = (char *) format (0, "ovpn0%c", 0);

  /* Load TLS-Crypt key if specified */
  if (tls_crypt_key)
    {
      error = ovpn_read_file_contents ((char *) tls_crypt_key,
				       &omp->options.tls_crypt_key);
      if (error)
	{
	  error = clib_error_return (0, "failed to read TLS-Crypt key: %U",
				     format_clib_error, error);
	  goto done;
	}
      int rv = ovpn_tls_crypt_parse_key (omp->options.tls_crypt_key,
					 vec_len (omp->options.tls_crypt_key),
					 &omp->tls_crypt, 1);
      if (rv < 0)
	{
	  error = clib_error_return (0, "failed to parse TLS-Crypt key: %d", rv);
	  goto done;
	}
      vlib_cli_output (vm, "TLS-Crypt initialized");
    }

  /* Load TLS-Auth key if specified */
  if (tls_auth_key)
    {
      error = ovpn_read_file_contents ((char *) tls_auth_key,
				       &omp->options.tls_auth_key);
      if (error)
	{
	  error = clib_error_return (0, "failed to read TLS-Auth key: %U",
				     format_clib_error, error);
	  goto done;
	}
      int rv = ovpn_tls_auth_parse_key (omp->options.tls_auth_key,
					vec_len (omp->options.tls_auth_key),
					&omp->tls_auth, 1);
      if (rv < 0)
	{
	  error = clib_error_return (0, "failed to parse TLS-Auth key: %d", rv);
	  goto done;
	}
      vlib_cli_output (vm, "TLS-Auth initialized");
    }

  /* Load certificates if specified */
  if (ca_cert)
    {
      error = ovpn_read_file_contents ((char *) ca_cert, &omp->options.ca_cert);
      if (error)
	goto done;
    }
  if (server_cert)
    {
      error = ovpn_read_file_contents ((char *) server_cert,
				       &omp->options.server_cert);
      if (error)
	goto done;
    }
  if (server_key)
    {
      error = ovpn_read_file_contents ((char *) server_key,
				       &omp->options.server_key);
      if (error)
	goto done;
    }

  /* Set cipher */
  if (cipher)
    {
      omp->cipher_alg = ovpn_crypto_cipher_alg_from_name ((char *) cipher);
      if (omp->cipher_alg == OVPN_CIPHER_ALG_NONE)
	{
	  error = clib_error_return (0, "unsupported cipher: %s", cipher);
	  goto done;
	}
    }
  else
    omp->cipher_alg = OVPN_CIPHER_ALG_AES_256_GCM;

  /* Set other options */
  omp->options.max_clients = max_clients;
  omp->options.keepalive_ping = keepalive_ping;
  omp->options.keepalive_timeout = keepalive_timeout;
  omp->options.handshake_window = handshake_timeout;
  omp->options.renegotiate_seconds = renegotiate_seconds;
  omp->options.tls_timeout = tls_timeout;
  omp->options.replay_protection = replay_protection;
  omp->options.replay_window = replay_window;
  omp->options.replay_time = replay_time;
  omp->options.transition_window = transition_window;
  if (pool_start.version != 0)
    omp->options.pool_start = pool_start;
  if (pool_end.version != 0)
    omp->options.pool_end = pool_end;

  /* Initialize replay protection for TLS */
  if (omp->tls_crypt.enabled && replay_protection)
    {
      omp->tls_crypt.time_backtrack = replay_time;
      omp->tls_crypt.replay_time_floor = 0;
    }

  /* Load static key if specified (--secret option) */
  if (secret_key)
    {
      u8 *key_contents = NULL;
      error = ovpn_read_file_contents ((char *) secret_key, &key_contents);
      if (error)
	{
	  error = clib_error_return (0, "failed to read static key file: %U",
				     format_clib_error, error);
	  goto done;
	}

      /* Allocate storage for parsed key */
      omp->options.static_key = clib_mem_alloc (OVPN_STATIC_KEY_SIZE);
      if (!omp->options.static_key)
	{
	  vec_free (key_contents);
	  error = clib_error_return (0, "failed to allocate static key memory");
	  goto done;
	}

      /* Parse the static key file */
      int rv = ovpn_parse_static_key (key_contents, vec_len (key_contents),
				      omp->options.static_key);
      vec_free (key_contents);
      if (rv < 0)
	{
	  clib_mem_free (omp->options.static_key);
	  omp->options.static_key = NULL;
	  error = clib_error_return (0, "failed to parse static key: %d", rv);
	  goto done;
	}

      omp->options.static_key_mode = 1;
      omp->options.static_key_direction = 0; /* Server mode = direction 0 */

      /* For static key mode, use AES-256-CBC as default (not AEAD)
       * unless explicitly overridden by cipher option */
      if (!cipher)
	omp->cipher_alg = OVPN_CIPHER_ALG_AES_256_CBC;

      vlib_cli_output (vm, "Static key loaded (direction %u, cipher %s)",
		       omp->options.static_key_direction,
		       omp->cipher_alg == OVPN_CIPHER_ALG_AES_256_CBC ?
			 "AES-256-CBC" :
			 "specified");
    }

  /* Initialize picotls context (only needed for TLS mode) */
  if (!omp->options.static_key_mode)
    {
      error = ovpn_init_picotls_context (omp);
      if (error)
	{
	  error = clib_error_return (0, "failed to initialize picotls: %U",
				     format_clib_error, error);
	  goto done;
	}
    }

  /* Create the OpenVPN interface */
  u32 sw_if_index = ~0;
  int rv = ovpn_if_create (vm, (u8 *) omp->options.dev_name, is_tun, mtu,
			   &sw_if_index);
  if (rv != 0)
    {
      error = clib_error_return (0, "failed to create ovpn interface");
      goto done;
    }
  omp->options.sw_if_index = sw_if_index;

  /* Register UDP port */
  udp_register_dst_port (vm, port, ovpn4_input_node.index, UDP_IP4);
  udp_register_dst_port (vm, port, ovpn6_input_node.index, UDP_IP6);

  /* Initialize peer database */
  ovpn_peer_db_init (&omp->multi_context.peer_db, sw_if_index);
  ovpn_pending_db_init (&omp->multi_context.pending_db);

  omp->is_enabled = 1;
  vlib_cli_output (vm, "OpenVPN interface %s created on port %u",
		   omp->options.dev_name, port);

done:
  vec_free (dev_name);
  vec_free (ca_cert);
  vec_free (server_cert);
  vec_free (server_key);
  vec_free (dh_params);
  vec_free (cipher);
  vec_free (auth);
  vec_free (tls_crypt_key);
  vec_free (tls_crypt_v2_key);
  vec_free (tls_auth_key);
  vec_free (secret_key);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ovpn_create_command, static) = {
  .path = "ovpn create",
  .short_help = "ovpn create local <ip> port <port> [dev <name>] "
		"[secret <keyfile>] "
		"[tls-crypt <key>] [tls-auth <key>] [ca <cert>] [cert <cert>] "
		"[key <key>] [cipher <name>] [server <ip>/<len>]",
  .function = ovpn_create_command_fn,
};

/*
 * CLI: ovpn delete interface <name>
 * Deletes an OpenVPN interface.
 */
static clib_error_t *
ovpn_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		vnet_get_main (), &sw_if_index))
    ;
  else
    {
      error = clib_error_return (0, "unknown input `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  if (!omp->is_enabled || omp->options.sw_if_index != sw_if_index)
    {
      error = clib_error_return (0, "interface not found or not an OpenVPN interface");
      goto done;
    }

  /* Unregister UDP port */
  udp_unregister_dst_port (vm, omp->options.listen_port, UDP_IP4);
  udp_unregister_dst_port (vm, omp->options.listen_port, UDP_IP6);

  /* Delete the interface */
  ovpn_if_delete (vm, sw_if_index);

  /* Cleanup databases */
  ovpn_peer_db_free (&omp->multi_context.peer_db);
  ovpn_pending_db_free (&omp->multi_context.pending_db);

  /* Cleanup picotls context */
  ovpn_cleanup_picotls_context (omp);

  /* Free options */
  ovpn_free_options (&omp->options);

  /* Reset state */
  omp->options.sw_if_index = ~0;
  omp->is_enabled = 0;

  vlib_cli_output (vm, "OpenVPN interface deleted");

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ovpn_delete_command, static) = {
  .path = "ovpn delete",
  .short_help = "ovpn delete interface <interface>",
  .function = ovpn_delete_command_fn,
};

/*
 * Plugin initialization
 */
static clib_error_t *
ovpn_init (vlib_main_t *vm)
{
  ovpn_main_t *omp = &ovpn_main;
  clib_error_t *error = NULL;

  omp->vm = vm;
  omp->vnm = vnet_get_main ();

  /* Store node indices */
  omp->ovpn4_input_node_index = ovpn4_input_node.index;
  omp->ovpn6_input_node_index = ovpn6_input_node.index;
  omp->ovpn4_output_node_index = ovpn4_output_node.index;
  omp->ovpn6_output_node_index = ovpn6_output_node.index;

  /* Initialize frame queues for handoff */
  omp->in4_fq_index = vlib_frame_queue_main_init (ovpn4_input_node.index, 0);
  omp->in6_fq_index = vlib_frame_queue_main_init (ovpn6_input_node.index, 0);
  omp->out4_fq_index = vlib_frame_queue_main_init (ovpn4_output_node.index, 0);
  omp->out6_fq_index = vlib_frame_queue_main_init (ovpn6_output_node.index, 0);

  /* Allocate high-priority FIB source for tunnel routes */
  omp->fib_src_hi = fib_source_allocate ("ovpn-hi", FIB_SOURCE_PRIORITY_HI,
					 FIB_SOURCE_BH_API);

  /* Initialize crypto subsystem */
  error = ovpn_crypto_init (vm);
  if (error)
    return error;

  /* Initialize options */
  omp->options.sw_if_index = ~0;

  return 0;
}

VLIB_INIT_FUNCTION (ovpn_init);

/*
 * Periodic process for:
 * - Checking rekey timers
 * - Expiring pending connections
 * - Cleaning up dead peers
 */
static uword
ovpn_periodic_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		       vlib_frame_t *f)
{
  ovpn_main_t *omp = &ovpn_main;
  f64 now;

  while (1)
    {
      /* Sleep for 1 second between checks */
      vlib_process_wait_for_event_or_clock (vm, 1.0);

      /* Handle any events (none defined for now) */
      vlib_process_get_events (vm, NULL);

      if (!omp->is_enabled)
	continue;

      now = vlib_time_now (vm);

      /* Expire old pending connections */
      ovpn_pending_db_expire (&omp->multi_context.pending_db, now);

      /* Cleanup expired keys (lame duck keys after transition window) */
      ovpn_peer_db_cleanup_expired_keys (vm, &omp->multi_context.peer_db, now);

      /*
       * Apply pending address updates (NAT/float support).
       * Data plane queues updates, we apply them here with barrier.
       */
      {
	int n_updates = 0;
	ovpn_peer_t *peer;

	/* First pass: check if any updates pending */
	pool_foreach (peer, omp->multi_context.peer_db.peers)
	  {
	    if (__atomic_load_n (&peer->pending_addr_update, __ATOMIC_ACQUIRE))
	      n_updates++;
	  }

	/* Only take barrier if updates are pending */
	if (n_updates > 0)
	  {
	    vlib_worker_thread_barrier_sync (vm);
	    ovpn_peer_db_apply_pending_updates (vm,
						&omp->multi_context.peer_db);
	    vlib_worker_thread_barrier_release (vm);
	  }
      }

      /* Get keepalive settings */
      f64 ping_interval = omp->options.keepalive_ping > 0 ?
			    (f64) omp->options.keepalive_ping :
			    10.0;
      f64 ping_timeout = omp->options.keepalive_timeout > 0 ?
			   (f64) omp->options.keepalive_timeout :
			   60.0;

      /* Check each peer */
      ovpn_peer_t *peer;
      u32 *peers_to_delete = NULL;

      pool_foreach (peer, omp->multi_context.peer_db.peers)
	{
	  /* Skip non-established peers */
	  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
	    continue;

	  /*
	   * Check keepalive timeout
	   * If we haven't received any packet from the peer within the
	   * timeout period, mark the peer as dead.
	   */
	  f64 last_activity = peer->last_rx_time;
	  f64 idle_time = now - last_activity;

	  if (idle_time > ping_timeout)
	    {
	      /*
	       * Peer has exceeded keepalive timeout
	       * Mark as dead for cleanup
	       */
	      peer->state = OVPN_PEER_STATE_DEAD;
	      vec_add1 (peers_to_delete, peer->peer_id);
	      continue;
	    }

	  /*
	   * Check if we should send a ping
	   * Send ping if we haven't sent anything recently
	   */
	  f64 tx_idle_time = now - peer->last_tx_time;
	  if (tx_idle_time >= ping_interval)
	    {
	      /*
	       * Send ping packet on data channel
	       * OpenVPN ping is sent as encrypted data with magic pattern
	       */
	      ovpn_peer_send_ping (vm, peer);
	    }

	  /* Check if rekey is needed (time, bytes, or packets) */
	  if (ovpn_peer_needs_rekey (peer, now, omp->options.renegotiate_bytes,
				    omp->options.renegotiate_packets))
	    {
	      /* Start server-initiated rekey */
	      u8 new_key_id = ovpn_peer_next_key_id (peer);
	      int rv =
		ovpn_peer_start_rekey (vm, peer, omp->ptls_ctx, new_key_id);
	      if (rv == 0)
		{
		  peer->rekey_initiated = 1;
		  /* Send SOFT_RESET to client */
		  if (peer->tls_ctx)
		    {
		      ovpn_reli_buffer_t *buf;
		      buf = ovpn_reliable_get_buf_output_sequenced (
			peer->tls_ctx->send_reliable);
		      if (buf)
			{
			  ovpn_buf_init (buf, 128);
			  ovpn_reliable_mark_active_outgoing (
			    peer->tls_ctx->send_reliable, buf,
			    OVPN_OP_CONTROL_SOFT_RESET_V1);
			}
		    }
		}
	    }
	}

      /* Clean up dead peers */
      for (u32 i = 0; i < vec_len (peers_to_delete); i++)
	{
	  ovpn_peer_delete (&omp->multi_context.peer_db, peers_to_delete[i]);
	}
      vec_free (peers_to_delete);
    }

  return 0;
}

VLIB_REGISTER_NODE (ovpn_periodic_node) = {
  .function = ovpn_periodic_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ovpn-periodic",
};

/*
 * Plugin registration
 */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OpenVPN Protocol",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */