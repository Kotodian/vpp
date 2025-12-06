/*
 * ovpn_ssl.c - ovpn ssl source file
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

#include <ovpn/ovpn_ssl.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_crypto.h>
#include <picotls/openssl.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>

/* Global pool for reliable buffers */
ovpn_reli_buffer_t *ovpn_buf_pool;

/* Zero session ID for comparison */
const ovpn_session_id_t x_session_id_zero = { .id = { 0 } };

static ovpn_key_source2_t *ovpn_key_source2s;

always_inline void
ovpn_secure_zero_memory (void *ptr, size_t size)
{
  static void *(*const volatile memset_v) (void *, int, size_t) = &memset;
  memset_v (ptr, 0, size);
}

ovpn_key_source2_t *
ovpn_key_source2_alloc (void)
{
  ovpn_key_source2_t *key_src2;
  pool_get (ovpn_key_source2s, key_src2);
  clib_memset (key_src2, 0, sizeof (ovpn_key_source2_t));
  key_src2->index = key_src2 - ovpn_key_source2s;
  return key_src2;
}

void
ovpn_key_source2_free (ovpn_key_source2_t *key_src2)
{
  ovpn_secure_zero_memory (key_src2, sizeof (ovpn_key_source2_t));
  pool_put_index (ovpn_key_source2s, key_src2->index);
}

/*
 * Derive data channel keys from TLS session
 *
 * Uses TLS 1.3 exporter to derive keys for OpenVPN data channel.
 * The exporter uses labels to derive separate keys for each direction.
 */
int
ovpn_derive_data_channel_keys (ptls_t *tls, ovpn_key_material_t *keys,
			       ovpn_cipher_alg_t cipher_alg, int is_server)
{
  u8 key_len;
  int ret;

  /* Determine key length based on cipher */
  key_len = ovpn_crypto_key_size (cipher_alg);
  if (key_len == 0)
    return -1;

  clib_memset (keys, 0, sizeof (*keys));
  keys->key_len = key_len;

  /*
   * Use TLS 1.3 exporter to derive keys
   * Labels follow OpenVPN's data channel key derivation
   */
  static const char *label_s2c = "EXPORTER-OpenVPN-datakey-server";
  static const char *label_c2s = "EXPORTER-OpenVPN-datakey-client";
  static const char *label_s2c_iv = "EXPORTER-OpenVPN-dataiv-server";
  static const char *label_c2s_iv = "EXPORTER-OpenVPN-dataiv-client";

  /* Export keys using picotls exporter */
  if (is_server)
    {
      /* Server: encrypt with s2c key, decrypt with c2s key */
      ret = ptls_export_secret (tls, keys->encrypt_key, key_len, label_s2c,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -2;

      ret = ptls_export_secret (tls, keys->decrypt_key, key_len, label_c2s,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -3;

      /* Export implicit IVs */
      ret = ptls_export_secret (tls, keys->encrypt_implicit_iv,
				OVPN_IMPLICIT_IV_LEN, label_s2c_iv,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -4;

      ret = ptls_export_secret (tls, keys->decrypt_implicit_iv,
				OVPN_IMPLICIT_IV_LEN, label_c2s_iv,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -5;
    }
  else
    {
      /* Client: encrypt with c2s key, decrypt with s2c key */
      ret = ptls_export_secret (tls, keys->encrypt_key, key_len, label_c2s,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -2;

      ret = ptls_export_secret (tls, keys->decrypt_key, key_len, label_s2c,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -3;

      /* Export implicit IVs */
      ret = ptls_export_secret (tls, keys->encrypt_implicit_iv,
				OVPN_IMPLICIT_IV_LEN, label_c2s_iv,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -4;

      ret = ptls_export_secret (tls, keys->decrypt_implicit_iv,
				OVPN_IMPLICIT_IV_LEN, label_s2c_iv,
				ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -5;
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */