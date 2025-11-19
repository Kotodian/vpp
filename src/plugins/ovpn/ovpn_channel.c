/*
 * ovpn_channel.c - ovpn channel source file
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>.
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

#include <picotls/openssl.h>
#include <picotls.h>
#include <vppinfra/random.h>
#include <ovpn/ovpn_channel.h>
#include <ovpn/private.h>
#include <openssl/conf.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/kdf.h>

void
ovpn_channel_init (vlib_main_t *vm, ovpn_channel_t *ch,
		   ptls_context_t *ssl_ctx, u64 remote_session_id,
		   ip46_address_t *remote_addr, u8 is_ip4, u32 ch_index)
{
  clib_memset (ch, 0, sizeof (ovpn_channel_t));
  ch->index = ch_index;
  ch->seed = 0x1badf00d;
  ch->state = OVPN_CHANNEL_STATE_INIT;
  ch->expired_time = vlib_time_now (vm) + OVN_CHANNEL_EXPIRED_TIMEOUT;
  ch->tls = ptls_new (ssl_ctx, 1);
  ch->session_id = random_u64 (&ch->seed);
  ch->remote_session_id = remote_session_id;
  ch->is_ip4 = is_ip4;
  ch->key_source_index = ~0;
  ch->hs_data = NULL;
  ch->hs_data_off = 0;
  clib_memcpy_fast (&ch->remote_addr, remote_addr, sizeof (ip46_address_t));
}

/* TLS1 PRF = P_MD5 XOR P_SHA1 */
static bool
ovpn_ssl_tls1_PRF (const uint8_t *seed, int seed_len, const uint8_t *secret,
		   int secret_len, uint8_t *output, int output_len)
{
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_TLS1_PRF, NULL);
  if (!pctx)
    {
      return false;
    }

  bool ret = false;
  if (!EVP_PKEY_derive_init (pctx))
    {
      goto out;
    }

  if (!EVP_PKEY_CTX_set_tls1_prf_md (pctx, EVP_md5_sha1 ()))
    {
      goto out;
    }

  if (!EVP_PKEY_CTX_set1_tls1_prf_secret (pctx, secret, secret_len))
    {
      goto out;
    }

  if (!EVP_PKEY_CTX_add1_tls1_prf_seed (pctx, seed, seed_len))
    {
      goto out;
    }

  size_t out_len = output_len;
  if (!EVP_PKEY_derive (pctx, output, &out_len))
    {
      goto out;
    }
  if (out_len != output_len)
    {
      goto out;
    }
  ret = true;
out:
  EVP_PKEY_CTX_free (pctx);
  return ret;
}

bool
ovpn_channel_derive_key_material_server (ovpn_channel_t *ch,
					 ovpn_key_source_t *ks,
					 ovpn_key2_t *key2)
{
  u8 master[48];

  // 1. 随机生成 server PRF seeds
  ptls_openssl_random_bytes (ks->server_prf_seed_master_secret, 32);
  ptls_openssl_random_bytes (ks->server_prf_seed_key_expansion, 32);

  // 2. 生成 master secret
  // 拼接 seed = "OpenVPN master secret" + client_seed + server_seed
  u8 master_seed[19 + 32 + 32];
  clib_memcpy_fast (master_seed, "OpenVPN master secret", 19);
  clib_memcpy_fast (master_seed + 19, ks->client_prf_seed_master_secret, 32);
  clib_memcpy_fast (master_seed + 19 + 32, ks->server_prf_seed_master_secret,
		    32);

  if (!ovpn_ssl_tls1_PRF (
	master_seed, sizeof (master_seed), ks->pre_master_secret,
	sizeof (ks->pre_master_secret), master, sizeof (master)))
    return false;

  // 3. 构建 key expansion seed
  u8 key_exp_seed[23 + 32 + 32 + 8 + 8]; // label + client_seed + server_seed +
					 // client_sid + server_sid
  clib_memcpy_fast (key_exp_seed, "OpenVPN key expansion", 23);
  clib_memcpy_fast (key_exp_seed + 23, ks->client_prf_seed_key_expansion, 32);
  clib_memcpy_fast (key_exp_seed + 23 + 32, ks->server_prf_seed_key_expansion,
		    32);

  u64 client_sid = ch->remote_session_id;
  u64 server_sid = ch->session_id;
  clib_memcpy_fast (key_exp_seed + 23 + 64, &client_sid, 8);
  clib_memcpy_fast (key_exp_seed + 23 + 72, &server_sid, 8);

  // 4. 生成 key expansion，填充到 key2->keys
  if (!ovpn_ssl_tls1_PRF (key_exp_seed, sizeof (key_exp_seed), master,
			  sizeof (master), (uint8_t *) key2->keys,
			  sizeof (key2->keys)))
    {
      ovpn_secure_zero_memory (master, sizeof (master));
      return false;
    }

  ovpn_secure_zero_memory (master, sizeof (master));
  key2->n = 2; // 两套单向 key

  return true;
}

void
ovpn_channel_free (ovpn_channel_t *ch)
{
  if (ch->hs_data != NULL)
    vec_free (ch->hs_data);
  ch->hs_data_off = 0;
  ptls_free (ch->tls);
  vec_free (ch->client_acks);
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
