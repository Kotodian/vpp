/*
 * ovpn_crypto.c - OpenVPN data channel crypto implementation
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

#include <ovpn/ovpn_crypto.h>
#include <vnet/crypto/crypto.h>

/* Per-thread crypto data */
static ovpn_per_thread_crypto_t *ovpn_per_thread_crypto;

clib_error_t *
ovpn_crypto_init (vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_threads = tm->n_vlib_mains;

  vec_validate_aligned (ovpn_per_thread_crypto, n_threads - 1,
			CLIB_CACHE_LINE_BYTES);

  for (u32 i = 0; i < n_threads; i++)
    {
      ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[i];
      vec_validate_aligned (ptd->crypto_ops, 0, CLIB_CACHE_LINE_BYTES);
      vec_reset_length (ptd->crypto_ops);
    }

  return 0;
}

ovpn_cipher_alg_t
ovpn_crypto_cipher_alg_from_name (const char *name)
{
  if (!name)
    return OVPN_CIPHER_ALG_NONE;

  if (strncasecmp (name, "AES-128-GCM", 11) == 0)
    return OVPN_CIPHER_ALG_AES_128_GCM;
  if (strncasecmp (name, "AES-256-GCM", 11) == 0)
    return OVPN_CIPHER_ALG_AES_256_GCM;
  if (strncasecmp (name, "CHACHA20-POLY1305", 17) == 0)
    return OVPN_CIPHER_ALG_CHACHA20_POLY1305;

  return OVPN_CIPHER_ALG_NONE;
}

static vnet_crypto_alg_t
ovpn_crypto_get_vnet_alg (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return VNET_CRYPTO_ALG_AES_128_GCM;
    case OVPN_CIPHER_ALG_AES_256_GCM:
      return VNET_CRYPTO_ALG_AES_256_GCM;
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
      return VNET_CRYPTO_ALG_CHACHA20_POLY1305;
    default:
      return VNET_CRYPTO_ALG_NONE;
    }
}

static vnet_crypto_op_id_t
ovpn_crypto_get_enc_op (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return VNET_CRYPTO_OP_AES_128_GCM_ENC;
    case OVPN_CIPHER_ALG_AES_256_GCM:
      return VNET_CRYPTO_OP_AES_256_GCM_ENC;
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
      return VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC;
    default:
      return VNET_CRYPTO_OP_NONE;
    }
}

static vnet_crypto_op_id_t
ovpn_crypto_get_dec_op (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return VNET_CRYPTO_OP_AES_128_GCM_DEC;
    case OVPN_CIPHER_ALG_AES_256_GCM:
      return VNET_CRYPTO_OP_AES_256_GCM_DEC;
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
      return VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC;
    default:
      return VNET_CRYPTO_OP_NONE;
    }
}

int
ovpn_crypto_context_init (ovpn_crypto_context_t *ctx,
			  ovpn_cipher_alg_t cipher_alg,
			  const ovpn_key_material_t *keys)
{
  vnet_crypto_alg_t vnet_alg;
  u8 key_len;

  clib_memset (ctx, 0, sizeof (*ctx));

  if (cipher_alg == OVPN_CIPHER_ALG_NONE)
    return -1;

  vnet_alg = ovpn_crypto_get_vnet_alg (cipher_alg);
  if (vnet_alg == VNET_CRYPTO_ALG_NONE)
    return -1;

  key_len = ovpn_crypto_key_size (cipher_alg);
  if (key_len == 0 || key_len != keys->key_len)
    return -1;

  ctx->cipher_alg = cipher_alg;

  /* Add encryption key */
  ctx->encrypt_key_index =
    vnet_crypto_key_add (vlib_get_main (), vnet_alg,
			 (u8 *) keys->encrypt_key, key_len);

  /* Add decryption key */
  ctx->decrypt_key_index =
    vnet_crypto_key_add (vlib_get_main (), vnet_alg,
			 (u8 *) keys->decrypt_key, key_len);

  /* Set up operation IDs */
  ctx->encrypt_op_id = ovpn_crypto_get_enc_op (cipher_alg);
  ctx->decrypt_op_id = ovpn_crypto_get_dec_op (cipher_alg);

  /* Copy implicit IVs */
  clib_memcpy_fast (ctx->encrypt_implicit_iv, keys->encrypt_implicit_iv,
		    OVPN_IMPLICIT_IV_LEN);
  clib_memcpy_fast (ctx->decrypt_implicit_iv, keys->decrypt_implicit_iv,
		    OVPN_IMPLICIT_IV_LEN);

  /* Initialize counters */
  ctx->packet_id_send = 1;
  ctx->replay_bitmap = 0;
  ctx->replay_packet_id_floor = 0;

  ctx->is_valid = 1;

  return 0;
}

void
ovpn_crypto_context_free (ovpn_crypto_context_t *ctx)
{
  if (!ctx->is_valid)
    return;

  vnet_crypto_key_del (vlib_get_main (), ctx->encrypt_key_index);
  vnet_crypto_key_del (vlib_get_main (), ctx->decrypt_key_index);

  clib_memset (ctx, 0, sizeof (*ctx));
}

int
ovpn_crypto_set_static_key (ovpn_crypto_context_t *ctx,
			    ovpn_cipher_alg_t cipher_alg, const u8 *key,
			    u8 key_len, const u8 *implicit_iv)
{
  ovpn_key_material_t keys;

  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = key_len;

  /* For static key mode, use same key for both directions */
  clib_memcpy_fast (keys.encrypt_key, key, key_len);
  clib_memcpy_fast (keys.decrypt_key, key, key_len);

  if (implicit_iv)
    {
      clib_memcpy_fast (keys.encrypt_implicit_iv, implicit_iv,
			OVPN_IMPLICIT_IV_LEN);
      clib_memcpy_fast (keys.decrypt_implicit_iv, implicit_iv,
			OVPN_IMPLICIT_IV_LEN);
    }

  return ovpn_crypto_context_init (ctx, cipher_alg, &keys);
}

int
ovpn_crypto_check_replay (ovpn_crypto_context_t *ctx, u32 packet_id)
{
  u32 diff;

  if (packet_id == 0)
    return 0; /* packet_id 0 is never valid */

  if (packet_id < ctx->replay_packet_id_floor)
    return 0; /* Too old */

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= OVPN_REPLAY_WINDOW_SIZE)
    return 1; /* Ahead of window, OK */

  /* Check bitmap */
  if (ctx->replay_bitmap & (1ULL << diff))
    return 0; /* Already seen */

  return 1;
}

void
ovpn_crypto_update_replay (ovpn_crypto_context_t *ctx, u32 packet_id)
{
  u32 diff;

  if (packet_id < ctx->replay_packet_id_floor)
    return;

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= OVPN_REPLAY_WINDOW_SIZE)
    {
      /* Advance window */
      u32 shift = diff - OVPN_REPLAY_WINDOW_SIZE + 1;
      if (shift >= 64)
	ctx->replay_bitmap = 0;
      else
	ctx->replay_bitmap >>= shift;
      ctx->replay_packet_id_floor += shift;
      diff = packet_id - ctx->replay_packet_id_floor;
    }

  /* Mark as seen */
  ctx->replay_bitmap |= (1ULL << diff);
}

int
ovpn_crypto_encrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
		     vlib_buffer_t *b, u32 peer_id, u8 key_id)
{
  u32 thread_index = vm->thread_index;
  ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[thread_index];
  vnet_crypto_op_t *op;
  ovpn_data_v2_header_t *hdr;
  ovpn_aead_nonce_t nonce;
  u32 packet_id;
  u8 *payload;
  u32 payload_len;
  u8 *tag;

  if (!ctx->is_valid)
    return -1;

  /* Get next packet ID */
  packet_id = ovpn_crypto_get_next_packet_id (ctx);

  /* Calculate payload length (current buffer data) */
  payload_len = b->current_length;

  /* Reserve space for header at the beginning */
  hdr =
    (ovpn_data_v2_header_t *) vlib_buffer_push_uninit (b, sizeof (*hdr));

  /* Fill in header */
  hdr->opcode_keyid = ovpn_op_compose (OVPN_OP_DATA_V2, key_id);
  ovpn_data_v2_set_peer_id (hdr, peer_id);
  hdr->packet_id = clib_host_to_net_u32 (packet_id);

  /* Payload starts after header */
  payload = (u8 *) (hdr + 1);

  /* Tag goes at the end */
  tag = vlib_buffer_put_uninit (b, OVPN_TAG_SIZE);

  /* Build nonce */
  ovpn_aead_nonce_build (&nonce, packet_id, ctx->encrypt_implicit_iv);

  /* Set up crypto operation */
  vec_reset_length (ptd->crypto_ops);
  vec_add2 (ptd->crypto_ops, op, 1);

  vnet_crypto_op_init (op, ctx->encrypt_op_id);
  op->key_index = ctx->encrypt_key_index;
  op->iv = (u8 *) &nonce;
  op->src = payload;
  op->dst = payload;
  op->len = payload_len;
  op->aad = (u8 *) hdr;
  op->aad_len = sizeof (*hdr);
  op->tag = tag;
  op->tag_len = OVPN_TAG_SIZE;

  /* Execute crypto operation */
  vnet_crypto_process_ops (vm, ptd->crypto_ops, 1);

  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -1;

  return 0;
}

int
ovpn_crypto_decrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
		     vlib_buffer_t *b, u32 *packet_id_out)
{
  u32 thread_index = vm->thread_index;
  ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[thread_index];
  vnet_crypto_op_t *op;
  ovpn_aead_nonce_t nonce;
  u32 packet_id;
  u8 *src;
  u32 src_len;
  u8 *tag;
  u8 *aad;
  u32 aad_len;

  if (!ctx->is_valid)
    return -1;

  /*
   * Buffer should point to start of OpenVPN packet (opcode byte)
   * Layout: [opcode+keyid:1][peer_id:3][packet_id:4][ciphertext][tag:16]
   */
  src_len = b->current_length;

  if (src_len < OVPN_DATA_V2_MIN_SIZE + OVPN_TAG_SIZE)
    return -1;

  /* AAD is the full header (opcode + peer_id + packet_id) */
  aad = vlib_buffer_get_current (b);
  aad_len = sizeof (ovpn_data_v2_header_t);

  /* Extract packet_id */
  packet_id = clib_net_to_host_u32 (((ovpn_data_v2_header_t *) aad)->packet_id);

  /* Check replay */
  if (!ovpn_crypto_check_replay (ctx, packet_id))
    return -2; /* Replay detected */

  /* Ciphertext starts after the header */
  src = aad + aad_len;
  src_len = src_len - aad_len - OVPN_TAG_SIZE;

  /* Tag is at the end */
  tag = aad + b->current_length - OVPN_TAG_SIZE;

  /* Build nonce */
  ovpn_aead_nonce_build (&nonce, packet_id, ctx->decrypt_implicit_iv);

  /* Set up crypto operation */
  vec_reset_length (ptd->crypto_ops);
  vec_add2 (ptd->crypto_ops, op, 1);

  vnet_crypto_op_init (op, ctx->decrypt_op_id);
  op->key_index = ctx->decrypt_key_index;
  op->iv = (u8 *) &nonce;
  op->src = src;
  op->dst = src;
  op->len = src_len;
  op->aad = aad;
  op->aad_len = aad_len;
  op->tag = tag;
  op->tag_len = OVPN_TAG_SIZE;

  /* Execute crypto operation */
  vnet_crypto_process_ops (vm, ptd->crypto_ops, 1);

  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -3; /* Decryption/auth failed */

  /* Update replay window */
  ovpn_crypto_update_replay (ctx, packet_id);

  /* Advance buffer past header to plaintext */
  vlib_buffer_advance (b, aad_len); /* Skip header */

  /* Trim tag from end */
  b->current_length -= OVPN_TAG_SIZE;

  if (packet_id_out)
    *packet_id_out = packet_id;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
