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

ovpn_per_thread_crypto_t *
ovpn_crypto_get_ptd (u32 thread_index)
{
  return &ovpn_per_thread_crypto[thread_index];
}

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
      vec_validate_aligned (ptd->chained_crypto_ops, 0, CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (ptd->chunks, 0, CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (ptd->ivs, 0, CLIB_CACHE_LINE_BYTES);
      vec_reset_length (ptd->crypto_ops);
      vec_reset_length (ptd->chained_crypto_ops);
      vec_reset_length (ptd->chunks);
      vec_reset_length (ptd->ivs);
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
			  const ovpn_key_material_t *keys, u32 replay_window)
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
  ctx->replay_bitmap_ext = NULL;
  ctx->replay_packet_id_floor = 0;

  /* Configure replay window size */
  if (replay_window == 0)
    replay_window = OVPN_REPLAY_WINDOW_SIZE_DEFAULT;
  else if (replay_window < OVPN_REPLAY_WINDOW_SIZE_MIN)
    replay_window = OVPN_REPLAY_WINDOW_SIZE_MIN;
  else if (replay_window > OVPN_REPLAY_WINDOW_SIZE_MAX)
    replay_window = OVPN_REPLAY_WINDOW_SIZE_MAX;

  /* Round up to multiple of 64 for bitmap alignment */
  replay_window = (replay_window + 63) & ~63;
  ctx->replay_window_size = replay_window;

  /* Allocate extended bitmap for windows larger than 64 */
  if (replay_window > 64)
    {
      u32 n_words = replay_window / 64;
      vec_validate_aligned (ctx->replay_bitmap_ext, n_words - 1,
			    CLIB_CACHE_LINE_BYTES);
      clib_memset (ctx->replay_bitmap_ext, 0, n_words * sizeof (u64));
    }

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

  /* Free extended replay bitmap if allocated */
  if (ctx->replay_bitmap_ext)
    vec_free (ctx->replay_bitmap_ext);

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

  return ovpn_crypto_context_init (ctx, cipher_alg, &keys,
				   0 /* use default replay window */);
}

/*
 * Helper: Check bit in extended bitmap
 */
static_always_inline int
ovpn_replay_bitmap_ext_check (const u64 *bitmap, u32 bit_pos)
{
  u32 word_idx = bit_pos / 64;
  u32 bit_idx = bit_pos % 64;
  return (bitmap[word_idx] & (1ULL << bit_idx)) != 0;
}

/*
 * Helper: Set bit in extended bitmap
 */
static_always_inline void
ovpn_replay_bitmap_ext_set (u64 *bitmap, u32 bit_pos)
{
  u32 word_idx = bit_pos / 64;
  u32 bit_idx = bit_pos % 64;
  bitmap[word_idx] |= (1ULL << bit_idx);
}

/*
 * Helper: Shift extended bitmap right by n bits
 */
static_always_inline void
ovpn_replay_bitmap_ext_shift (u64 *bitmap, u32 n_words, u32 shift)
{
  if (shift >= n_words * 64)
    {
      clib_memset (bitmap, 0, n_words * sizeof (u64));
      return;
    }

  u32 word_shift = shift / 64;
  u32 bit_shift = shift % 64;

  if (word_shift > 0)
    {
      for (u32 i = 0; i < n_words - word_shift; i++)
	bitmap[i] = bitmap[i + word_shift];
      for (u32 i = n_words - word_shift; i < n_words; i++)
	bitmap[i] = 0;
    }

  if (bit_shift > 0)
    {
      for (u32 i = 0; i < n_words - 1; i++)
	bitmap[i] = (bitmap[i] >> bit_shift) | (bitmap[i + 1] << (64 - bit_shift));
      bitmap[n_words - 1] >>= bit_shift;
    }
}

int
ovpn_crypto_check_replay (ovpn_crypto_context_t *ctx, u32 packet_id)
{
  u32 diff;
  u32 window_size = ctx->replay_window_size;

  if (packet_id == 0)
    return 0; /* packet_id 0 is never valid */

  if (packet_id < ctx->replay_packet_id_floor)
    return 0; /* Too old */

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= window_size)
    return 1; /* Ahead of window, OK */

  /* Check bitmap - use fast path for small windows */
  if (window_size <= 64)
    {
      if (ctx->replay_bitmap & (1ULL << diff))
	return 0; /* Already seen */
    }
  else
    {
      if (ovpn_replay_bitmap_ext_check (ctx->replay_bitmap_ext, diff))
	return 0; /* Already seen */
    }

  return 1;
}

void
ovpn_crypto_update_replay (ovpn_crypto_context_t *ctx, u32 packet_id)
{
  u32 diff;
  u32 window_size = ctx->replay_window_size;

  if (packet_id < ctx->replay_packet_id_floor)
    return;

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= window_size)
    {
      /* Advance window */
      u32 shift = diff - window_size + 1;

      if (window_size <= 64)
	{
	  if (shift >= 64)
	    ctx->replay_bitmap = 0;
	  else
	    ctx->replay_bitmap >>= shift;
	}
      else
	{
	  u32 n_words = window_size / 64;
	  ovpn_replay_bitmap_ext_shift (ctx->replay_bitmap_ext, n_words, shift);
	}

      ctx->replay_packet_id_floor += shift;
      diff = packet_id - ctx->replay_packet_id_floor;
    }

  /* Mark as seen */
  if (window_size <= 64)
    ctx->replay_bitmap |= (1ULL << diff);
  else
    ovpn_replay_bitmap_ext_set (ctx->replay_bitmap_ext, diff);
}

/*
 * Build chunks for chained buffer crypto operations
 * This creates chunk descriptors for each buffer in the chain
 */
static_always_inline void
ovpn_crypto_chain_chunks (vlib_main_t *vm, ovpn_per_thread_crypto_t *ptd,
			  vlib_buffer_t *b, vlib_buffer_t *lb, u8 *start,
			  u32 start_len, u16 *n_ch, i32 last_buf_adj)
{
  vnet_crypto_op_chunk_t *ch;
  vlib_buffer_t *cb = b;
  u32 n_chunks = 1;

  /* First chunk from the first buffer */
  vec_add2 (ptd->chunks, ch, 1);
  ch->len = start_len;
  ch->src = ch->dst = start;

  /* Move to next buffer in chain */
  if (cb->flags & VLIB_BUFFER_NEXT_PRESENT)
    cb = vlib_get_buffer (vm, cb->next_buffer);
  else
    goto done;

  /* Process remaining buffers in chain */
  while (1)
    {
      vec_add2 (ptd->chunks, ch, 1);
      n_chunks += 1;

      /* Last buffer may need adjustment (e.g., exclude tag) */
      if (lb == cb)
	ch->len = cb->current_length + last_buf_adj;
      else
	ch->len = cb->current_length;

      ch->src = ch->dst = vlib_buffer_get_current (cb);

      if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;

      cb = vlib_get_buffer (vm, cb->next_buffer);
    }

done:
  if (n_ch)
    *n_ch = n_chunks;
}

/*
 * Find the last buffer in a chain
 */
static_always_inline vlib_buffer_t *
ovpn_find_last_buffer (vlib_main_t *vm, vlib_buffer_t *b)
{
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    b = vlib_get_buffer (vm, b->next_buffer);
  return b;
}

/*
 * Prepare encryption operation for a buffer (supports chained buffers)
 */
int
ovpn_crypto_encrypt_prepare (vlib_main_t *vm, ovpn_per_thread_crypto_t *ptd,
			     ovpn_crypto_context_t *ctx, vlib_buffer_t *b,
			     u32 bi, u32 peer_id, u8 key_id)
{
  vlib_buffer_t *lb;
  vnet_crypto_op_t *op;
  ovpn_data_v2_header_t *hdr;
  u32 n_bufs;
  u32 packet_id;
  u8 *payload;
  u32 payload_len;
  u8 *tag;
  u8 *iv;

  if (!ctx->is_valid)
    return -1;

  /* Linearize buffer chain if needed */
  lb = b;
  n_bufs = vlib_buffer_chain_linearize (vm, b);
  if (n_bufs == 0)
    return -2; /* No buffers available */

  /* Find last buffer in chain */
  if (n_bufs > 1)
    lb = ovpn_find_last_buffer (vm, b);

  /* Ensure there is enough space at the end of last buffer for auth tag */
  if (PREDICT_FALSE (vlib_buffer_space_left_at_end (vm, lb) < OVPN_TAG_SIZE))
    {
      u32 tmp_bi = 0;
      if (vlib_buffer_alloc (vm, &tmp_bi, 1) != 1)
	return -3; /* No buffers available */
      lb = vlib_buffer_chain_buffer (vm, lb, tmp_bi);
    }

  /* Calculate payload length from chain before modifying */
  payload_len = vlib_buffer_length_in_chain (vm, b);

  /* Reserve space for header at the beginning */
  hdr =
    (ovpn_data_v2_header_t *) vlib_buffer_push_uninit (b, sizeof (*hdr));

  /* Get next packet ID */
  packet_id = ovpn_crypto_get_next_packet_id (ctx);

  /* Fill in header */
  hdr->opcode_keyid = ovpn_op_compose (OVPN_OP_DATA_V2, key_id);
  ovpn_data_v2_set_peer_id (hdr, peer_id);
  hdr->packet_id = clib_host_to_net_u32 (packet_id);

  /* Payload starts after header */
  payload = (u8 *) (hdr + 1);

  /* Reserve space for tag at end of chain */
  vlib_buffer_chain_increase_length (b, lb, OVPN_TAG_SIZE);

  /* Tag goes at the end of last buffer */
  tag = vlib_buffer_get_tail (lb) - OVPN_TAG_SIZE;

  /* Allocate IV storage */
  vec_add2 (ptd->ivs, iv, OVPN_NONCE_SIZE);
  ovpn_aead_nonce_build ((ovpn_aead_nonce_t *) iv, packet_id,
			 ctx->encrypt_implicit_iv);

  /* Set up crypto operation */
  if (b != lb)
    {
      /* Chained buffers - use chunked crypto */
      vec_add2_aligned (ptd->chained_crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->encrypt_op_id);

      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
      op->chunk_index = vec_len (ptd->chunks);
      ovpn_crypto_chain_chunks (vm, ptd, b, lb, payload, b->current_length -
						sizeof (*hdr),
				&op->n_chunks, -OVPN_TAG_SIZE);
    }
  else
    {
      /* Single buffer */
      vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->encrypt_op_id);

      op->src = payload;
      op->dst = payload;
      op->len = payload_len;
    }

  op->key_index = ctx->encrypt_key_index;
  op->iv = iv;
  op->aad = (u8 *) hdr;
  op->aad_len = sizeof (*hdr);
  op->tag = tag;
  op->tag_len = OVPN_TAG_SIZE;
  op->user_data = bi;

  return 0;
}

/*
 * Prepare decryption operation for a buffer (supports chained buffers)
 */
int
ovpn_crypto_decrypt_prepare (vlib_main_t *vm, ovpn_per_thread_crypto_t *ptd,
			     ovpn_crypto_context_t *ctx, vlib_buffer_t *b,
			     u32 bi, u32 *packet_id_out)
{
  vlib_buffer_t *lb;
  vnet_crypto_op_t *op;
  u32 n_bufs;
  u32 packet_id;
  u8 *aad;
  u32 aad_len;
  u8 *src;
  u32 src_len;
  u32 total_len;
  u8 *tag;
  u8 *iv;

  if (!ctx->is_valid)
    return -1;

  /* Linearize buffer chain if needed */
  lb = b;
  n_bufs = vlib_buffer_chain_linearize (vm, b);
  if (n_bufs == 0)
    return -2; /* No buffers available */

  /* Find last buffer in chain */
  if (n_bufs > 1)
    {
      vlib_buffer_t *before_last = b;
      lb = b;

      while (lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  before_last = lb;
	  lb = vlib_get_buffer (vm, lb->next_buffer);
	}

      /*
       * Ensure auth tag is contiguous in the last buffer
       * (not split across the last two buffers)
       */
      if (PREDICT_FALSE (lb->current_length < OVPN_TAG_SIZE))
	{
	  u32 len_diff = OVPN_TAG_SIZE - lb->current_length;

	  before_last->current_length -= len_diff;
	  if (before_last == b)
	    before_last->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  vlib_buffer_advance (lb, (signed) -len_diff);
	  clib_memcpy_fast (vlib_buffer_get_current (lb),
			    vlib_buffer_get_tail (before_last), len_diff);
	}
    }

  /* Get total length from chain */
  total_len = vlib_buffer_length_in_chain (vm, b);

  /*
   * Buffer should point to start of OpenVPN packet (opcode byte)
   * Layout: [opcode+keyid:1][peer_id:3][packet_id:4][ciphertext][tag:16]
   */
  if (total_len < OVPN_DATA_V2_MIN_SIZE + OVPN_TAG_SIZE)
    return -3;

  /* AAD is the full header (opcode + peer_id + packet_id) */
  aad = vlib_buffer_get_current (b);
  aad_len = sizeof (ovpn_data_v2_header_t);

  /* Extract packet_id */
  packet_id = clib_net_to_host_u32 (((ovpn_data_v2_header_t *) aad)->packet_id);

  /* Check replay */
  if (!ovpn_crypto_check_replay (ctx, packet_id))
    return -4; /* Replay detected */

  /* Ciphertext starts after the header */
  src = aad + aad_len;
  src_len = total_len - aad_len - OVPN_TAG_SIZE;

  /* Tag is at the end of the last buffer */
  tag = vlib_buffer_get_tail (lb) - OVPN_TAG_SIZE;

  /* Allocate IV storage */
  vec_add2 (ptd->ivs, iv, OVPN_NONCE_SIZE);
  ovpn_aead_nonce_build ((ovpn_aead_nonce_t *) iv, packet_id,
			 ctx->decrypt_implicit_iv);

  /* Set up crypto operation */
  if (b != lb)
    {
      /* Chained buffers - use chunked crypto */
      vec_add2_aligned (ptd->chained_crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->decrypt_op_id);

      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
      op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
      op->chunk_index = vec_len (ptd->chunks);

      /* For decrypt, include tag in chunk calculation for verification */
      ovpn_crypto_chain_chunks (vm, ptd, b, lb, src,
				b->current_length - aad_len, &op->n_chunks,
				0);
    }
  else
    {
      /* Single buffer */
      vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->decrypt_op_id);

      op->src = src;
      op->dst = src;
      op->len = src_len;
      op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
    }

  op->key_index = ctx->decrypt_key_index;
  op->iv = iv;
  op->aad = aad;
  op->aad_len = aad_len;
  op->tag = tag;
  op->tag_len = OVPN_TAG_SIZE;
  op->user_data = bi;

  if (packet_id_out)
    *packet_id_out = packet_id;

  return 0;
}

/*
 * Process all pending encryption operations
 */
void
ovpn_crypto_encrypt_process (vlib_main_t *vm, vlib_node_runtime_t *node,
			     ovpn_per_thread_crypto_t *ptd,
			     vlib_buffer_t *bufs[], u16 *nexts, u16 drop_next)
{
  u32 n_ops, n_chained_ops;
  u32 n_fail;
  vnet_crypto_op_t *op;

  /* Process single-buffer operations */
  n_ops = vec_len (ptd->crypto_ops);
  if (n_ops > 0)
    {
      op = ptd->crypto_ops;
      n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

      while (n_fail)
	{
	  ASSERT (op - ptd->crypto_ops < n_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Encrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }

  /* Process chained-buffer operations */
  n_chained_ops = vec_len (ptd->chained_crypto_ops);
  if (n_chained_ops > 0)
    {
      op = ptd->chained_crypto_ops;
      n_fail = n_chained_ops -
	       vnet_crypto_process_chained_ops (vm, op, ptd->chunks,
						n_chained_ops);

      while (n_fail)
	{
	  ASSERT (op - ptd->chained_crypto_ops < n_chained_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Encrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }
}

/*
 * Process all pending decryption operations
 */
void
ovpn_crypto_decrypt_process (vlib_main_t *vm, vlib_node_runtime_t *node,
			     ovpn_per_thread_crypto_t *ptd,
			     vlib_buffer_t *bufs[], u16 *nexts, u16 drop_next)
{
  u32 n_ops, n_chained_ops;
  u32 n_fail;
  vnet_crypto_op_t *op;

  /* Process single-buffer operations */
  n_ops = vec_len (ptd->crypto_ops);
  if (n_ops > 0)
    {
      op = ptd->crypto_ops;
      n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

      while (n_fail)
	{
	  ASSERT (op - ptd->crypto_ops < n_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Decrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }

  /* Process chained-buffer operations */
  n_chained_ops = vec_len (ptd->chained_crypto_ops);
  if (n_chained_ops > 0)
    {
      op = ptd->chained_crypto_ops;
      n_fail = n_chained_ops -
	       vnet_crypto_process_chained_ops (vm, op, ptd->chunks,
						n_chained_ops);

      while (n_fail)
	{
	  ASSERT (op - ptd->chained_crypto_ops < n_chained_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Decrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }
}

/*
 * Legacy single-packet encrypt function (kept for compatibility)
 * Uses the new batch infrastructure internally
 */
int
ovpn_crypto_encrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
		     vlib_buffer_t *b, u32 peer_id, u8 key_id)
{
  u32 thread_index = vm->thread_index;
  ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[thread_index];
  int rv;

  ovpn_crypto_reset_ptd (ptd);

  rv = ovpn_crypto_encrypt_prepare (vm, ptd, ctx, b, 0, peer_id, key_id);
  if (rv < 0)
    return rv;

  /* Process single-buffer ops */
  if (vec_len (ptd->crypto_ops) > 0)
    {
      vnet_crypto_process_ops (vm, ptd->crypto_ops, vec_len (ptd->crypto_ops));
      if (ptd->crypto_ops[0].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -1;
    }

  /* Process chained-buffer ops */
  if (vec_len (ptd->chained_crypto_ops) > 0)
    {
      vnet_crypto_process_chained_ops (vm, ptd->chained_crypto_ops,
				       ptd->chunks,
				       vec_len (ptd->chained_crypto_ops));
      if (ptd->chained_crypto_ops[0].status !=
	  VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -1;
    }

  return 0;
}

/*
 * Legacy single-packet decrypt function (kept for compatibility)
 * Uses the new batch infrastructure internally
 */
int
ovpn_crypto_decrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
		     vlib_buffer_t *b, u32 *packet_id_out)
{
  u32 thread_index = vm->thread_index;
  ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[thread_index];
  vlib_buffer_t *lb;
  u32 aad_len = sizeof (ovpn_data_v2_header_t);
  int rv;

  ovpn_crypto_reset_ptd (ptd);

  rv = ovpn_crypto_decrypt_prepare (vm, ptd, ctx, b, 0, packet_id_out);
  if (rv < 0)
    return rv;

  /* Process single-buffer ops */
  if (vec_len (ptd->crypto_ops) > 0)
    {
      vnet_crypto_process_ops (vm, ptd->crypto_ops, vec_len (ptd->crypto_ops));
      if (ptd->crypto_ops[0].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -3;
    }

  /* Process chained-buffer ops */
  if (vec_len (ptd->chained_crypto_ops) > 0)
    {
      vnet_crypto_process_chained_ops (vm, ptd->chained_crypto_ops,
				       ptd->chunks,
				       vec_len (ptd->chained_crypto_ops));
      if (ptd->chained_crypto_ops[0].status !=
	  VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -3;
    }

  /* Update replay window */
  if (packet_id_out && *packet_id_out)
    ovpn_crypto_update_replay (ctx, *packet_id_out);

  /* Find last buffer */
  lb = ovpn_find_last_buffer (vm, b);

  /* Advance buffer past header to plaintext */
  vlib_buffer_advance (b, aad_len);

  /* Remove tag from chain length */
  vlib_buffer_chain_increase_length (b, lb, -OVPN_TAG_SIZE);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
