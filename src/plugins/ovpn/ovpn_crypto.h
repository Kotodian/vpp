/*
 * ovpn_crypto.h - OpenVPN data channel crypto
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

#ifndef __included_ovpn_crypto_h__
#define __included_ovpn_crypto_h__

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <ovpn/ovpn_packet.h>

/* Supported cipher algorithms */
typedef enum
{
  OVPN_CIPHER_ALG_NONE = 0,
  OVPN_CIPHER_ALG_AES_128_GCM,
  OVPN_CIPHER_ALG_AES_256_GCM,
  OVPN_CIPHER_ALG_CHACHA20_POLY1305,
} ovpn_cipher_alg_t;

/* Key sizes in bytes */
#define OVPN_KEY_SIZE_128 16
#define OVPN_KEY_SIZE_256 32
#define OVPN_KEY_SIZE_MAX 32

/* IV/Nonce sizes */
#define OVPN_IV_SIZE	     16
#define OVPN_NONCE_SIZE	     12
#define OVPN_IMPLICIT_IV_LEN 8

/* Tag size for AEAD */
#define OVPN_TAG_SIZE 16

/* Replay protection window */
#define OVPN_REPLAY_WINDOW_SIZE 64

/*
 * Crypto key material derived from TLS handshake
 * OpenVPN derives 4 keys: encrypt/decrypt for each direction
 */
typedef struct ovpn_key_material_t_
{
  u8 encrypt_key[OVPN_KEY_SIZE_MAX];
  u8 decrypt_key[OVPN_KEY_SIZE_MAX];
  u8 encrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];
  u8 decrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];
  u8 key_len;
} ovpn_key_material_t;

/*
 * Per-key crypto context
 * Each key_state has its own crypto context
 */
typedef struct ovpn_crypto_context_t_
{
  /* VPP crypto key indices */
  vnet_crypto_key_index_t encrypt_key_index;
  vnet_crypto_key_index_t decrypt_key_index;

  /* Crypto algorithm info */
  ovpn_cipher_alg_t cipher_alg;
  vnet_crypto_op_id_t encrypt_op_id;
  vnet_crypto_op_id_t decrypt_op_id;

  /* Implicit IV for nonce construction */
  u8 encrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];
  u8 decrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];

  /* Packet ID for replay protection */
  u32 packet_id_send;

  /* Replay window for received packets */
  u64 replay_bitmap;
  u32 replay_packet_id_floor;

  /* Key is valid and ready for use */
  u8 is_valid;
} ovpn_crypto_context_t;

/*
 * Per-thread crypto data for batch operations
 */
typedef struct ovpn_per_thread_crypto_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Crypto operation arrays */
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *chained_crypto_ops;
  vnet_crypto_op_chunk_t *chunks;

  /* Async crypto frames */
  vnet_crypto_async_frame_t **async_frames;

  /* Temporary buffer for crypto operations */
  u8 scratch[2048];
} ovpn_per_thread_crypto_t;

/*
 * Initialize crypto subsystem
 */
clib_error_t *ovpn_crypto_init (vlib_main_t *vm);

/*
 * Create crypto context from key material
 */
int ovpn_crypto_context_init (ovpn_crypto_context_t *ctx,
			      ovpn_cipher_alg_t cipher_alg,
			      const ovpn_key_material_t *keys);

/*
 * Destroy crypto context
 */
void ovpn_crypto_context_free (ovpn_crypto_context_t *ctx);

/*
 * Encrypt a data packet (in place)
 * Returns: 0 on success, <0 on error
 *
 * Input buffer should have:
 *   - Space reserved at start for header (OVPN_DATA_V2_MIN_SIZE)
 *   - Plaintext payload
 *   - Space at end for tag (OVPN_TAG_SIZE)
 *
 * Output buffer will contain:
 *   - opcode + peer_id (4 bytes for V2)
 *   - packet_id (4 bytes)
 *   - encrypted payload
 *   - authentication tag (16 bytes)
 */
int ovpn_crypto_encrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			 vlib_buffer_t *b, u32 peer_id, u8 key_id);

/*
 * Decrypt a data packet (in place)
 * Returns: 0 on success, <0 on error
 *
 * Input buffer should contain:
 *   - opcode + peer_id (already parsed, buffer starts at packet_id)
 *   - packet_id (4 bytes)
 *   - encrypted payload
 *   - authentication tag (16 bytes)
 *
 * Output buffer will contain:
 *   - decrypted plaintext payload
 */
int ovpn_crypto_decrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			 vlib_buffer_t *b, u32 *packet_id_out);

/*
 * Check packet ID for replay
 * Returns: 1 if packet is OK, 0 if replay detected
 */
int ovpn_crypto_check_replay (ovpn_crypto_context_t *ctx, u32 packet_id);

/*
 * Update replay window after successful decryption
 */
void ovpn_crypto_update_replay (ovpn_crypto_context_t *ctx, u32 packet_id);

/*
 * Get next packet ID for sending
 */
always_inline u32
ovpn_crypto_get_next_packet_id (ovpn_crypto_context_t *ctx)
{
  return ctx->packet_id_send++;
}

/*
 * Map cipher name string to algorithm enum
 */
ovpn_cipher_alg_t ovpn_crypto_cipher_alg_from_name (const char *name);

/*
 * Get key size for algorithm
 */
always_inline u8
ovpn_crypto_key_size (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return OVPN_KEY_SIZE_128;
    case OVPN_CIPHER_ALG_AES_256_GCM:
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
      return OVPN_KEY_SIZE_256;
    default:
      return 0;
    }
}

/*
 * Static key support for testing
 * In production, keys are derived from TLS handshake
 */
int ovpn_crypto_set_static_key (ovpn_crypto_context_t *ctx,
				ovpn_cipher_alg_t cipher_alg, const u8 *key,
				u8 key_len, const u8 *implicit_iv);

#endif /* __included_ovpn_crypto_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
