/*
 * ovpn_handshake_test.c - OpenVPN handshake unit tests
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
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_crypto.h>

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
 * Test pending database init and free
 */
static int
ovpn_test_pending_db_init (vlib_main_t *vm)
{
  ovpn_pending_db_t db;

  vlib_cli_output (vm, "=== Test Pending DB Init/Free ===\n");

  /* Initialize database */
  ovpn_pending_db_init (&db);

  OVPN_TEST (db.connections == NULL || pool_elts (db.connections) == 0,
	     "Connections pool should be empty");
  OVPN_TEST (db.pending_by_remote != NULL, "Hash should be initialized");
  OVPN_TEST (db.timeout > 0, "Timeout should be set");

  /* Free database */
  ovpn_pending_db_free (&db);

  OVPN_TEST (db.connections == NULL, "Connections should be NULL after free");
  OVPN_TEST (db.pending_by_remote == NULL, "Hash should be NULL after free");

  vlib_cli_output (vm, "Pending DB init/free test PASSED\n");
  return 0;
}

/*
 * Test pending connection create and lookup
 */
static int
ovpn_test_pending_connection_create (vlib_main_t *vm)
{
  ovpn_pending_db_t db;
  ovpn_pending_connection_t *pending1, *pending2, *lookup;
  ip_address_t addr1, addr2;
  ovpn_session_id_t sid;

  vlib_cli_output (vm, "=== Test Pending Connection Create/Lookup ===\n");

  ovpn_pending_db_init (&db);

  /* Setup test addresses */
  clib_memset (&addr1, 0, sizeof (addr1));
  addr1.version = AF_IP4;
  addr1.ip.ip4.as_u32 = 0x0100007f; /* 127.0.0.1 */

  clib_memset (&addr2, 0, sizeof (addr2));
  addr2.version = AF_IP4;
  addr2.ip.ip4.as_u32 = 0x0200007f; /* 127.0.0.2 */

  /* Generate session ID */
  ovpn_session_id_generate (&sid);

  /* Create first pending connection */
  pending1 = ovpn_pending_connection_create (&db, &addr1, 1194, &sid, 0);
  OVPN_TEST (pending1 != NULL, "Should create pending connection 1");
  OVPN_TEST (pending1->state == OVPN_PENDING_STATE_INITIAL,
	     "Initial state should be INITIAL");
  OVPN_TEST (pending1->remote_port == 1194, "Remote port should be 1194");
  OVPN_TEST (pending1->key_id == 0, "Key ID should be 0");
  OVPN_TEST (pending1->send_reliable != NULL,
	     "Send reliable should be allocated");

  /* Lookup should find it */
  lookup = ovpn_pending_connection_lookup (&db, &addr1, 1194);
  OVPN_TEST (lookup == pending1, "Lookup should find pending1");

  /* Create second pending connection */
  pending2 = ovpn_pending_connection_create (&db, &addr2, 1195, &sid, 1);
  OVPN_TEST (pending2 != NULL, "Should create pending connection 2");
  OVPN_TEST (pending2 != pending1, "Should be different from pending1");
  OVPN_TEST (pending2->key_id == 1, "Key ID should be 1");

  /* Lookup should find both */
  lookup = ovpn_pending_connection_lookup (&db, &addr1, 1194);
  OVPN_TEST (lookup == pending1, "Should still find pending1");

  lookup = ovpn_pending_connection_lookup (&db, &addr2, 1195);
  OVPN_TEST (lookup == pending2, "Should find pending2");

  /* Lookup non-existent should return NULL */
  lookup = ovpn_pending_connection_lookup (&db, &addr1, 9999);
  OVPN_TEST (lookup == NULL, "Should not find non-existent connection");

  /* Re-create existing should update it */
  ovpn_session_id_t new_sid;
  ovpn_session_id_generate (&new_sid);
  ovpn_pending_connection_t *updated =
    ovpn_pending_connection_create (&db, &addr1, 1194, &new_sid, 2);
  OVPN_TEST (updated == pending1, "Should return existing connection");
  OVPN_TEST (updated->key_id == 2, "Key ID should be updated to 2");

  /* Verify pool size */
  OVPN_TEST (pool_elts (db.connections) == 2,
	     "Should have 2 pending connections");

  ovpn_pending_db_free (&db);

  vlib_cli_output (vm, "Pending connection create/lookup test PASSED\n");
  return 0;
}

/*
 * Test pending connection delete
 */
static int
ovpn_test_pending_connection_delete (vlib_main_t *vm)
{
  ovpn_pending_db_t db;
  ovpn_pending_connection_t *pending;
  ip_address_t addr;
  ovpn_session_id_t sid;

  vlib_cli_output (vm, "=== Test Pending Connection Delete ===\n");

  ovpn_pending_db_init (&db);

  /* Setup test address */
  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  ovpn_session_id_generate (&sid);

  /* Create pending connection */
  pending = ovpn_pending_connection_create (&db, &addr, 1194, &sid, 0);
  OVPN_TEST (pending != NULL, "Should create pending connection");
  OVPN_TEST (pool_elts (db.connections) == 1, "Should have 1 connection");

  /* Delete it */
  ovpn_pending_connection_delete (&db, pending);

  /* Verify deleted */
  OVPN_TEST (pool_elts (db.connections) == 0,
	     "Should have 0 connections after delete");

  pending = ovpn_pending_connection_lookup (&db, &addr, 1194);
  OVPN_TEST (pending == NULL, "Lookup should return NULL after delete");

  /* Delete NULL should be safe */
  ovpn_pending_connection_delete (&db, NULL);

  ovpn_pending_db_free (&db);

  vlib_cli_output (vm, "Pending connection delete test PASSED\n");
  return 0;
}

/*
 * Test hard-reset state machine
 */
static int
ovpn_test_hard_reset_state_machine (vlib_main_t *vm)
{
  ovpn_pending_db_t db;
  ovpn_pending_connection_t *pending;
  ip_address_t addr;
  ovpn_session_id_t client_sid;

  vlib_cli_output (vm, "=== Test Hard-Reset State Machine ===\n");

  ovpn_pending_db_init (&db);

  /* Setup client address */
  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100a8c0; /* 192.168.0.1 */

  /* Simulate receiving P_CONTROL_HARD_RESET_CLIENT_V2 */
  ovpn_session_id_generate (&client_sid);

  /* Create pending connection (done by handshake processing) */
  pending = ovpn_pending_connection_create (&db, &addr, 12345, &client_sid, 0);
  OVPN_TEST (pending != NULL, "Should create pending connection");

  /* Verify initial state */
  OVPN_TEST (pending->state == OVPN_PENDING_STATE_INITIAL,
	     "State should be INITIAL");
  OVPN_TEST (ovpn_session_id_defined (&pending->local_session_id),
	     "Local session ID should be generated");
  OVPN_TEST (ovpn_session_id_equal (&pending->remote_session_id, &client_sid),
	     "Remote session ID should match client");

  /* Simulate ACK for client's HARD_RESET */
  ovpn_reliable_ack_acknowledge_packet_id (&pending->recv_ack, 0);
  OVPN_TEST (pending->recv_ack.len == 1, "Should have 1 ACK pending");

  /* Simulate sending P_CONTROL_HARD_RESET_SERVER_V2 */
  /* Get buffer for response */
  ovpn_reli_buffer_t *buf =
    ovpn_reliable_get_buf_output_sequenced (pending->send_reliable);
  OVPN_TEST (buf != NULL, "Should get buffer for server reset");

  /* Transition to SENT_RESET */
  pending->state = OVPN_PENDING_STATE_SENT_RESET;
  OVPN_TEST (pending->state == OVPN_PENDING_STATE_SENT_RESET,
	     "State should be SENT_RESET");

  /* Simulate receiving P_ACK_V1 from client */
  ovpn_reliable_send_purge (pending->send_reliable, &pending->recv_ack);

  /* Transition to ESTABLISHED (ready for TLS) */
  pending->state = OVPN_PENDING_STATE_ESTABLISHED;
  OVPN_TEST (pending->state == OVPN_PENDING_STATE_ESTABLISHED,
	     "State should be ESTABLISHED");

  ovpn_pending_db_free (&db);

  vlib_cli_output (vm, "Hard-reset state machine test PASSED\n");
  return 0;
}

/*
 * Test session ID operations in handshake
 */
static int
ovpn_test_session_id_handshake (vlib_main_t *vm)
{
  ovpn_session_id_t sid1, sid2, zero_sid;

  vlib_cli_output (vm, "=== Test Session ID Handshake Operations ===\n");

  /* Generate session IDs */
  ovpn_session_id_generate (&sid1);
  ovpn_session_id_generate (&sid2);
  clib_memset (&zero_sid, 0, sizeof (zero_sid));

  /* Verify generated IDs are not zero */
  OVPN_TEST (ovpn_session_id_defined (&sid1),
	     "Generated session ID 1 should not be zero");
  OVPN_TEST (ovpn_session_id_defined (&sid2),
	     "Generated session ID 2 should not be zero");

  /* Verify zero detection */
  OVPN_TEST (!ovpn_session_id_defined (&zero_sid),
	     "Zero session ID should be detected");

  /* Verify two generated IDs are different (high probability) */
  OVPN_TEST (!ovpn_session_id_equal (&sid1, &sid2),
	     "Two generated IDs should be different");

  /* Verify copy works */
  ovpn_session_id_t sid_copy;
  ovpn_session_id_copy (&sid_copy, &sid1);
  OVPN_TEST (ovpn_session_id_equal (&sid_copy, &sid1),
	     "Copied session ID should equal original");

  vlib_cli_output (vm, "Session ID handshake operations test PASSED\n");
  return 0;
}

/*
 * Test pending connection expiry
 */
static int
ovpn_test_pending_expiry (vlib_main_t *vm)
{
  ovpn_pending_db_t db;
  ovpn_pending_connection_t *pending1, *pending2;
  ip_address_t addr1, addr2;
  ovpn_session_id_t sid;
  f64 now;

  vlib_cli_output (vm, "=== Test Pending Connection Expiry ===\n");

  ovpn_pending_db_init (&db);

  /* Setup addresses */
  clib_memset (&addr1, 0, sizeof (addr1));
  addr1.version = AF_IP4;
  addr1.ip.ip4.as_u32 = 0x01000001;

  clib_memset (&addr2, 0, sizeof (addr2));
  addr2.version = AF_IP4;
  addr2.ip.ip4.as_u32 = 0x02000001;

  ovpn_session_id_generate (&sid);
  now = vlib_time_now (vm);

  /* Create two pending connections */
  pending1 = ovpn_pending_connection_create (&db, &addr1, 1000, &sid, 0);
  pending2 = ovpn_pending_connection_create (&db, &addr2, 1001, &sid, 0);

  OVPN_TEST (pending1 != NULL && pending2 != NULL,
	     "Should create both pending connections");
  OVPN_TEST (pool_elts (db.connections) == 2, "Should have 2 connections");

  /* Manually set one to expire */
  pending1->timeout = now - 10.0; /* Expired 10 seconds ago */
  pending2->timeout = now + 100.0; /* Still valid */

  /* Run expiry */
  ovpn_pending_db_expire (&db, now);

  /* Verify expired one is removed */
  OVPN_TEST (pool_elts (db.connections) == 1,
	     "Should have 1 connection after expiry");
  OVPN_TEST (ovpn_pending_connection_lookup (&db, &addr1, 1000) == NULL,
	     "Expired connection should be removed");
  OVPN_TEST (ovpn_pending_connection_lookup (&db, &addr2, 1001) != NULL,
	     "Valid connection should remain");

  ovpn_pending_db_free (&db);

  vlib_cli_output (vm, "Pending connection expiry test PASSED\n");
  return 0;
}

/*
 * Test peer database init and peer creation
 */
static int
ovpn_test_peer_db_operations (vlib_main_t *vm)
{
  ovpn_peer_db_t db;
  ip_address_t addr;
  u32 peer_id;
  ovpn_peer_t *peer;

  vlib_cli_output (vm, "=== Test Peer DB Operations ===\n");

  /* Initialize peer database */
  ovpn_peer_db_init (&db, 0);

  OVPN_TEST (db.peers == NULL || pool_elts (db.peers) == 0,
	     "Peers pool should be empty");

  /* Setup address */
  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  /* Create peer */
  peer_id = ovpn_peer_create (&db, &addr, 1194);
  OVPN_TEST (peer_id != ~0, "Should create peer");

  /* Get peer */
  peer = ovpn_peer_get (&db, peer_id);
  OVPN_TEST (peer != NULL, "Should get peer by ID");
  OVPN_TEST (peer->peer_id == peer_id, "Peer ID should match");
  OVPN_TEST (peer->remote_port == 1194, "Remote port should match");
  OVPN_TEST (peer->state == OVPN_PEER_STATE_INITIAL, "Initial state");

  /* Verify generation counter starts at 0 */
  OVPN_TEST (ovpn_peer_get_generation (peer) == 0,
	     "Generation should start at 0");

  /* Delete peer */
  ovpn_peer_delete (&db, peer_id);
  OVPN_TEST (pool_elts (db.peers) == 0, "Should have 0 peers after delete");

  ovpn_peer_db_free (&db);

  vlib_cli_output (vm, "Peer DB operations test PASSED\n");
  return 0;
}

/*
 * Test peer state transitions
 */
static int
ovpn_test_peer_state_transitions (vlib_main_t *vm)
{
  ovpn_peer_db_t db;
  ip_address_t addr;
  u32 peer_id;
  ovpn_peer_t *peer;

  vlib_cli_output (vm, "=== Test Peer State Transitions ===\n");

  ovpn_peer_db_init (&db, 0);

  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  peer_id = ovpn_peer_create (&db, &addr, 1194);
  peer = ovpn_peer_get (&db, peer_id);
  OVPN_TEST (peer != NULL, "Should get peer");

  /* Test state transitions */
  OVPN_TEST (ovpn_peer_get_state (peer) == OVPN_PEER_STATE_INITIAL,
	     "Initial state");

  ovpn_peer_set_state (peer, OVPN_PEER_STATE_HANDSHAKE);
  OVPN_TEST (ovpn_peer_get_state (peer) == OVPN_PEER_STATE_HANDSHAKE,
	     "Handshake state");

  ovpn_peer_set_state (peer, OVPN_PEER_STATE_ESTABLISHED);
  OVPN_TEST (ovpn_peer_get_state (peer) == OVPN_PEER_STATE_ESTABLISHED,
	     "Established state");

  /* Verify peer is valid for data processing */
  OVPN_TEST (ovpn_peer_is_established (peer), "Should be established");
  OVPN_TEST (ovpn_peer_is_valid (peer), "Should be valid");

  /* Test rekeying state */
  ovpn_peer_set_state (peer, OVPN_PEER_STATE_REKEYING);
  OVPN_TEST (ovpn_peer_get_state (peer) == OVPN_PEER_STATE_REKEYING,
	     "Rekeying state");
  OVPN_TEST (ovpn_peer_is_established (peer),
	     "Should still be established during rekey");

  /* Test dead state */
  ovpn_peer_set_state (peer, OVPN_PEER_STATE_DEAD);
  OVPN_TEST (ovpn_peer_get_state (peer) == OVPN_PEER_STATE_DEAD, "Dead state");
  OVPN_TEST (!ovpn_peer_is_valid (peer), "Should not be valid when dead");
  OVPN_TEST (!ovpn_peer_is_established (peer),
	     "Should not be established when dead");

  ovpn_peer_delete (&db, peer_id);
  ovpn_peer_db_free (&db);

  vlib_cli_output (vm, "Peer state transitions test PASSED\n");
  return 0;
}

/*
 * Test peer generation counter
 */
static int
ovpn_test_peer_generation_counter (vlib_main_t *vm)
{
  ovpn_peer_db_t db;
  ip_address_t addr;
  u32 peer_id;
  ovpn_peer_t *peer;
  u32 gen1, gen2, gen3;

  vlib_cli_output (vm, "=== Test Peer Generation Counter ===\n");

  ovpn_peer_db_init (&db, 0);

  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  peer_id = ovpn_peer_create (&db, &addr, 1194);
  peer = ovpn_peer_get (&db, peer_id);
  OVPN_TEST (peer != NULL, "Should get peer");

  /* Get initial generation */
  gen1 = ovpn_peer_get_generation (peer);
  OVPN_TEST (gen1 == 0, "Initial generation should be 0");

  /* Increment generation */
  ovpn_peer_increment_generation (peer);
  gen2 = ovpn_peer_get_generation (peer);
  OVPN_TEST (gen2 == gen1 + 1, "Generation should increment by 1");

  /* Increment again */
  ovpn_peer_increment_generation (peer);
  gen3 = ovpn_peer_get_generation (peer);
  OVPN_TEST (gen3 == gen2 + 1, "Generation should increment again");

  ovpn_peer_delete (&db, peer_id);
  ovpn_peer_db_free (&db);

  vlib_cli_output (vm, "Peer generation counter test PASSED\n");
  return 0;
}

/*
 * Test rekey state tracking
 */
static int
ovpn_test_rekey_state (vlib_main_t *vm)
{
  ovpn_peer_db_t db;
  ip_address_t addr;
  u32 peer_id;
  ovpn_peer_t *peer;
  f64 now = vlib_time_now (vm);

  vlib_cli_output (vm, "=== Test Rekey State ===\n");

  ovpn_peer_db_init (&db, 0);

  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  peer_id = ovpn_peer_create (&db, &addr, 1194);
  peer = ovpn_peer_get (&db, peer_id);
  OVPN_TEST (peer != NULL, "Should get peer");

  /* Set to established */
  ovpn_peer_set_state (peer, OVPN_PEER_STATE_ESTABLISHED);

  /* Configure rekey interval */
  peer->rekey_interval = 3600.0; /* 1 hour */
  peer->next_rekey_time = now + 3600.0;
  peer->last_rekey_time = now;
  peer->rekey_initiated = 0;

  /* Should not need rekey yet */
  OVPN_TEST (!ovpn_peer_needs_rekey (peer, now, 0, 0),
	     "Should not need rekey initially");

  /* After rekey interval */
  OVPN_TEST (ovpn_peer_needs_rekey (peer, now + 3601.0, 0, 0),
	     "Should need rekey after interval");

  /* Test reneg-bytes trigger */
  peer->bytes_since_rekey = 100000;
  OVPN_TEST (ovpn_peer_needs_rekey (peer, now, 50000, 0),
	     "Should need rekey when bytes exceeded");
  OVPN_TEST (!ovpn_peer_needs_rekey (peer, now, 200000, 0),
	     "Should not need rekey when bytes not exceeded");

  /* Test reneg-pkts trigger */
  peer->packets_since_rekey = 10000;
  OVPN_TEST (ovpn_peer_needs_rekey (peer, now, 0, 5000),
	     "Should need rekey when packets exceeded");

  /* Should not trigger if already rekeying */
  peer->rekey_initiated = 1;
  OVPN_TEST (!ovpn_peer_needs_rekey (peer, now + 3601.0, 0, 0),
	     "Should not trigger rekey if already initiated");

  ovpn_peer_delete (&db, peer_id);
  ovpn_peer_db_free (&db);

  vlib_cli_output (vm, "Rekey state test PASSED\n");
  return 0;
}

/*
 * Test key ID rotation
 */
static int
ovpn_test_key_id_rotation (vlib_main_t *vm)
{
  ovpn_peer_db_t db;
  ip_address_t addr;
  u32 peer_id;
  ovpn_peer_t *peer;
  u8 key_id;

  vlib_cli_output (vm, "=== Test Key ID Rotation ===\n");

  ovpn_peer_db_init (&db, 0);

  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  peer_id = ovpn_peer_create (&db, &addr, 1194);
  peer = ovpn_peer_get (&db, peer_id);
  OVPN_TEST (peer != NULL, "Should get peer");

  /* Set initial key ID */
  peer->keys[OVPN_KEY_SLOT_PRIMARY].key_id = 0;
  peer->current_key_slot = OVPN_KEY_SLOT_PRIMARY;

  /* Test key ID rotation */
  key_id = ovpn_peer_next_key_id (peer);
  OVPN_TEST (key_id == 1, "Next key ID from 0 should be 1");

  peer->keys[OVPN_KEY_SLOT_PRIMARY].key_id = 1;
  key_id = ovpn_peer_next_key_id (peer);
  OVPN_TEST (key_id == 2, "Next key ID from 1 should be 2");

  /* Test wrap around at 7 */
  peer->keys[OVPN_KEY_SLOT_PRIMARY].key_id = 7;
  key_id = ovpn_peer_next_key_id (peer);
  OVPN_TEST (key_id == 0, "Key ID should wrap from 7 to 0");

  /* Test mask behavior */
  peer->keys[OVPN_KEY_SLOT_PRIMARY].key_id = 6;
  key_id = ovpn_peer_next_key_id (peer);
  OVPN_TEST (key_id == 7, "Next key ID from 6 should be 7");

  ovpn_peer_delete (&db, peer_id);
  ovpn_peer_db_free (&db);

  vlib_cli_output (vm, "Key ID rotation test PASSED\n");
  return 0;
}

/*
 * Test key slot management
 */
static int
ovpn_test_key_slot_management (vlib_main_t *vm)
{
  ovpn_peer_db_t db;
  ip_address_t addr;
  u32 peer_id;
  ovpn_peer_t *peer;

  vlib_cli_output (vm, "=== Test Key Slot Management ===\n");

  ovpn_peer_db_init (&db, 0);

  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  peer_id = ovpn_peer_create (&db, &addr, 1194);
  peer = ovpn_peer_get (&db, peer_id);
  OVPN_TEST (peer != NULL, "Should get peer");

  /* Verify key slot constants */
  OVPN_TEST (OVPN_KEY_SLOT_PRIMARY == 0, "Primary slot should be 0");
  OVPN_TEST (OVPN_KEY_SLOT_SECONDARY == 1, "Secondary slot should be 1");
  OVPN_TEST (OVPN_KEY_SLOT_COUNT == 2, "Should have 2 key slots");

  /* Initialize key slots */
  peer->keys[OVPN_KEY_SLOT_PRIMARY].key_id = 0;
  peer->keys[OVPN_KEY_SLOT_PRIMARY].is_active = 1;
  peer->keys[OVPN_KEY_SLOT_SECONDARY].is_active = 0;
  peer->current_key_slot = OVPN_KEY_SLOT_PRIMARY;

  /* Verify active slot */
  OVPN_TEST (peer->current_key_slot == OVPN_KEY_SLOT_PRIMARY,
	     "Current slot should be primary");
  OVPN_TEST (peer->keys[peer->current_key_slot].is_active,
	     "Current slot should be active");

  /* Simulate rekey: prepare secondary slot */
  peer->keys[OVPN_KEY_SLOT_SECONDARY].key_id = 1;
  peer->keys[OVPN_KEY_SLOT_SECONDARY].is_active = 1;
  peer->pending_key_slot = OVPN_KEY_SLOT_SECONDARY;

  OVPN_TEST (peer->keys[OVPN_KEY_SLOT_PRIMARY].is_active,
	     "Primary should still be active");
  OVPN_TEST (peer->keys[OVPN_KEY_SLOT_SECONDARY].is_active,
	     "Secondary should now be active");

  /* Complete rekey: switch to secondary */
  peer->keys[OVPN_KEY_SLOT_PRIMARY].is_active = 0;
  peer->current_key_slot = OVPN_KEY_SLOT_SECONDARY;

  OVPN_TEST (peer->current_key_slot == OVPN_KEY_SLOT_SECONDARY,
	     "Current slot should be secondary after rekey");
  OVPN_TEST (!peer->keys[OVPN_KEY_SLOT_PRIMARY].is_active,
	     "Primary should be inactive after rekey");

  ovpn_peer_delete (&db, peer_id);
  ovpn_peer_db_free (&db);

  vlib_cli_output (vm, "Key slot management test PASSED\n");
  return 0;
}

/*
 * Test peer activity tracking
 */
static int
ovpn_test_peer_activity (vlib_main_t *vm)
{
  ovpn_peer_db_t db;
  ip_address_t addr;
  u32 peer_id;
  ovpn_peer_t *peer;
  f64 now = vlib_time_now (vm);

  vlib_cli_output (vm, "=== Test Peer Activity Tracking ===\n");

  ovpn_peer_db_init (&db, 0);

  clib_memset (&addr, 0, sizeof (addr));
  addr.version = AF_IP4;
  addr.ip.ip4.as_u32 = 0x0100007f;

  peer_id = ovpn_peer_create (&db, &addr, 1194);
  peer = ovpn_peer_get (&db, peer_id);
  OVPN_TEST (peer != NULL, "Should get peer");

  /* Initialize counters */
  peer->rx_bytes = 0;
  peer->tx_bytes = 0;
  peer->rx_packets = 0;
  peer->tx_packets = 0;
  peer->bytes_since_rekey = 0;
  peer->packets_since_rekey = 0;

  /* Update RX */
  ovpn_peer_update_rx (peer, now, 1000);
  OVPN_TEST (peer->rx_bytes == 1000, "RX bytes should be 1000");
  OVPN_TEST (peer->rx_packets == 1, "RX packets should be 1");
  OVPN_TEST (peer->bytes_since_rekey == 1000,
	     "Bytes since rekey should be 1000");
  OVPN_TEST (peer->packets_since_rekey == 1,
	     "Packets since rekey should be 1");
  OVPN_TEST (peer->last_rx_time == now, "Last RX time should be updated");

  /* Update TX */
  ovpn_peer_update_tx (peer, now + 1.0, 500);
  OVPN_TEST (peer->tx_bytes == 500, "TX bytes should be 500");
  OVPN_TEST (peer->tx_packets == 1, "TX packets should be 1");
  OVPN_TEST (peer->bytes_since_rekey == 1500,
	     "Bytes since rekey should be 1500");
  OVPN_TEST (peer->packets_since_rekey == 2,
	     "Packets since rekey should be 2");
  OVPN_TEST (peer->last_tx_time == now + 1.0, "Last TX time should be updated");

  /* Multiple updates */
  ovpn_peer_update_rx (peer, now + 2.0, 2000);
  OVPN_TEST (peer->rx_bytes == 3000, "RX bytes should be 3000");
  OVPN_TEST (peer->rx_packets == 2, "RX packets should be 2");

  ovpn_peer_delete (&db, peer_id);
  ovpn_peer_db_free (&db);

  vlib_cli_output (vm, "Peer activity tracking test PASSED\n");
  return 0;
}

/*
 * Test TLS-Auth replay protection
 */
static int
ovpn_test_tls_auth_replay (vlib_main_t *vm)
{
  ovpn_tls_auth_t ctx;

  vlib_cli_output (vm, "=== Test TLS-Auth Replay Protection ===\n");

  clib_memset (&ctx, 0, sizeof (ctx));
  ctx.enabled = 1;
  ctx.replay_bitmap = 0;
  ctx.replay_packet_id_floor = 1;
  ctx.time_backtrack = 30; /* 30 second window */
  ctx.replay_time_floor = 0;

  u32 now = 1000;

  /* Packet ID 0 is always invalid */
  OVPN_TEST (!ovpn_tls_auth_check_replay (&ctx, 0, now, now),
	     "Packet ID 0 should be rejected");

  /* First packet should be valid */
  OVPN_TEST (ovpn_tls_auth_check_replay (&ctx, 1, now, now),
	     "Packet ID 1 should be valid");
  ovpn_tls_auth_update_replay (&ctx, 1, now);

  /* Replay should be detected */
  OVPN_TEST (!ovpn_tls_auth_check_replay (&ctx, 1, now, now),
	     "Replay of packet ID 1 should be detected");

  /* New packet should be valid */
  OVPN_TEST (ovpn_tls_auth_check_replay (&ctx, 2, now, now),
	     "Packet ID 2 should be valid");
  ovpn_tls_auth_update_replay (&ctx, 2, now);

  /* Out of order but in window should work */
  OVPN_TEST (ovpn_tls_auth_check_replay (&ctx, 10, now, now),
	     "Packet ID 10 should be valid");
  ovpn_tls_auth_update_replay (&ctx, 10, now);

  /* Timestamp too old should fail */
  OVPN_TEST (!ovpn_tls_auth_check_replay (&ctx, 11, now - 60, now),
	     "Old timestamp should be rejected");

  /* Timestamp in future (within tolerance) should pass */
  OVPN_TEST (ovpn_tls_auth_check_replay (&ctx, 12, now + 10, now),
	     "Near-future timestamp should be accepted");

  /* Timestamp too far in future should fail */
  OVPN_TEST (!ovpn_tls_auth_check_replay (&ctx, 13, now + 60, now),
	     "Far-future timestamp should be rejected");

  vlib_cli_output (vm, "TLS-Auth replay protection test PASSED\n");
  return 0;
}

/*
 * Test TLS-Crypt replay protection
 */
static int
ovpn_test_tls_crypt_replay (vlib_main_t *vm)
{
  ovpn_tls_crypt_t ctx;

  vlib_cli_output (vm, "=== Test TLS-Crypt Replay Protection ===\n");

  clib_memset (&ctx, 0, sizeof (ctx));
  ctx.enabled = 1;
  ctx.replay_bitmap = 0;
  ctx.replay_packet_id_floor = 1;
  ctx.time_backtrack = 30;
  ctx.replay_time_floor = 0;

  u32 now = 2000;

  /* Packet ID 0 is invalid */
  OVPN_TEST (!ovpn_tls_crypt_check_replay (&ctx, 0, now, now),
	     "Packet ID 0 should be rejected");

  /* First valid packet */
  OVPN_TEST (ovpn_tls_crypt_check_replay (&ctx, 1, now, now),
	     "Packet ID 1 should be valid");
  ovpn_tls_crypt_update_replay (&ctx, 1, now);

  /* Replay detection */
  OVPN_TEST (!ovpn_tls_crypt_check_replay (&ctx, 1, now, now),
	     "Replay should be detected");

  /* Window advancement */
  for (u32 i = 2; i <= 70; i++)
    {
      OVPN_TEST (ovpn_tls_crypt_check_replay (&ctx, i, now, now),
		 "Packet ID %u should be valid", i);
      ovpn_tls_crypt_update_replay (&ctx, i, now);
    }

  /* Packet before window should fail */
  OVPN_TEST (!ovpn_tls_crypt_check_replay (&ctx, 1, now, now),
	     "Packet before window should be rejected");

  /* Packet at floor should fail */
  OVPN_TEST (!ovpn_tls_crypt_check_replay (&ctx, ctx.replay_packet_id_floor - 1,
					   now, now),
	     "Packet at floor should be rejected");

  vlib_cli_output (vm, "TLS-Crypt replay protection test PASSED\n");
  return 0;
}

/*
 * Test pending remote hash key generation
 */
static int
ovpn_test_pending_hash_key (vlib_main_t *vm)
{
  ip_address_t addr4_1, addr4_2, addr6;
  u64 key1, key2, key3, key4, key5;

  vlib_cli_output (vm, "=== Test Pending Remote Hash Key ===\n");

  /* Setup IPv4 addresses */
  clib_memset (&addr4_1, 0, sizeof (addr4_1));
  addr4_1.version = AF_IP4;
  addr4_1.ip.ip4.as_u32 = 0x0100007f;

  clib_memset (&addr4_2, 0, sizeof (addr4_2));
  addr4_2.version = AF_IP4;
  addr4_2.ip.ip4.as_u32 = 0x0200007f;

  /* Setup IPv6 address */
  clib_memset (&addr6, 0, sizeof (addr6));
  addr6.version = AF_IP6;
  addr6.ip.ip6.as_u64[0] = 0x1;
  addr6.ip.ip6.as_u64[1] = 0x2;

  /* Same address, different port should give different keys */
  key1 = ovpn_pending_remote_hash_key (&addr4_1, 1000);
  key2 = ovpn_pending_remote_hash_key (&addr4_1, 1001);
  OVPN_TEST (key1 != key2, "Different ports should give different keys");

  /* Different address, same port should give different keys */
  key3 = ovpn_pending_remote_hash_key (&addr4_2, 1000);
  OVPN_TEST (key1 != key3, "Different addresses should give different keys");

  /* Same address and port should give same key */
  key4 = ovpn_pending_remote_hash_key (&addr4_1, 1000);
  OVPN_TEST (key1 == key4, "Same address and port should give same key");

  /* IPv6 should work */
  key5 = ovpn_pending_remote_hash_key (&addr6, 1000);
  OVPN_TEST (key5 != key1, "IPv6 key should differ from IPv4 key");

  vlib_cli_output (vm, "Pending remote hash key test PASSED\n");
  return 0;
}

/*
 * Run all handshake tests
 */
static int
ovpn_handshake_test_all (vlib_main_t *vm)
{
  int rv = 0;

  vlib_cli_output (vm, "\n========================================\n");
  vlib_cli_output (vm, "OpenVPN Handshake Unit Tests\n");
  vlib_cli_output (vm, "========================================\n\n");

  rv |= ovpn_test_pending_db_init (vm);
  rv |= ovpn_test_pending_connection_create (vm);
  rv |= ovpn_test_pending_connection_delete (vm);
  rv |= ovpn_test_hard_reset_state_machine (vm);
  rv |= ovpn_test_session_id_handshake (vm);
  rv |= ovpn_test_pending_expiry (vm);
  rv |= ovpn_test_peer_db_operations (vm);
  rv |= ovpn_test_peer_state_transitions (vm);
  rv |= ovpn_test_peer_generation_counter (vm);
  rv |= ovpn_test_rekey_state (vm);
  rv |= ovpn_test_key_id_rotation (vm);
  rv |= ovpn_test_key_slot_management (vm);
  rv |= ovpn_test_peer_activity (vm);
  rv |= ovpn_test_tls_auth_replay (vm);
  rv |= ovpn_test_tls_crypt_replay (vm);
  rv |= ovpn_test_pending_hash_key (vm);

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
 * CLI command to run handshake tests
 */
static clib_error_t *
ovpn_handshake_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  int rv;

  rv = ovpn_handshake_test_all (vm);

  if (rv)
    return clib_error_return (0, "Tests failed");

  return 0;
}

VLIB_CLI_COMMAND (ovpn_handshake_test_command, static) = {
  .path = "test ovpn handshake",
  .short_help = "test ovpn handshake - run OpenVPN handshake unit tests",
  .function = ovpn_handshake_test_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
