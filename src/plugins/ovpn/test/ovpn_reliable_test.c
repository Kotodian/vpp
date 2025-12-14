/*
 * ovpn_reliable_test.c - OpenVPN reliable layer unit tests
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
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_buffer.h>
#include <ovpn/ovpn_session_id.h>

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
 * Test ACK structure operations
 */
static int
ovpn_test_ack_operations (vlib_main_t *vm)
{
  ovpn_reliable_ack_t ack;
  int rv;

  vlib_cli_output (vm, "=== Test ACK Operations ===\n");

  /* Initialize ACK structure */
  clib_memset (&ack, 0, sizeof (ack));

  /* Test empty check */
  OVPN_TEST (ovpn_reliable_ack_empty (&ack) == 1, "ACK should be empty");
  OVPN_TEST (ovpn_reliable_ack_outstanding (&ack) == 0,
	     "No outstanding ACKs expected");

  /* Add packet ID */
  rv = ovpn_reliable_ack_acknowledge_packet_id (&ack, 1);
  OVPN_TEST (rv == 1, "Should add packet_id 1");
  OVPN_TEST (ack.len == 1, "ACK len should be 1");
  OVPN_TEST (ack.packet_id[0] == 1, "packet_id[0] should be 1");

  /* Add duplicate - should fail */
  rv = ovpn_reliable_ack_acknowledge_packet_id (&ack, 1);
  OVPN_TEST (rv == 0, "Should not add duplicate packet_id");
  OVPN_TEST (ack.len == 1, "ACK len should still be 1");

  /* Add more packet IDs */
  rv = ovpn_reliable_ack_acknowledge_packet_id (&ack, 2);
  OVPN_TEST (rv == 1, "Should add packet_id 2");
  rv = ovpn_reliable_ack_acknowledge_packet_id (&ack, 3);
  OVPN_TEST (rv == 1, "Should add packet_id 3");
  OVPN_TEST (ack.len == 3, "ACK len should be 3");

  /* Test not empty */
  OVPN_TEST (ovpn_reliable_ack_empty (&ack) == 0, "ACK should not be empty");
  OVPN_TEST (ovpn_reliable_ack_outstanding (&ack) == 1,
	     "Should have outstanding ACKs");

  /* Fill to capacity */
  for (u32 i = 4; i <= OVPN_RELIABLE_ACK_SIZE; i++)
    {
      rv = ovpn_reliable_ack_acknowledge_packet_id (&ack, i);
      OVPN_TEST (rv == 1, "Should add packet_id %u", i);
    }
  OVPN_TEST (ack.len == OVPN_RELIABLE_ACK_SIZE, "ACK should be at capacity");

  /* Try to add beyond capacity - should fail */
  rv = ovpn_reliable_ack_acknowledge_packet_id (&ack, 100);
  OVPN_TEST (rv == 0, "Should not add beyond capacity");

  vlib_cli_output (vm, "ACK operations test PASSED\n");
  return 0;
}

/*
 * Test ACK parse and write
 */
static int
ovpn_test_ack_parse_write (vlib_main_t *vm)
{
  ovpn_reliable_ack_t ack_write, ack_read, ack_mru;
  ovpn_reli_buffer_t buf;
  ovpn_session_id_t sid, sid_read;
  u32 buf_idx;
  int rv;

  vlib_cli_output (vm, "=== Test ACK Parse/Write ===\n");

  /* Initialize */
  clib_memset (&ack_write, 0, sizeof (ack_write));
  clib_memset (&ack_read, 0, sizeof (ack_read));
  clib_memset (&ack_mru, 0, sizeof (ack_mru));

  /* Generate session ID */
  ovpn_session_id_generate (&sid);

  /* Add some ACKs */
  ovpn_reliable_ack_acknowledge_packet_id (&ack_write, 10);
  ovpn_reliable_ack_acknowledge_packet_id (&ack_write, 11);
  ovpn_reliable_ack_acknowledge_packet_id (&ack_write, 12);

  /* Allocate buffer */
  buf_idx = ovpn_buf_alloc (256);
  ovpn_reli_buffer_t *pbuf = ovpn_buf_get (buf_idx);
  OVPN_TEST (pbuf != NULL, "Buffer allocation should succeed");
  ovpn_buf_init (pbuf, 64);

  /* Write ACKs to buffer */
  rv = ovpn_reliable_ack_write (&ack_write, &ack_mru, pbuf, &sid, 3, 0);
  OVPN_TEST (rv == 0, "ACK write should succeed");

  /* Prepare buffer for reading */
  clib_memset (&buf, 0, sizeof (buf));
  buf.data = OVPN_BPTR (pbuf);
  buf.offset = 0;
  buf.len = OVPN_BLEN (pbuf);
  buf.capacity = OVPN_BLEN (pbuf);

  /* Parse ACKs from buffer */
  rv = ovpn_reliable_ack_parse (&buf, &ack_read, &sid_read);
  OVPN_TEST (rv == 1, "ACK parse should succeed");
  OVPN_TEST (ack_read.len == 3, "Should read 3 ACKs, got %u", ack_read.len);

  /* Verify session ID */
  OVPN_TEST (ovpn_session_id_equal (&sid, &sid_read),
	     "Session IDs should match");

  /* Verify packet IDs - MRU order (most recently added first) */
  vlib_cli_output (vm, "ACKs read: %u, %u, %u\n", ack_read.packet_id[0],
		   ack_read.packet_id[1], ack_read.packet_id[2]);
  OVPN_TEST (ack_read.packet_id[0] == 12, "First ACK should be 12 (MRU)");
  OVPN_TEST (ack_read.packet_id[1] == 11, "Second ACK should be 11");
  OVPN_TEST (ack_read.packet_id[2] == 10, "Third ACK should be 10");

  /* Free buffer */
  ovpn_buf_free (pbuf);

  vlib_cli_output (vm, "ACK parse/write test PASSED\n");
  return 0;
}

/*
 * Test reliable structure init and free
 */
static int
ovpn_test_reliable_init (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;

  vlib_cli_output (vm, "=== Test Reliable Init/Free ===\n");

  /* Allocate and initialize */
  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  OVPN_TEST (rel != NULL, "Reliable allocation should succeed");

  ovpn_reliable_init (rel, 1024, 64, 4, 0);

  OVPN_TEST (rel->size == 4, "Size should be 4");
  OVPN_TEST (rel->offset == 64, "Offset should be 64");
  OVPN_TEST (rel->packet_id == 0, "Initial packet_id should be 0");
  OVPN_TEST (rel->hold == 0, "Hold should be 0");

  /* All entries should be inactive */
  for (int i = 0; i < rel->size; i++)
    {
      OVPN_TEST (rel->array[i].active == 0, "Entry %d should be inactive", i);
    }

  /* Free */
  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  /* Test with hold = 1 */
  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 8, 1);
  OVPN_TEST (rel->hold == 1, "Hold should be 1");
  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Reliable init/free test PASSED\n");
  return 0;
}

/*
 * Test buffer management
 */
static int
ovpn_test_buffer_management (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;
  ovpn_reli_buffer_t *buf;

  vlib_cli_output (vm, "=== Test Buffer Management ===\n");

  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 4, 0);

  /* Should be able to get buffers */
  OVPN_TEST (ovpn_reliable_can_get (rel) == 1, "Should have free buffers");

  /* Get all buffers */
  for (int i = 0; i < 4; i++)
    {
      buf = ovpn_reliable_get_buf (rel);
      OVPN_TEST (buf != NULL, "Should get buffer %d", i);

      /* Mark as active (simulating incoming packet) */
      ovpn_reliable_mark_active_incoming (rel, buf, i, 0x20);
    }

  /* Should not be able to get more */
  OVPN_TEST (ovpn_reliable_can_get (rel) == 0, "Should have no free buffers");

  buf = ovpn_reliable_get_buf (rel);
  OVPN_TEST (buf == NULL, "Should return NULL when full");

  /* Check reliable is not empty */
  OVPN_TEST (ovpn_reliable_empty (rel) == 0, "Reliable should not be empty");

  /* Free one entry */
  buf = ovpn_buf_get (rel->array[0].buf_index);
  ovpn_reliable_mark_deleted (rel, buf);

  /* Should be able to get one buffer now */
  OVPN_TEST (ovpn_reliable_can_get (rel) == 1, "Should have one free buffer");

  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Buffer management test PASSED\n");
  return 0;
}

/*
 * Test replay detection
 */
static int
ovpn_test_replay_detection (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;
  ovpn_reli_buffer_t *buf;

  vlib_cli_output (vm, "=== Test Replay Detection ===\n");

  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 4, 0);

  /* Packet ID 0 should be valid initially */
  OVPN_TEST (ovpn_reliable_not_replay (rel, 0) == 1,
	     "Packet ID 0 should not be replay");

  /* Add packet with ID 0 */
  buf = ovpn_reliable_get_buf (rel);
  ovpn_reliable_mark_active_incoming (rel, buf, 0, 0x20);

  /* Packet ID 0 should now be replay */
  OVPN_TEST (ovpn_reliable_not_replay (rel, 0) == 0,
	     "Packet ID 0 should be replay");

  /* Packet ID 1 should be valid */
  OVPN_TEST (ovpn_reliable_not_replay (rel, 1) == 1,
	     "Packet ID 1 should not be replay");

  /* Mark packet 0 as deleted (advance window) */
  buf = ovpn_buf_get (rel->array[0].buf_index);
  ovpn_reliable_mark_deleted (rel, buf);

  /* Now packet_id base is 1, so 0 is old and should be replay */
  OVPN_TEST (ovpn_reliable_not_replay (rel, 0) == 0,
	     "Old packet ID 0 should be replay");

  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Replay detection test PASSED\n");
  return 0;
}

/*
 * Test sequentiality check
 */
static int
ovpn_test_sequentiality (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;

  vlib_cli_output (vm, "=== Test Sequentiality ===\n");

  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 4, 0);

  /* Packets within window size should be OK */
  OVPN_TEST (ovpn_reliable_wont_break_sequentiality (rel, 0) == 1,
	     "Packet 0 within window");
  OVPN_TEST (ovpn_reliable_wont_break_sequentiality (rel, 1) == 1,
	     "Packet 1 within window");
  OVPN_TEST (ovpn_reliable_wont_break_sequentiality (rel, 3) == 1,
	     "Packet 3 within window");

  /* Packet beyond window should fail */
  OVPN_TEST (ovpn_reliable_wont_break_sequentiality (rel, 4) == 0,
	     "Packet 4 beyond window");
  OVPN_TEST (ovpn_reliable_wont_break_sequentiality (rel, 100) == 0,
	     "Packet 100 beyond window");

  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Sequentiality test PASSED\n");
  return 0;
}

/*
 * Test outgoing packet operations
 */
static int
ovpn_test_outgoing_packets (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;
  ovpn_reli_buffer_t *buf;
  u8 opcode;

  vlib_cli_output (vm, "=== Test Outgoing Packets ===\n");

  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 4, 1); /* hold = 1 */
  ovpn_reliable_set_timeout (rel, 2.0);

  /* With hold=1, can_send should return false */
  OVPN_TEST (ovpn_reliable_can_send (vm, rel) == 0,
	     "Should not send while held");

  /* Get sequenced buffer */
  buf = ovpn_reliable_get_buf_output_sequenced (rel);
  OVPN_TEST (buf != NULL, "Should get output buffer");

  /* Write some data */
  u8 test_data[] = "Hello OpenVPN";
  ovpn_buf_write (buf, test_data, sizeof (test_data));

  /* Mark as active outgoing */
  ovpn_reliable_mark_active_outgoing (rel, buf, 0x20);

  /* Check packet_id was assigned */
  OVPN_TEST (rel->array[0].packet_id == 0, "First packet should have ID 0");
  OVPN_TEST (rel->packet_id == 1, "Next packet_id should be 1");

  /* Still held, can't send */
  OVPN_TEST (ovpn_reliable_can_send (vm, rel) == 0, "Still held");

  /* Schedule now (removes hold) */
  ovpn_reliable_schedule_now (vm, rel);
  OVPN_TEST (rel->hold == 0, "Hold should be cleared");

  /* Now can send */
  OVPN_TEST (ovpn_reliable_can_send (vm, rel) == 1, "Should be able to send");

  /* Get packet to send */
  buf = ovpn_reliable_send (vm, rel, &opcode);
  OVPN_TEST (buf != NULL, "Should get buffer to send");
  OVPN_TEST (opcode == 0x20, "Opcode should be 0x20");

  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Outgoing packets test PASSED\n");
  return 0;
}

/*
 * Test send purge (ACK processing)
 */
static int
ovpn_test_send_purge (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;
  ovpn_reliable_ack_t ack;
  ovpn_reli_buffer_t *buf;

  vlib_cli_output (vm, "=== Test Send Purge ===\n");

  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 4, 0);
  ovpn_reliable_set_timeout (rel, 2.0);

  /* Add 3 outgoing packets */
  for (int i = 0; i < 3; i++)
    {
      buf = ovpn_reliable_get_buf_output_sequenced (rel);
      OVPN_TEST (buf != NULL, "Should get buffer %d", i);
      ovpn_reliable_mark_active_outgoing (rel, buf, 0x20);
    }

  /* Verify all active */
  OVPN_TEST (rel->array[0].active == 1, "Entry 0 should be active");
  OVPN_TEST (rel->array[1].active == 1, "Entry 1 should be active");
  OVPN_TEST (rel->array[2].active == 1, "Entry 2 should be active");

  /* Create ACK for packet 1 */
  clib_memset (&ack, 0, sizeof (ack));
  ovpn_reliable_ack_acknowledge_packet_id (&ack, 1);

  /* Purge acknowledged packets */
  ovpn_reliable_send_purge (rel, &ack);

  /* Packet 1 should be inactive */
  OVPN_TEST (rel->array[1].active == 0, "Entry 1 should be purged");

  /* Packets 0 and 2 should still be active */
  OVPN_TEST (rel->array[0].active == 1, "Entry 0 should still be active");
  OVPN_TEST (rel->array[2].active == 1, "Entry 2 should still be active");

  /* Packet 0 should have n_acks incremented (later packet was ACKed) */
  OVPN_TEST (rel->array[0].n_acks == 1, "Entry 0 n_acks should be 1");

  /* ACK packet 0 */
  clib_memset (&ack, 0, sizeof (ack));
  ovpn_reliable_ack_acknowledge_packet_id (&ack, 0);
  ovpn_reliable_send_purge (rel, &ack);

  OVPN_TEST (rel->array[0].active == 0, "Entry 0 should be purged");

  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Send purge test PASSED\n");
  return 0;
}

/*
 * Test sequenced entry retrieval (in-order processing)
 */
static int
ovpn_test_sequenced_retrieval (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;
  ovpn_reli_buffer_t *buf;
  ovpn_reliable_entry_t *entry;

  vlib_cli_output (vm, "=== Test Sequenced Retrieval ===\n");

  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 4, 0);

  /* Add packets out of order: 2, 0, 1 */
  buf = ovpn_reliable_get_buf (rel);
  ovpn_reliable_mark_active_incoming (rel, buf, 2, 0x20);

  buf = ovpn_reliable_get_buf (rel);
  ovpn_reliable_mark_active_incoming (rel, buf, 0, 0x20);

  buf = ovpn_reliable_get_buf (rel);
  ovpn_reliable_mark_active_incoming (rel, buf, 1, 0x20);

  /* Get sequenced entry - should return packet 0 first */
  entry = ovpn_reliable_get_entry_sequenced (rel);
  OVPN_TEST (entry != NULL, "Should get entry");
  OVPN_TEST (entry->packet_id == 0, "First entry should be packet 0");

  /* Mark as processed */
  buf = ovpn_buf_get (entry->buf_index);
  ovpn_reliable_mark_deleted (rel, buf);

  /* Get next - should be packet 1 */
  entry = ovpn_reliable_get_entry_sequenced (rel);
  OVPN_TEST (entry != NULL, "Should get entry");
  OVPN_TEST (entry->packet_id == 1, "Second entry should be packet 1");

  buf = ovpn_buf_get (entry->buf_index);
  ovpn_reliable_mark_deleted (rel, buf);

  /* Get next - should be packet 2 */
  entry = ovpn_reliable_get_entry_sequenced (rel);
  OVPN_TEST (entry != NULL, "Should get entry");
  OVPN_TEST (entry->packet_id == 2, "Third entry should be packet 2");

  buf = ovpn_buf_get (entry->buf_index);
  ovpn_reliable_mark_deleted (rel, buf);

  /* No more entries */
  entry = ovpn_reliable_get_entry_sequenced (rel);
  OVPN_TEST (entry == NULL, "Should have no more entries");

  /* Reliable should be empty */
  OVPN_TEST (ovpn_reliable_empty (rel) == 1, "Reliable should be empty");

  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Sequenced retrieval test PASSED\n");
  return 0;
}

/*
 * Test timeout handling
 */
static int
ovpn_test_timeout (vlib_main_t *vm)
{
  ovpn_reliable_t *rel;
  ovpn_reli_buffer_t *buf;
  f64 timeout;

  vlib_cli_output (vm, "=== Test Timeout ===\n");

  rel = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (rel, 512, 32, 4, 0);
  ovpn_reliable_set_timeout (rel, 5.0);

  /* No entries - big timeout */
  timeout = ovpn_reliable_send_timeout (vm, rel);
  OVPN_TEST (timeout >= OVPN_BIG_TIMEOUT - 1, "Empty should have big timeout");

  /* Add outgoing packet */
  buf = ovpn_reliable_get_buf_output_sequenced (rel);
  ovpn_reliable_mark_active_outgoing (rel, buf, 0x20);

  /* Should be ready to send immediately (next_try = 0) */
  timeout = ovpn_reliable_send_timeout (vm, rel);
  OVPN_TEST (timeout == 0, "New packet should be ready to send");

  /* Schedule now sets timeout */
  ovpn_reliable_schedule_now (vm, rel);

  /* After scheduling, timeout should be ~initial_timeout */
  timeout = ovpn_reliable_send_timeout (vm, rel);
  OVPN_TEST (timeout <= 5.0 && timeout >= 0.0, "Timeout should be <= 5.0");

  ovpn_reliable_free (rel);
  clib_mem_free (rel);

  vlib_cli_output (vm, "Timeout test PASSED\n");
  return 0;
}

/*
 * Test copy ACKs to MRU
 */
static int
ovpn_test_ack_mru (vlib_main_t *vm)
{
  ovpn_reliable_ack_t ack, ack_mru;

  vlib_cli_output (vm, "=== Test ACK MRU ===\n");

  clib_memset (&ack, 0, sizeof (ack));
  clib_memset (&ack_mru, 0, sizeof (ack_mru));

  /* Add ACKs */
  ovpn_reliable_ack_acknowledge_packet_id (&ack, 10);
  ovpn_reliable_ack_acknowledge_packet_id (&ack, 20);
  ovpn_reliable_ack_acknowledge_packet_id (&ack, 30);

  /* Copy to MRU */
  ovpn_reliable_copy_acks_to_mru (&ack, &ack_mru, 2);

  OVPN_TEST (ack_mru.len >= 2, "MRU should have at least 2 entries");
  OVPN_TEST (ack_mru.packet_id[0] == 20 || ack_mru.packet_id[0] == 10,
	     "MRU should contain copied IDs");

  /* Copy more - should update MRU */
  ovpn_reliable_copy_acks_to_mru (&ack, &ack_mru, 3);
  OVPN_TEST (ack_mru.len >= 3, "MRU should have at least 3 entries");

  vlib_cli_output (vm, "ACK MRU test PASSED\n");
  return 0;
}

/*
 * Run all tests
 */
static int
ovpn_reliable_test_all (vlib_main_t *vm)
{
  int rv = 0;

  vlib_cli_output (vm, "\n========================================\n");
  vlib_cli_output (vm, "OpenVPN Reliable Layer Unit Tests\n");
  vlib_cli_output (vm, "========================================\n\n");

  rv |= ovpn_test_ack_operations (vm);
  rv |= ovpn_test_ack_parse_write (vm);
  rv |= ovpn_test_reliable_init (vm);
  rv |= ovpn_test_buffer_management (vm);
  rv |= ovpn_test_replay_detection (vm);
  rv |= ovpn_test_sequentiality (vm);
  rv |= ovpn_test_outgoing_packets (vm);
  rv |= ovpn_test_send_purge (vm);
  rv |= ovpn_test_sequenced_retrieval (vm);
  rv |= ovpn_test_timeout (vm);
  rv |= ovpn_test_ack_mru (vm);

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
ovpn_reliable_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  int rv;

  rv = ovpn_reliable_test_all (vm);

  if (rv)
    return clib_error_return (0, "Tests failed");

  return 0;
}

VLIB_CLI_COMMAND (ovpn_reliable_test_command, static) = {
  .path = "test ovpn reliable",
  .short_help = "test ovpn reliable - run OpenVPN reliable layer unit tests",
  .function = ovpn_reliable_test_command_fn,
};

/*
 * Plugin registration
 */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OpenVPN Reliable Layer Unit Tests",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
