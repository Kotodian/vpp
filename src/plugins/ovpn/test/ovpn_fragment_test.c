/*
 * ovpn_fragment_test.c - OpenVPN fragmentation unit tests
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
#include <ovpn/ovpn_fragment.h>

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
 * Test fragment header make/parse
 */
static int
ovpn_test_frag_header (vlib_main_t *vm)
{
  u32 hdr;
  u8 frag_type, seq_id, frag_id;
  u16 frag_size;

  vlib_cli_output (vm, "=== Test Fragment Header Make/Parse ===\n");

  /* Test FRAG_WHOLE header */
  hdr = ovpn_frag_make_header (OVPN_FRAG_WHOLE, 0, 0, 0);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_WHOLE, "Type should be WHOLE");
  OVPN_TEST (seq_id == 0, "Seq ID should be 0");
  OVPN_TEST (frag_id == 0, "Frag ID should be 0");

  /* Test FRAG_YES_NOTLAST header with seq_id and frag_id */
  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, 5, 2, 0);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_YES_NOTLAST, "Type should be YES_NOTLAST");
  OVPN_TEST (seq_id == 5, "Seq ID should be 5");
  OVPN_TEST (frag_id == 2, "Frag ID should be 2");

  /* Test FRAG_YES_LAST header with frag_size */
  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_LAST, 10, 3, 1300);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_YES_LAST, "Type should be YES_LAST");
  OVPN_TEST (seq_id == 10, "Seq ID should be 10");
  OVPN_TEST (frag_id == 3, "Frag ID should be 3");
  OVPN_TEST (frag_size == 1300, "Frag size should be 1300");

  /* Test max values - note: frag_size is stored with 2-bit rounding (div by 4) */
  hdr = ovpn_frag_make_header (OVPN_FRAG_TEST, 255, 31, 16380);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_TEST, "Type should be TEST");
  OVPN_TEST (seq_id == 255, "Seq ID should be 255 (max)");
  OVPN_TEST (frag_id == 31, "Frag ID should be 31 (max)");
  OVPN_TEST (frag_size == 16380, "Frag size should be 16380 (max aligned)");

  vlib_cli_output (vm, "Fragment header test PASSED\n");
  return 0;
}

/*
 * Test fragment state init/free
 */
static int
ovpn_test_frag_state_init (vlib_main_t *vm)
{
  ovpn_frag_state_t state;

  vlib_cli_output (vm, "=== Test Fragment State Init/Free ===\n");

  /* Initialize state */
  ovpn_frag_state_init (&state);
  OVPN_TEST (state.tx_seq_id == 0, "Initial tx_seq_id should be 0");
  /* Note: reassembly is now a fixed array, not a pool */
  OVPN_TEST (state.reassembly[0].received_mask == 0,
	     "Initial reassembly[0] should have no fragments");

  /* Free state */
  ovpn_frag_state_free (&state);
  OVPN_TEST (state.reassembly[0].received_mask == 0,
	     "Reassembly[0] should be cleared after free");

  vlib_cli_output (vm, "Fragment state init/free test PASSED\n");
  return 0;
}

/*
 * Test fragmentation of small packet (no fragmentation needed)
 */
static int
ovpn_test_frag_no_fragmentation (vlib_main_t *vm)
{
  ovpn_frag_state_t state;
  u8 test_data[100];
  u8 **fragments = NULL;
  u16 *frag_lengths = NULL;
  u32 n_fragments = 0;
  int rv;

  vlib_cli_output (vm, "=== Test No Fragmentation Needed ===\n");

  ovpn_frag_state_init (&state);

  /* Fill test data */
  for (int i = 0; i < sizeof (test_data); i++)
    test_data[i] = i & 0xff;

  /* Fragment with large max size - should result in single FRAG_WHOLE */
  rv = ovpn_frag_fragment_packet (test_data, sizeof (test_data), 1400, &state,
				  &fragments, &frag_lengths, &n_fragments);

  OVPN_TEST (rv == 0, "Fragmentation should succeed");
  OVPN_TEST (n_fragments == 1, "Should have 1 fragment");
  OVPN_TEST (frag_lengths[0] == sizeof (test_data) + OVPN_FRAG_HDR_SIZE,
	     "Fragment should include header");

  /* Verify fragment header is FRAG_WHOLE */
  u8 frag_type, seq_id, frag_id;
  u16 frag_size;
  u32 hdr;
  clib_memcpy (&hdr, fragments[0], OVPN_FRAG_HDR_SIZE);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_WHOLE, "Fragment type should be WHOLE");

  /* Verify data */
  OVPN_TEST (clib_memcmp (fragments[0] + OVPN_FRAG_HDR_SIZE, test_data,
			  sizeof (test_data)) == 0,
	     "Fragment data should match original");

  /* Cleanup */
  for (u32 i = 0; i < n_fragments; i++)
    clib_mem_free (fragments[i]);
  vec_free (fragments);
  vec_free (frag_lengths);
  ovpn_frag_state_free (&state);

  vlib_cli_output (vm, "No fragmentation needed test PASSED\n");
  return 0;
}

/*
 * Test fragmentation of large packet
 */
static int
ovpn_test_frag_fragmentation (vlib_main_t *vm)
{
  ovpn_frag_state_t state;
  u8 test_data[500];
  u8 **fragments = NULL;
  u16 *frag_lengths = NULL;
  u32 n_fragments = 0;
  int rv;

  vlib_cli_output (vm, "=== Test Fragmentation ===\n");

  ovpn_frag_state_init (&state);

  /* Fill test data */
  for (int i = 0; i < sizeof (test_data); i++)
    test_data[i] = i & 0xff;

  /* Fragment with small max size - should result in multiple fragments */
  /* max_frag_size = 200, payload per frag = 200 - 4 = 196 */
  /* 500 bytes / 196 = 3 fragments (196 + 196 + 108) */
  rv = ovpn_frag_fragment_packet (test_data, sizeof (test_data), 200, &state,
				  &fragments, &frag_lengths, &n_fragments);

  OVPN_TEST (rv == 0, "Fragmentation should succeed");
  OVPN_TEST (n_fragments == 3, "Should have 3 fragments, got %u", n_fragments);

  /* Verify fragment headers */
  u8 frag_type, seq_id, frag_id;
  u16 frag_size;
  u32 hdr;

  /* First fragment - NOTLAST */
  clib_memcpy (&hdr, fragments[0], OVPN_FRAG_HDR_SIZE);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_YES_NOTLAST,
	     "First fragment should be NOTLAST");
  OVPN_TEST (frag_id == 0, "First fragment ID should be 0");

  /* Second fragment - NOTLAST */
  clib_memcpy (&hdr, fragments[1], OVPN_FRAG_HDR_SIZE);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_YES_NOTLAST,
	     "Second fragment should be NOTLAST");
  OVPN_TEST (frag_id == 1, "Second fragment ID should be 1");

  /* Last fragment - LAST */
  clib_memcpy (&hdr, fragments[2], OVPN_FRAG_HDR_SIZE);
  ovpn_frag_parse_header (hdr, &frag_type, &seq_id, &frag_id, &frag_size);
  OVPN_TEST (frag_type == OVPN_FRAG_YES_LAST, "Last fragment should be LAST");
  OVPN_TEST (frag_id == 2, "Last fragment ID should be 2");
  OVPN_TEST (frag_size == 200, "Last fragment should have max size");

  /* Cleanup */
  for (u32 i = 0; i < n_fragments; i++)
    clib_mem_free (fragments[i]);
  vec_free (fragments);
  vec_free (frag_lengths);
  ovpn_frag_state_free (&state);

  vlib_cli_output (vm, "Fragmentation test PASSED\n");
  return 0;
}

/*
 * Test reassembly of FRAG_WHOLE packet
 */
static int
ovpn_test_frag_reassemble_whole (vlib_main_t *vm)
{
  ovpn_frag_state_t state;
  u8 frag_packet[104]; /* 4 byte header + 100 byte payload */
  u8 *reassembled = NULL;
  u32 reassembled_len = 0;
  int rv;

  vlib_cli_output (vm, "=== Test Reassemble FRAG_WHOLE ===\n");

  ovpn_frag_state_init (&state);

  /* Create FRAG_WHOLE packet */
  u32 hdr = ovpn_frag_make_header (OVPN_FRAG_WHOLE, 0, 0, 0);
  clib_memcpy (frag_packet, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 100; i++)
    frag_packet[OVPN_FRAG_HDR_SIZE + i] = i & 0xff;

  /* Process the fragment */
  rv = ovpn_frag_process_fragment (frag_packet, sizeof (frag_packet), &state,
				   0.0, &reassembled, &reassembled_len);

  OVPN_TEST (rv == 1, "Should return 1 (complete)");
  OVPN_TEST (reassembled != NULL, "Reassembled should not be NULL");
  OVPN_TEST (reassembled_len == 100, "Reassembled length should be 100");

  /* Verify data */
  for (int i = 0; i < 100; i++)
    {
      if (reassembled[i] != (i & 0xff))
	{
	  OVPN_TEST (0, "Data mismatch at offset %d", i);
	  break;
	}
    }
  OVPN_TEST (1, "Data verification passed");

  /* Cleanup */
  if (reassembled)
    clib_mem_free (reassembled);
  ovpn_frag_state_free (&state);

  vlib_cli_output (vm, "Reassemble FRAG_WHOLE test PASSED\n");
  return 0;
}

/*
 * Test reassembly of fragmented packets
 */
static int
ovpn_test_frag_reassemble_fragments (vlib_main_t *vm)
{
  ovpn_frag_state_t state;
  u8 frag1[54], frag2[54], frag3[24]; /* 3 fragments */
  u8 *reassembled = NULL;
  u32 reassembled_len = 0;
  int rv;
  u8 seq_id = 42;

  vlib_cli_output (vm, "=== Test Reassemble Fragments ===\n");

  ovpn_frag_state_init (&state);

  /* Create fragment 1 (NOTLAST, 50 bytes payload) */
  u32 hdr = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, seq_id, 0, 0);
  clib_memcpy (frag1, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 50; i++)
    frag1[OVPN_FRAG_HDR_SIZE + i] = i;

  /* Create fragment 2 (NOTLAST, 50 bytes payload) */
  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, seq_id, 1, 0);
  clib_memcpy (frag2, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 50; i++)
    frag2[OVPN_FRAG_HDR_SIZE + i] = 50 + i;

  /* Create fragment 3 (LAST, 20 bytes payload) */
  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_LAST, seq_id, 2, 100);
  clib_memcpy (frag3, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 20; i++)
    frag3[OVPN_FRAG_HDR_SIZE + i] = 100 + i;

  /* Process fragment 1 */
  rv = ovpn_frag_process_fragment (frag1, sizeof (frag1), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "Fragment 1 should return 0 (incomplete)");
  OVPN_TEST (reassembled == NULL, "No reassembly yet");

  /* Process fragment 2 */
  rv = ovpn_frag_process_fragment (frag2, sizeof (frag2), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "Fragment 2 should return 0 (incomplete)");
  OVPN_TEST (reassembled == NULL, "No reassembly yet");

  /* Process fragment 3 (last) */
  rv = ovpn_frag_process_fragment (frag3, sizeof (frag3), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 1, "Fragment 3 should return 1 (complete)");
  OVPN_TEST (reassembled != NULL, "Reassembled should not be NULL");
  OVPN_TEST (reassembled_len == 120,
	     "Reassembled length should be 120, got %u", reassembled_len);

  /* Verify reassembled data */
  int data_ok = 1;
  for (int i = 0; i < 120; i++)
    {
      if (reassembled[i] != (i & 0xff))
	{
	  data_ok = 0;
	  break;
	}
    }
  OVPN_TEST (data_ok, "Reassembled data should match original");

  /* Cleanup */
  if (reassembled)
    clib_mem_free (reassembled);
  ovpn_frag_state_free (&state);

  vlib_cli_output (vm, "Reassemble fragments test PASSED\n");
  return 0;
}

/*
 * Test out-of-order fragment reassembly
 */
static int
ovpn_test_frag_out_of_order (vlib_main_t *vm)
{
  ovpn_frag_state_t state;
  u8 frag0[24], frag1[24], frag2[24];
  u8 *reassembled = NULL;
  u32 reassembled_len = 0;
  int rv;
  u8 seq_id = 7;

  vlib_cli_output (vm, "=== Test Out-of-Order Reassembly ===\n");

  ovpn_frag_state_init (&state);

  /* Create 3 fragments with 20 bytes payload each */
  u32 hdr;

  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, seq_id, 0, 0);
  clib_memcpy (frag0, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 20; i++)
    frag0[OVPN_FRAG_HDR_SIZE + i] = 'A';

  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, seq_id, 1, 0);
  clib_memcpy (frag1, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 20; i++)
    frag1[OVPN_FRAG_HDR_SIZE + i] = 'B';

  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_LAST, seq_id, 2, 100);
  clib_memcpy (frag2, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 20; i++)
    frag2[OVPN_FRAG_HDR_SIZE + i] = 'C';

  /* Process out of order: 2, 0, 1 */
  rv = ovpn_frag_process_fragment (frag2, sizeof (frag2), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "Last fragment alone should be incomplete");

  rv = ovpn_frag_process_fragment (frag0, sizeof (frag0), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "Still incomplete with 2 of 3 fragments");

  rv = ovpn_frag_process_fragment (frag1, sizeof (frag1), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 1, "Should be complete with all 3 fragments");
  OVPN_TEST (reassembled != NULL, "Reassembled should not be NULL");
  OVPN_TEST (reassembled_len == 60, "Should have 60 bytes total");

  /* Verify data order: AAAAA... BBBBB... CCCCC... */
  OVPN_TEST (reassembled[0] == 'A', "First 20 bytes should be 'A'");
  OVPN_TEST (reassembled[20] == 'B', "Next 20 bytes should be 'B'");
  OVPN_TEST (reassembled[40] == 'C', "Last 20 bytes should be 'C'");

  /* Cleanup */
  if (reassembled)
    clib_mem_free (reassembled);
  ovpn_frag_state_free (&state);

  vlib_cli_output (vm, "Out-of-order reassembly test PASSED\n");
  return 0;
}

/*
 * Test duplicate fragment handling
 */
static int
ovpn_test_frag_duplicate (vlib_main_t *vm)
{
  ovpn_frag_state_t state;
  u8 frag0[24], frag1[24];
  u8 *reassembled = NULL;
  u32 reassembled_len = 0;
  int rv;
  u8 seq_id = 99;

  vlib_cli_output (vm, "=== Test Duplicate Fragment ===\n");

  ovpn_frag_state_init (&state);

  /* Create 2 fragments */
  u32 hdr;

  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, seq_id, 0, 0);
  clib_memcpy (frag0, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 20; i++)
    frag0[OVPN_FRAG_HDR_SIZE + i] = 'X';

  hdr = ovpn_frag_make_header (OVPN_FRAG_YES_LAST, seq_id, 1, 100);
  clib_memcpy (frag1, &hdr, OVPN_FRAG_HDR_SIZE);
  for (int i = 0; i < 20; i++)
    frag1[OVPN_FRAG_HDR_SIZE + i] = 'Y';

  /* Process fragment 0 */
  rv = ovpn_frag_process_fragment (frag0, sizeof (frag0), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "First fragment should be incomplete");

  /* Process duplicate fragment 0 - should be ignored */
  rv = ovpn_frag_process_fragment (frag0, sizeof (frag0), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "Duplicate should be ignored (return 0)");

  /* Process fragment 1 to complete */
  rv = ovpn_frag_process_fragment (frag1, sizeof (frag1), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 1, "Should complete after last fragment");
  OVPN_TEST (reassembled_len == 40, "Should have 40 bytes (not 60)");

  /* Cleanup */
  if (reassembled)
    clib_mem_free (reassembled);
  ovpn_frag_state_free (&state);

  vlib_cli_output (vm, "Duplicate fragment test PASSED\n");
  return 0;
}

/*
 * Test 9: Fragment timeout
 */
static int
ovpn_test_frag_timeout (vlib_main_t *vm)
{
  ovpn_frag_state_t state;
  u8 *reassembled = NULL;
  u32 reassembled_len = 0;
  int rv;

  vlib_cli_output (vm, "Running: Fragment timeout test\n");

  ovpn_frag_state_init (&state);

  /* Create first fragment at time 0.0 */
  u8 frag0[24];
  u32 hdr0 = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, 1, 0, 0);
  clib_memcpy (frag0, &hdr0, 4);
  memset (frag0 + 4, 0xAA, 20);

  rv = ovpn_frag_process_fragment (frag0, sizeof (frag0), &state, 0.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "First fragment should be pending");
  OVPN_TEST (state.reassembly[1].received_mask != 0,
	     "Should have reassembly for seq_id=1");

  /* Process another fragment at time 5.0 (before timeout) - same seq_id */
  rv = ovpn_frag_process_fragment (frag0, sizeof (frag0), &state, 5.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (state.reassembly[1].received_mask != 0,
	     "Should still have reassembly for seq_id=1 before timeout");

  /* Process at time 12.0 (after 10s timeout + 1s check interval) */
  u8 frag_new[24];
  u32 hdr_new = ovpn_frag_make_header (OVPN_FRAG_YES_NOTLAST, 2, 0, 0);
  clib_memcpy (frag_new, &hdr_new, 4);
  memset (frag_new + 4, 0xBB, 20);

  rv = ovpn_frag_process_fragment (frag_new, sizeof (frag_new), &state, 12.0,
				   &reassembled, &reassembled_len);
  OVPN_TEST (rv == 0, "New fragment should be pending");
  /* Old seq_id=1 should be expired, new seq_id=2 should exist */
  OVPN_TEST (state.reassembly[1].received_mask == 0,
	     "Old reassembly (seq_id=1) should be expired");
  OVPN_TEST (state.reassembly[2].received_mask != 0,
	     "New reassembly (seq_id=2) should exist");

  ovpn_frag_state_free (&state);

  vlib_cli_output (vm, "Fragment timeout test PASSED\n");
  return 0;
}

/*
 * Main test command handler
 */
static clib_error_t *
ovpn_test_fragment_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  int failed = 0;

  vlib_cli_output (vm, "\n========================================\n");
  vlib_cli_output (vm, "OpenVPN Fragmentation Unit Tests\n");
  vlib_cli_output (vm, "========================================\n\n");

  if (ovpn_test_frag_header (vm))
    failed++;
  if (ovpn_test_frag_state_init (vm))
    failed++;
  if (ovpn_test_frag_no_fragmentation (vm))
    failed++;
  if (ovpn_test_frag_fragmentation (vm))
    failed++;
  if (ovpn_test_frag_reassemble_whole (vm))
    failed++;
  if (ovpn_test_frag_reassemble_fragments (vm))
    failed++;
  if (ovpn_test_frag_out_of_order (vm))
    failed++;
  if (ovpn_test_frag_duplicate (vm))
    failed++;
  if (ovpn_test_frag_timeout (vm))
    failed++;

  vlib_cli_output (vm, "\n========================================\n");
  if (failed)
    vlib_cli_output (vm, "%d TEST(S) FAILED\n", failed);
  else
    vlib_cli_output (vm, "ALL TESTS PASSED\n");
  vlib_cli_output (vm, "========================================\n");

  return 0;
}

VLIB_CLI_COMMAND (ovpn_test_fragment_command, static) = {
  .path = "test ovpn fragment",
  .short_help = "test ovpn fragment",
  .function = ovpn_test_fragment_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
