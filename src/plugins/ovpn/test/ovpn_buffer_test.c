/*
 * ovpn_buffer_test.c - OpenVPN buffer unit tests
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
#include <ovpn/ovpn_buffer.h>

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

/* ovpn_buf_pool is defined in ovpn_ssl.c and declared extern in ovpn_buffer.h */

/*
 * Test basic buffer allocation and free
 */
static int
ovpn_test_buffer_alloc_free (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;

  vlib_cli_output (vm, "=== Test Buffer Alloc/Free ===\n");

  /* Allocate a buffer */
  buf_idx = ovpn_buf_alloc (256);
  buf = ovpn_buf_get (buf_idx);

  OVPN_TEST (buf != NULL, "Buffer should be allocated");
  OVPN_TEST (buf->capacity == 256, "Capacity should be 256");
  OVPN_TEST (buf->offset == 0, "Offset should be 0");
  OVPN_TEST (buf->len == 0, "Length should be 0");
  OVPN_TEST (buf->data != NULL, "Data pointer should not be NULL");
  OVPN_TEST (ovpn_buf_valid (buf), "Buffer should be valid");

  /* Free the buffer */
  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer alloc/free test PASSED\n");
  return 0;
}

/*
 * Test buffer write operations
 */
static int
ovpn_test_buffer_write (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;
  u8 test_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
  u8 *ptr;

  vlib_cli_output (vm, "=== Test Buffer Write ===\n");

  /* Allocate a buffer */
  buf_idx = ovpn_buf_alloc (256);
  buf = ovpn_buf_get (buf_idx);

  /* Test ovpn_buf_write */
  OVPN_TEST (ovpn_buf_write (buf, test_data, sizeof (test_data)),
	     "Write should succeed");
  OVPN_TEST (OVPN_BLEN (buf) == 5, "Length should be 5");
  OVPN_TEST (clib_memcmp (OVPN_BPTR (buf), test_data, 5) == 0,
	     "Data should match");

  /* Test ovpn_buf_write_u8 */
  OVPN_TEST (ovpn_buf_write_u8 (buf, 0xAA), "Write u8 should succeed");
  OVPN_TEST (OVPN_BLEN (buf) == 6, "Length should be 6");
  OVPN_TEST (OVPN_BPTR (buf)[5] == 0xAA, "Last byte should be 0xAA");

  /* Test ovpn_buf_write_u16 */
  OVPN_TEST (ovpn_buf_write_u16 (buf, 0x1234), "Write u16 should succeed");
  OVPN_TEST (OVPN_BLEN (buf) == 8, "Length should be 8");
  /* Network byte order: 0x12, 0x34 */
  OVPN_TEST (OVPN_BPTR (buf)[6] == 0x12, "High byte should be 0x12");
  OVPN_TEST (OVPN_BPTR (buf)[7] == 0x34, "Low byte should be 0x34");

  /* Test ovpn_buf_write_u32 */
  OVPN_TEST (ovpn_buf_write_u32 (buf, 0xDEADBEEF), "Write u32 should succeed");
  OVPN_TEST (OVPN_BLEN (buf) == 12, "Length should be 12");
  /* Network byte order: 0xDE, 0xAD, 0xBE, 0xEF */
  OVPN_TEST (OVPN_BPTR (buf)[8] == 0xDE, "First byte should be 0xDE");
  OVPN_TEST (OVPN_BPTR (buf)[9] == 0xAD, "Second byte should be 0xAD");
  OVPN_TEST (OVPN_BPTR (buf)[10] == 0xBE, "Third byte should be 0xBE");
  OVPN_TEST (OVPN_BPTR (buf)[11] == 0xEF, "Fourth byte should be 0xEF");

  /* Test ovpn_buf_write_alloc */
  ptr = ovpn_buf_write_alloc (buf, 4);
  OVPN_TEST (ptr != NULL, "Write alloc should succeed");
  OVPN_TEST (OVPN_BLEN (buf) == 16, "Length should be 16");
  ptr[0] = 0x11;
  ptr[1] = 0x22;
  ptr[2] = 0x33;
  ptr[3] = 0x44;
  OVPN_TEST (OVPN_BPTR (buf)[12] == 0x11, "Allocated byte 0 correct");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer write test PASSED\n");
  return 0;
}

/*
 * Test buffer read operations
 */
static int
ovpn_test_buffer_read (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;
  u8 test_data[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78 };
  u8 read_data[8];
  int val;
  u8 good;

  vlib_cli_output (vm, "=== Test Buffer Read ===\n");

  /* Allocate and write test data */
  buf_idx = ovpn_buf_alloc (256);
  buf = ovpn_buf_get (buf_idx);
  ovpn_buf_write (buf, test_data, sizeof (test_data));

  /* Reset to read mode by setting offset */
  buf->offset = 0;
  buf->len = sizeof (test_data);

  /* Test ovpn_buf_read_u8 */
  val = ovpn_buf_read_u8 (buf);
  OVPN_TEST (val == 0xDE, "Read u8 should be 0xDE, got 0x%02x", val);
  OVPN_TEST (OVPN_BLEN (buf) == 7, "Length should be 7 after read");

  /* Test ovpn_buf_read_u16 */
  val = ovpn_buf_read_u16 (buf);
  OVPN_TEST (val == 0xADBE, "Read u16 should be 0xADBE, got 0x%04x", val);
  OVPN_TEST (OVPN_BLEN (buf) == 5, "Length should be 5 after read");

  /* Test ovpn_buf_read_u32 */
  u32 val32 = ovpn_buf_read_u32 (buf, &good);
  OVPN_TEST (good == 1, "Read u32 should succeed");
  OVPN_TEST (val32 == 0xEF123456, "Read u32 should be 0xEF123456, got 0x%08x",
	     val32);
  OVPN_TEST (OVPN_BLEN (buf) == 1, "Length should be 1 after read");

  /* Test ovpn_buf_read with destination buffer */
  buf->offset = 0;
  buf->len = sizeof (test_data);
  OVPN_TEST (ovpn_buf_read (buf, read_data, 4), "Read 4 bytes should succeed");
  OVPN_TEST (clib_memcmp (read_data, test_data, 4) == 0, "Read data matches");

  /* Test read past end */
  buf->offset = 0;
  buf->len = 2;
  val32 = ovpn_buf_read_u32 (buf, &good);
  OVPN_TEST (good == 0, "Read u32 past end should fail");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer read test PASSED\n");
  return 0;
}

/*
 * Test buffer prepend operations
 */
static int
ovpn_test_buffer_prepend (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;
  u8 *ptr;

  vlib_cli_output (vm, "=== Test Buffer Prepend ===\n");

  /* Allocate a buffer with offset space */
  buf_idx = ovpn_buf_alloc (256);
  buf = ovpn_buf_get (buf_idx);

  /* Initialize with offset to allow prepend */
  buf->offset = 64;
  buf->len = 0;

  /* Write some data first */
  ovpn_buf_write_u32 (buf, 0x12345678);
  OVPN_TEST (OVPN_BLEN (buf) == 4, "Length should be 4");
  OVPN_TEST (buf->offset == 64, "Offset should still be 64");

  /* Prepend data */
  ptr = ovpn_buf_prepend (buf, 4);
  OVPN_TEST (ptr != NULL, "Prepend should succeed");
  OVPN_TEST (buf->offset == 60, "Offset should be 60 after prepend");
  OVPN_TEST (OVPN_BLEN (buf) == 8, "Length should be 8 after prepend");

  /* Fill prepended space */
  ptr[0] = 0xAA;
  ptr[1] = 0xBB;
  ptr[2] = 0xCC;
  ptr[3] = 0xDD;

  /* Verify data order */
  OVPN_TEST (OVPN_BPTR (buf)[0] == 0xAA, "First byte should be 0xAA");
  OVPN_TEST (OVPN_BPTR (buf)[4] == 0x12, "Fifth byte should be 0x12");

  /* Test ovpn_buf_write_prepend */
  u8 prepend_data[] = { 0x11, 0x22 };
  OVPN_TEST (ovpn_buf_write_prepend (buf, prepend_data, 2),
	     "Write prepend should succeed");
  OVPN_TEST (buf->offset == 58, "Offset should be 58");
  OVPN_TEST (OVPN_BLEN (buf) == 10, "Length should be 10");
  OVPN_TEST (OVPN_BPTR (buf)[0] == 0x11, "First byte should be 0x11");

  /* Test prepend failure (not enough space) */
  ptr = ovpn_buf_prepend (buf, 100);
  OVPN_TEST (ptr == NULL, "Prepend beyond offset should fail");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer prepend test PASSED\n");
  return 0;
}

/*
 * Test buffer advance operations
 */
static int
ovpn_test_buffer_advance (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;
  u8 test_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  vlib_cli_output (vm, "=== Test Buffer Advance ===\n");

  buf_idx = ovpn_buf_alloc (256);
  buf = ovpn_buf_get (buf_idx);
  ovpn_buf_write (buf, test_data, sizeof (test_data));

  /* Test advance */
  OVPN_TEST (ovpn_buf_advance (buf, 3), "Advance 3 should succeed");
  OVPN_TEST (buf->offset == 3, "Offset should be 3");
  OVPN_TEST (OVPN_BLEN (buf) == 5, "Length should be 5");
  OVPN_TEST (OVPN_BPTR (buf)[0] == 0x04, "First byte should be 0x04");

  /* Test advance again */
  OVPN_TEST (ovpn_buf_advance (buf, 2), "Advance 2 should succeed");
  OVPN_TEST (buf->offset == 5, "Offset should be 5");
  OVPN_TEST (OVPN_BLEN (buf) == 3, "Length should be 3");
  OVPN_TEST (OVPN_BPTR (buf)[0] == 0x06, "First byte should be 0x06");

  /* Test advance failure (too much) */
  OVPN_TEST (ovpn_buf_advance (buf, 10) == 0, "Advance beyond len should fail");
  OVPN_TEST (OVPN_BLEN (buf) == 3, "Length should still be 3");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer advance test PASSED\n");
  return 0;
}

/*
 * Test buffer capacity functions
 */
static int
ovpn_test_buffer_capacity (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;

  vlib_cli_output (vm, "=== Test Buffer Capacity ===\n");

  buf_idx = ovpn_buf_alloc (100);
  buf = ovpn_buf_get (buf_idx);

  /* Initial state */
  OVPN_TEST (ovpn_buf_forward_capacity (buf, 0) == 100,
	     "Forward capacity should be 100");
  OVPN_TEST (ovpn_buf_reverse_capacity (buf) == 0,
	     "Reverse capacity should be 0");

  /* Set offset */
  buf->offset = 20;
  buf->len = 30;

  OVPN_TEST (ovpn_buf_forward_capacity (buf, 0) == 50,
	     "Forward capacity should be 50");
  OVPN_TEST (ovpn_buf_reverse_capacity (buf) == 20,
	     "Reverse capacity should be 20");
  OVPN_TEST (ovpn_buf_forward_capacity_total (buf) == 80,
	     "Forward capacity total should be 80");

  /* Test ovpn_buf_safe */
  OVPN_TEST (ovpn_buf_safe (buf, 40), "Should be safe to add 40 bytes");
  OVPN_TEST (ovpn_buf_safe (buf, 50), "Should be safe to add 50 bytes");
  OVPN_TEST (!ovpn_buf_safe (buf, 60), "Should not be safe to add 60 bytes");

  /* Test ovpn_buf_safe_bidir */
  OVPN_TEST (ovpn_buf_safe_bidir (buf, 10), "Should be safe to extend by 10");
  OVPN_TEST (ovpn_buf_safe_bidir (buf, -10), "Should be safe to shrink by 10");
  OVPN_TEST (!ovpn_buf_safe_bidir (buf, -40),
	     "Should not be safe to shrink by 40");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer capacity test PASSED\n");
  return 0;
}

/*
 * Test buffer copy operations
 */
static int
ovpn_test_buffer_copy (vlib_main_t *vm)
{
  u32 buf1_idx, buf2_idx;
  ovpn_reli_buffer_t *buf1, *buf2;
  u8 test_data[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };

  vlib_cli_output (vm, "=== Test Buffer Copy ===\n");

  buf1_idx = ovpn_buf_alloc (256);
  buf2_idx = ovpn_buf_alloc (256);

  /* Re-fetch pointers after all allocations (pool_get may reallocate) */
  buf1 = ovpn_buf_get (buf1_idx);
  buf2 = ovpn_buf_get (buf2_idx);

  ovpn_buf_write (buf1, test_data, sizeof (test_data));

  /* Test ovpn_buf_copy */
  OVPN_TEST (ovpn_buf_copy (buf2, buf1), "Copy should succeed");
  OVPN_TEST (OVPN_BLEN (buf2) == 5, "Dest length should be 5");
  OVPN_TEST (clib_memcmp (OVPN_BPTR (buf2), test_data, 5) == 0,
	     "Copied data should match");

  /* Test ovpn_buf_equal */
  OVPN_TEST (ovpn_buf_equal (buf1, buf2), "Buffers should be equal");

  /* Modify buf2 and test inequality */
  OVPN_BPTR (buf2)[0] = 0xFF;
  OVPN_TEST (!ovpn_buf_equal (buf1, buf2), "Modified buffers should not be equal");

  /* Test ovpn_buf_copy_range - need to reset buf2 first */
  ovpn_reli_buf_reset_len (buf2);
  vec_resize (buf2->data, 256);
  buf2->capacity = 256;
  buf2->offset = 10;
  OVPN_TEST (ovpn_buf_copy_range (buf2, 0, buf1, 1, 3),
	     "Copy range should succeed");
  OVPN_TEST (OVPN_BLEN (buf2) == 3, "Dest length should be 3");
  OVPN_TEST (OVPN_BPTR (buf2)[0] == 0xBB, "First byte should be 0xBB");
  OVPN_TEST (OVPN_BPTR (buf2)[2] == 0xDD, "Third byte should be 0xDD");

  ovpn_buf_free (buf1);
  ovpn_buf_free (buf2);

  vlib_cli_output (vm, "Buffer copy test PASSED\n");
  return 0;
}

/*
 * Test buffer clone
 */
static int
ovpn_test_buffer_clone (vlib_main_t *vm)
{
  u32 buf1_idx, buf2_idx;
  ovpn_reli_buffer_t *buf1, *buf2;
  u8 test_data[] = { 0x11, 0x22, 0x33, 0x44 };

  vlib_cli_output (vm, "=== Test Buffer Clone ===\n");

  buf1_idx = ovpn_buf_alloc (64);
  buf1 = ovpn_buf_get (buf1_idx);
  ovpn_buf_write (buf1, test_data, sizeof (test_data));

  /* Clone the buffer - this may reallocate the pool */
  buf2_idx = ovpn_buf_clone (buf1);

  /* Re-fetch pointers after clone (pool_get may reallocate) */
  buf1 = ovpn_buf_get (buf1_idx);
  buf2 = ovpn_buf_get (buf2_idx);

  OVPN_TEST (buf2 != NULL, "Cloned buffer should exist");
  OVPN_TEST (buf2 != buf1, "Cloned buffer should be different object");
  OVPN_TEST (buf2->capacity == buf1->capacity, "Capacities should match");

  /* Verify data is independent */
  OVPN_BPTR (buf1)[0] = 0xFF;
  OVPN_TEST (buf2->data[0] == 0x11,
	     "Cloned buffer data should be independent");

  ovpn_buf_free (buf1);
  ovpn_buf_free (buf2);

  vlib_cli_output (vm, "Buffer clone test PASSED\n");
  return 0;
}

/*
 * Test buffer reset and clear
 */
static int
ovpn_test_buffer_reset_clear (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;
  u8 test_data[] = { 0x01, 0x02, 0x03 };

  vlib_cli_output (vm, "=== Test Buffer Reset/Clear ===\n");

  buf_idx = ovpn_buf_alloc (128);
  buf = ovpn_buf_get (buf_idx);
  buf->offset = 32;
  ovpn_buf_write (buf, test_data, sizeof (test_data));

  OVPN_TEST (OVPN_BLEN (buf) == 3, "Length should be 3");
  OVPN_TEST (buf->offset == 32, "Offset should be 32");

  /* Test ovpn_reli_buf_reset_len */
  ovpn_reli_buf_reset_len (buf);
  OVPN_TEST (OVPN_BLEN (buf) == 0, "Length should be 0 after reset_len");
  OVPN_TEST (buf->offset == 0, "Offset should be 0 after reset_len");

  /* Write again and test clear */
  buf->offset = 16;
  ovpn_buf_write (buf, test_data, sizeof (test_data));
  ovpn_buf_clear (buf);
  OVPN_TEST (OVPN_BLEN (buf) == 0, "Length should be 0 after clear");
  OVPN_TEST (buf->offset == 0, "Offset should be 0 after clear");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer reset/clear test PASSED\n");
  return 0;
}

/*
 * Test buffer sub-buffer creation
 */
static int
ovpn_test_buffer_sub (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;
  ovpn_reli_buffer_t sub;

  vlib_cli_output (vm, "=== Test Buffer Sub ===\n");

  buf_idx = ovpn_buf_alloc (256);
  buf = ovpn_buf_get (buf_idx);
  buf->offset = 32;

  /* Create sub-buffer (append mode) */
  sub = ovpn_buf_sub (buf, 16, 0);
  OVPN_TEST (sub.data != NULL, "Sub-buffer should be created");
  OVPN_TEST (sub.capacity == 16, "Sub-buffer capacity should be 16");
  OVPN_TEST (OVPN_BLEN (buf) == 16, "Parent length should be 16");

  /* Create sub-buffer (prepend mode) */
  buf->offset = 32;
  buf->len = 0;
  sub = ovpn_buf_sub (buf, 8, 1);
  OVPN_TEST (sub.data != NULL, "Prepend sub-buffer should be created");
  OVPN_TEST (sub.capacity == 8, "Prepend sub-buffer capacity should be 8");
  OVPN_TEST (buf->offset == 24, "Parent offset should be 24 after prepend sub");
  OVPN_TEST (OVPN_BLEN (buf) == 8, "Parent length should be 8");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer sub test PASSED\n");
  return 0;
}

/*
 * Test buffer size validation
 */
static int
ovpn_test_buffer_size_validation (vlib_main_t *vm)
{
  vlib_cli_output (vm, "=== Test Buffer Size Validation ===\n");

  /* Test ovpn_buf_size_valid */
  OVPN_TEST (ovpn_buf_size_valid (100), "Size 100 should be valid");
  OVPN_TEST (ovpn_buf_size_valid (BUF_SIZE_MAX - 1),
	     "Size BUF_SIZE_MAX-1 should be valid");
  OVPN_TEST (!ovpn_buf_size_valid (BUF_SIZE_MAX),
	     "Size BUF_SIZE_MAX should be invalid");
  OVPN_TEST (!ovpn_buf_size_valid (BUF_SIZE_MAX + 1),
	     "Size BUF_SIZE_MAX+1 should be invalid");

  /* Test ovpn_buf_valid_signed */
  OVPN_TEST (ovpn_buf_valid_signed (100), "Signed 100 should be valid");
  OVPN_TEST (ovpn_buf_valid_signed (-100), "Signed -100 should be valid");
  OVPN_TEST (ovpn_buf_valid_signed (0), "Signed 0 should be valid");
  OVPN_TEST (!ovpn_buf_valid_signed (BUF_SIZE_MAX),
	     "Signed BUF_SIZE_MAX should be invalid");
  OVPN_TEST (!ovpn_buf_valid_signed (-BUF_SIZE_MAX - 1),
	     "Signed -BUF_SIZE_MAX-1 should be invalid");

  vlib_cli_output (vm, "Buffer size validation test PASSED\n");
  return 0;
}

/*
 * Test buffer helper macros
 */
static int
ovpn_test_buffer_macros (vlib_main_t *vm)
{
  u32 buf_idx;
  ovpn_reli_buffer_t *buf;
  u8 test_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

  vlib_cli_output (vm, "=== Test Buffer Macros ===\n");

  buf_idx = ovpn_buf_alloc (64);
  buf = ovpn_buf_get (buf_idx);
  buf->offset = 10;
  ovpn_buf_write (buf, test_data, sizeof (test_data));

  /* Test OVPN_BPTR */
  OVPN_TEST (OVPN_BPTR (buf) == buf->data + buf->offset,
	     "OVPN_BPTR should point to data + offset");

  /* Test OVPN_BLEN */
  OVPN_TEST (OVPN_BLEN (buf) == 5, "OVPN_BLEN should be 5");

  /* Test OVPN_BEND */
  OVPN_TEST (OVPN_BEND (buf) == OVPN_BPTR (buf) + 5,
	     "OVPN_BEND should point to end");

  /* Test OVPN_BLAST */
  OVPN_TEST (OVPN_BLAST (buf) == OVPN_BPTR (buf) + 4,
	     "OVPN_BLAST should point to last byte");
  OVPN_TEST (*OVPN_BLAST (buf) == 0x05, "Last byte should be 0x05");

  /* Test OVPN_BDEF */
  OVPN_TEST (OVPN_BDEF (buf), "OVPN_BDEF should be true");

  /* Test forward capacity */
  OVPN_TEST (ovpn_buf_forward_capacity (buf, 0) == 64 - 10 - 5,
	     "Forward capacity should be 49");

  ovpn_buf_free (buf);

  vlib_cli_output (vm, "Buffer macros test PASSED\n");
  return 0;
}

/*
 * Run all buffer tests
 */
static int
ovpn_buffer_test_run_all (vlib_main_t *vm)
{
  int rv = 0;

  vlib_cli_output (vm, "\n========================================\n");
  vlib_cli_output (vm, "OpenVPN Buffer Unit Tests\n");
  vlib_cli_output (vm, "========================================\n\n");

  rv |= ovpn_test_buffer_alloc_free (vm);
  rv |= ovpn_test_buffer_write (vm);
  rv |= ovpn_test_buffer_read (vm);
  rv |= ovpn_test_buffer_prepend (vm);
  rv |= ovpn_test_buffer_advance (vm);
  rv |= ovpn_test_buffer_capacity (vm);
  rv |= ovpn_test_buffer_copy (vm);
  rv |= ovpn_test_buffer_clone (vm);
  rv |= ovpn_test_buffer_reset_clear (vm);
  rv |= ovpn_test_buffer_sub (vm);
  rv |= ovpn_test_buffer_size_validation (vm);
  rv |= ovpn_test_buffer_macros (vm);

  vlib_cli_output (vm, "\n========================================\n");
  if (rv == 0)
    vlib_cli_output (vm, "ALL BUFFER TESTS PASSED\n");
  else
    vlib_cli_output (vm, "SOME BUFFER TESTS FAILED\n");
  vlib_cli_output (vm, "========================================\n");

  return rv;
}

/*
 * CLI command to run buffer tests
 */
static clib_error_t *
ovpn_buffer_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  int rv = ovpn_buffer_test_run_all (vm);

  if (rv)
    return clib_error_return (0, "Buffer tests failed");

  return 0;
}

VLIB_CLI_COMMAND (ovpn_buffer_test_command, static) = {
  .path = "test ovpn buffer",
  .short_help = "test ovpn buffer - run OpenVPN buffer unit tests",
  .function = ovpn_buffer_test_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
