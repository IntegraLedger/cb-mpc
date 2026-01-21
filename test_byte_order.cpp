/**
 * Simple test to verify byte order functions
 */
#include <cbmpc/core/utils.h>
#include <cbmpc/core/convert.h>
#include <cstdio>
#include <vector>

int main() {
    printf("=== Byte Order Test ===\n\n");

    uint8_t buf_be[4] = {0};
    uint8_t buf_le[4] = {0};

    uint32_t value = 31;  // 0x0000001f

    coinbase::be_set_4(buf_be, value);
    coinbase::le_set_4(buf_le, value);

    printf("Value: %u (0x%08x)\n\n", value, value);

    printf("be_set_4 output: %02x %02x %02x %02x\n",
           buf_be[0], buf_be[1], buf_be[2], buf_be[3]);
    printf("  Expected (big-endian): 00 00 00 1f\n\n");

    printf("le_set_4 output: %02x %02x %02x %02x\n",
           buf_le[0], buf_le[1], buf_le[2], buf_le[3]);
    printf("  Expected (little-endian): 1f 00 00 00\n\n");

    // Also test convert_t for int
    printf("Now testing std::vector<int> serialization...\n");

    std::vector<int> test_vec = {31, 33, 10};
    coinbase::buf_t serialized = coinbase::ser(test_vec);

    printf("Vector {31, 33, 10} serialized to %d bytes:\n  ", serialized.size());
    for (int i = 0; i < serialized.size(); i++) {
        printf("%02x ", serialized.data()[i]);
    }
    printf("\n");
    printf("  If big-endian ints: 03 00 00 00 1f 00 00 00 21 00 00 00 0a\n");
    printf("  (count=3 as convert_len, then 31,33,10 as BE 4-byte ints)\n");

    return 0;
}
