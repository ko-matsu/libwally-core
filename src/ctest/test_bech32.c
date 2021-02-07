#include "config.h"

#include <wally_core.h>
#include <wally_address.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static const char *invalid = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg";

static bool check_segwit_to_bytes(void)
{
    unsigned char *mem = calloc(90, sizeof(unsigned char));
    size_t written;
    int ret;

    if (!mem)
        return false;

    ret = wally_addr_segwit_to_bytes(invalid, "tb", 0, mem, 90, &written);

    if (ret != WALLY_EINVAL)
        return false;

    free(mem);

    return true;
}

static bool check_segwit_addr(void)
{
    unsigned char *mem = calloc(90, sizeof(unsigned char));
    size_t written;
    int ret;
    bool is_success = true;
    char *output = NULL;
    
    if (!mem)
        return false;

    ret = wally_hex_to_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 43) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "tb", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 43) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", 75) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("6002751e", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1sw50qgdz25j", 15) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("5210751e76e8199196d454941c45d1b3a323", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", 37) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "tb", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "tb", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    ret = wally_hex_to_bytes("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    else {
        ret = wally_addr_segwit_from_bytes(mem, written, "bc", 0, &output);
        if (ret != WALLY_OK)
            is_success = false;
        else {
            if (memcmp(output, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", 63) != 0)
                is_success = false;
            wally_free_string(output);
        }
    }

    free(mem);

    return is_success;
}

static bool check_addr_segwit(void)
{
    unsigned char *mem;
    unsigned char *mem2;
    size_t written;
    size_t written2;
    int ret;
    bool is_success = true;

    mem = calloc(90, sizeof(unsigned char));
    if (!mem)
        return false;

    mem2 = calloc(90, sizeof(unsigned char));
    if (!mem2) {
        free(mem);
        return false;
    }

    ret = wally_addr_segwit_to_bytes(
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "tb", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "BC1SW50QGDZ25J",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes("6002751e", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes("5210751e76e8199196d454941c45d1b3a323", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "tb", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "tb", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    ret = wally_addr_segwit_to_bytes(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "bc", 0, mem, 90, &written);
    if (ret != WALLY_OK)
        is_success = false;
    ret = wally_hex_to_bytes(
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", mem2, 90, &written2);
    if (ret != WALLY_OK || written != written2 || memcmp(mem, mem2, written) != 0)
        is_success = false;

    free(mem);
    free(mem2);

    return is_success;
}

int main(void)
{
    bool tests_ok = true;

    if (!check_segwit_to_bytes()) {
        printf("check_segwit_to_bytes test failed!\n");
        tests_ok = false;
    }
    if (!check_segwit_addr()) {
        printf("check_segwit_addr test failed!\n");
        tests_ok = false;
    }
    if (!check_addr_segwit()) {
        printf("check_addr_segwit test failed!\n");
        tests_ok = false;
    }

    return tests_ok ? 0 : 1;
}
