#include "internal.h"

#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/crypto/sha256/sha256.h"

#include <include/wally_crypto.h>
#include <include/wally_script.h>
#include <include/wally_transaction.h>

#include <limits.h>
#include <stdbool.h>

#define MINISCRIPT_TYPE_FRAGMENT  0x01
#define MINISCRIPT_TYPE_SCRIPT    0x02    /* Output Descriptor */

#define MINISCRIPT_KIND_FRAGMENT  0x01
#define MINISCRIPT_KIND_SCRIPT    0x02    /* Output Descriptor script */
#define MINISCRIPT_KIND_RAW       0x04    /* Output Descriptor */
#define MINISCRIPT_KIND_NUMBER    0x08    /* Output Descriptor */
#define MINISCRIPT_KIND_ADDRESS   0x10    /* Output Descriptor */
#define MINISCRIPT_KIND_KEY       0x20    /* Output Descriptor */

#define MINISCRIPT_KIND_BASE58    (0x0100 | MINISCRIPT_KIND_ADDRESS)
#define MINISCRIPT_KIND_BECH32    (0x0200 | MINISCRIPT_KIND_ADDRESS)

#define MINISCRIPT_KIND_PUBKEY    (0x1000 | MINISCRIPT_KIND_KEY)
#define MINISCRIPT_KIND_PRIVKEY   (0x2000 | MINISCRIPT_KIND_KEY)
#define MINISCRIPT_KIND_BIP32     (0x4000 | MINISCRIPT_KIND_KEY)

#define MINISCRIPT_KIND_ALL       0xffff

#define MINISCRIPT_LIMIT_LENGTH  100000

#define MINISCRIPT_KEY_NAME_MAX_LENGTH    128
#define MINISCRIPT_KEY_VALUE_MAX_LENGTH   256

#define MINISCRIPT_CHECKSUM_LENGTH  8

#define MINISCRIPT_TYPE_SCRIPT_SH      (0x00000100 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_WSH     (0x00000200 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_PKH     (0x00000300 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_WPKH    (0x00000400 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_COMBO   (0x00000500 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_MULTI   (0x00000600 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_SMULTI  (0x00000700 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_ADDR    (0x00000800 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_RAW     (0x00000900 | MINISCRIPT_TYPE_SCRIPT)
#define MINISCRIPT_TYPE_SCRIPT_MASK    (0xffffff00 | MINISCRIPT_TYPE_SCRIPT)

#define MINISCRIPT_TYPE_FRAGMENT_PK        (0x00000100 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_PKH       (0x00000200 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_OLDER     (0x00000300 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_AFTER     (0x00000400 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_SHA256    (0x00000500 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_HASH256   (0x00000600 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_RIPEMD160 (0x00000700 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_HASH160   (0x00000800 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_ANDOR     (0x00000900 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_AND_V     (0x00000a00 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_AND_B     (0x00000b00 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_AND_N     (0x00000c00 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_OR_B      (0x00000d00 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_OR_C      (0x00000e00 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_OR_D      (0x00000f00 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_OR_I      (0x00001000 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_THRESH    (0x00001100 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_THRESH_M  (0x00001200 | MINISCRIPT_TYPE_FRAGMENT)
#define MINISCRIPT_TYPE_FRAGMENT_MASK      (0xffffff00 | MINISCRIPT_TYPE_FRAGMENT)

#define MINISCRIPT_TYPE_WRAPPER_A      (0x00000100)
#define MINISCRIPT_TYPE_WRAPPER_S      (0x00000200)
#define MINISCRIPT_TYPE_WRAPPER_C      (0x00000400)
#define MINISCRIPT_TYPE_WRAPPER_T      (0x00000800)
#define MINISCRIPT_TYPE_WRAPPER_D      (0x00001000)
#define MINISCRIPT_TYPE_WRAPPER_V      (0x00002000)
#define MINISCRIPT_TYPE_WRAPPER_J      (0x00004000)
#define MINISCRIPT_TYPE_WRAPPER_N      (0x00008000)
#define MINISCRIPT_TYPE_WRAPPER_L      (0x00010000)
#define MINISCRIPT_TYPE_WRAPPER_U      (0x00020000)
#define MINISCRIPT_TYPE_WRAPPER_MASK   (0xffffff00)

struct miniscript_node_t {
    const miniscript_item_t *info;
    struct miniscript_node_t *next;
    struct miniscript_node_t *back;
    struct miniscript_node_t *child;
    unsigned int chain_count;
    int kind;
    uint32_t wrapper;
    int64_t number;
    char *data;
    char *derive_path;
    unsigned short data_size;
    unsigned short derive_path_len;
    unsigned char is_derive;
};

struct miniscript_item_t {
    const char *name;
    int type;
    int inner_num;
    void* verify_function;
    void* generate_function;
};

static int verify_miniscript_sh(miniscript_node_t *node, miniscript_node_t *parent)
{
    if (parent || !node->child || !node->child->info)
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int verify_miniscript_wsh(miniscript_node_t *node, miniscript_node_t *parent)
{
    if (parent && (!parent->info || (parent->info->type != MINISCRIPT_TYPE_SCRIPT_SH)))
        return WALLY_EINVAL;
    if (!node->child || !node->child->info)
        return WALLY_EINVAL;
    return WALLY_OK;
}

static int verify_miniscript_addr(miniscript_node_t *node, miniscript_node_t *parent)
{
    if (parent || !node->child || node->child->info)
        return WALLY_EINVAL;
    /* check addr string */
    return WALLY_OK;
}

static int verify_miniscript_raw(miniscript_node_t *node, miniscript_node_t *parent)
{
    if (parent || !node->child || node->child->info)
        return WALLY_EINVAL;
    /* check hex string */
    return WALLY_OK;
}


static const miniscript_item_t miniscript_info_table[] = {
    /* output descriptor */
    {
        "sh", MINISCRIPT_TYPE_SCRIPT_SH, 1, verify_miniscript_sh, NULL
    },
    {
        "wsh", MINISCRIPT_TYPE_SCRIPT_WSH, 1, verify_miniscript_wsh, NULL
    },
    {
        "pkh", MINISCRIPT_TYPE_SCRIPT_PKH, 1, NULL, NULL
    },
    {
        "wpkh", MINISCRIPT_TYPE_SCRIPT_WPKH, 1, NULL, NULL
    },
    {
        "combo", MINISCRIPT_TYPE_SCRIPT_COMBO, 1, NULL, NULL
    },
    {
        "multi", MINISCRIPT_TYPE_SCRIPT_MULTI, 1, NULL, NULL
    },
    {
        "sortedmulti", MINISCRIPT_TYPE_SCRIPT_SMULTI, -1, NULL, NULL
    },
    {
        "addr", MINISCRIPT_TYPE_SCRIPT_ADDR, -1, verify_miniscript_addr, NULL
    },
    {
        "raw", MINISCRIPT_TYPE_SCRIPT_RAW, 1, verify_miniscript_raw, NULL
    },
    /* miniscript */
    {
        "pk", MINISCRIPT_TYPE_FRAGMENT_PK, 1, NULL, NULL
    },
    {
        "pk_h", MINISCRIPT_TYPE_FRAGMENT_PKH, 1, NULL, NULL
    },
    {
        "older", MINISCRIPT_TYPE_FRAGMENT_OLDER, 1, {NULL, NULL
    },
    {
        "after", MINISCRIPT_TYPE_FRAGMENT_AFTER, 1, NULL, NULL
    },
    {
        "sha256", MINISCRIPT_TYPE_FRAGMENT_SHA256, 1, NULL, NULL
    },
    {
        "hash256", MINISCRIPT_TYPE_FRAGMENT_HASH256, 1, NULL, NULL
    },
    {
        "ripemd160", MINISCRIPT_TYPE_FRAGMENT_RIPEMD160, 1, NULL, NULL
    },
    {
        "hash160", MINISCRIPT_TYPE_FRAGMENT_HASH160, 1, NULL, NULL
    },
    {
        "andor", MINISCRIPT_TYPE_FRAGMENT_ANDOR, 3, NULL, NULL
    },
    {
        "and_v", MINISCRIPT_TYPE_FRAGMENT_AND_V, 2, NULL, NULL
    },
    {
        "and_b", MINISCRIPT_TYPE_FRAGMENT_AND_B, 2, NULL, NULL
    },
    {
        "and_n", MINISCRIPT_TYPE_FRAGMENT_AND_N, 2, NULL, NULL
    },
    {
        "or_b", MINISCRIPT_TYPE_FRAGMENT_OR_B, 2, NULL, NULL
    },
    {
        "or_c", MINISCRIPT_TYPE_FRAGMENT_OR_C, 2, NULL, NULL
    },
    {
        "or_d", MINISCRIPT_TYPE_FRAGMENT_OR_D, 2, NULL, NULL
    },
    {
        "or_i", MINISCRIPT_TYPE_FRAGMENT_OR_I, 2, NULL, NULL
    },
    {
        "thresh", MINISCRIPT_TYPE_FRAGMENT_THRESH, -1, NULL, NULL
    },
    {
        "thresh_m", MINISCRIPT_TYPE_FRAGMENT_THRESH_M, -1, NULL, NULL
    }
}

static const miniscript_item_t miniscript_wrapper_table[] = {
    { "a", MINISCRIPT_TYPE_WRAPPER_A, 0, NULL, NULL },
    { "s", MINISCRIPT_TYPE_WRAPPER_S, 0, NULL, NULL },
    { "c", MINISCRIPT_TYPE_WRAPPER_C, 0, NULL, NULL },
    { "t", MINISCRIPT_TYPE_WRAPPER_T, 0, NULL, NULL },
    { "d", MINISCRIPT_TYPE_WRAPPER_D, 0, NULL, NULL },
    { "v", MINISCRIPT_TYPE_WRAPPER_V, 0, NULL, NULL },
    { "j", MINISCRIPT_TYPE_WRAPPER_J, 0, NULL, NULL },
    { "n", MINISCRIPT_TYPE_WRAPPER_N, 0, NULL, NULL },
    { "l", MINISCRIPT_TYPE_WRAPPER_L, 0, NULL, NULL },
    { "u", MINISCRIPT_TYPE_WRAPPER_U, 0, NULL, NULL },
};

static uint32_t convert_miniscript_wrapper_flag(const char *wrapper)
{
    uint32_t result = 0;
    size_t max = sizeof(miniscript_wrapper_table) / sizeof(miniscript_item_t);
    size_t wrapper_len = strlen(wrapper);

    for (index = 0; index < max; ++index) {
        if (strchr(wrapper, miniscript_wrapper_table[index].name[0]) != NULL) {
            result |= (uint32_t)miniscript_wrapper_table[index].type;
        }
    }
    return result;
}

static const miniscript_item_t *search_miniscript_info(const char *name)
{
    const miniscript_item_t *result = NULL;
    size_t index;
    size_t max = sizeof(miniscript_info_table) / sizeof(miniscript_item_t);
    size_t name_len = strlen(name) + 1;

    for (index = 0; index < max; ++index) {
        if (memcmp(name, miniscript_info_table[index].name, name_len) == 0) {
            result = &miniscript_info_table[index];
            break;
        }
    }
    return result;
}

static uint64_t poly_mod_descriptor_checksum(uint64_t c, int val)
{
      uint8_t c0 = c >> 35;
      c = ((c & 0x7ffffffff) << 5) ^ val;
      if (c0 & 1) c ^= 0xf5dee51989;
      if (c0 & 2) c ^= 0xa9fdca3312;
      if (c0 & 4) c ^= 0x1bab10e32d;
      if (c0 & 8) c ^= 0x3706b1677a;
      if (c0 & 16) c ^= 0x644d626ffd;
      return c;
};

static int generate_descriptor_checksum(const char *descriptor, char *checksum)
{
    /* base */
    /* bitcoin/src/script/descriptor.cpp */
    /* std::string DescriptorChecksum(const Span<const char>& span) */

    /** A character set designed such that:
     *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
     *  - Case errors cause an offset that's a multiple of 32.
     *  - As many alphabetic characters are in the same group (while following the above restrictions).
     *
     * If p(x) gives the position of a character c in this character set, every group of 3 characters
     * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
     * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
     * affect a single symbol.
     *
     * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
     * the position within the groups.
     */
    static const char* input_charset =
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

    /* The character set for the checksum itself (same as bech32). */
    static const char* checksum_charset =
        "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    uint64_t c = 1;
    int cls = 0;
    int clscount = 0;
    int j;
    size_t pos;
    size_t max = strlen(input_charset);
    for (size_t idx = 0; idx < strlen(descriptor); ++idx) {
        const char& ch = descriptor[idx];
        for (pos = 0; pos < max; ++pos) {
            if (ch == input_charset[pos])
                break;
        }
        if (pos == max)
            return WALLY_EINVAL;
        /* Emit a symbol for the position inside the group, for every character. */
        c = poly_mod_descriptor_checksum(c, pos & 31);
        /* Accumulate the group numbers */
        cls = cls * 3 + (int)(pos >> 5);
        if (++clscount == 3) {
            /* Emit an extra symbol representing the group numbers, for every 3 characters. */
            c = poly_mod_descriptor_checksum(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0)
        c = poly_mod_descriptor_checksum(c, cls);
    for (j = 0; j < 8; ++j)
        c = poly_mod_descriptor_checksum(c, 0);
    c ^= 1;

    for (j = 0; j < MINISCRIPT_CHECKSUM_LENGTH; ++j)
        checksum[j] = checksum_charset[(c >> (5 * (7 - j))) & 31];

    return ret;
}

static void free_miniscript_node(miniscript_node_t *node)
{
    if (!node)
        return;
    if (node->child)
        free_miniscript_node(node->child);
    if (node->next)
        free_miniscript_node(node->next);

    if (node->data && node->data_size) {
        wally_bzero(node->data, node->data_size);
        wally_free(node->data);
    }
    if (node->derive_path && node->derive_path_len) {
        wally_bzero(node->derive_path, node->derive_path_len);
        wally_free(node->derive_path);
    }

    wally_bzero(node, sizeof(miniscript_node_t));
    wally_free(node);
}


static int analyze_miniscript_addr(
    const char *message,
    miniscript_node_t *node,
    miniscript_node_t *parent_node)
{
    int ret;
    char *target = NULL;
    char addr_family[90];
    char *buf = NULL;
    size_t buf_len = 0;
    uint32_t version;
    unsigned char bytes_base58_decode[1 + HASH160_LEN + BASE58_CHECKSUM_LEN];
    size_t written;

    node->data = wally_strdup(message);
    if (!node->data)
        return WALLY_ENOMEM;

    node->data_size = strlen(message);

    if (wally_base58_to_bytes(message, BASE58_FLAG_CHECKSUM, bytes_base58_decode, sizeof(bytes_base58_decode), &written) == WALLY_OK) {
        if (written_base58_decode != HASH160_LEN + 1)
            return WALLY_EINVAL;

        version = bytes_base58_decode[0];
        switch (version) {
        case WALLY_ADDRESS_VERSION_P2PKH_MAINNET:
        case WALLY_ADDRESS_VERSION_P2SH_MAINNET:
        case WALLY_ADDRESS_VERSION_P2PKH_TESTNET:
        case WALLY_ADDRESS_VERSION_P2SH_TESTNET:
        case WALLY_ADDRESS_VERSION_P2PKH_LIQUID:
        case WALLY_ADDRESS_VERSION_P2SH_LIQUID:
        case WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST:
        case WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST:
            break;
        default:
            return WALLY_EINVAL;
        }
        node->kind = MINISCRIPT_KIND_BASE58;
        return WALLY_OK;
    }

    /* segwit */
    buf_len = 256;
    buf = wally_malloc(buf_len);
    if (!buf)
        return WALLY_ENOMEM;

    wally_bzero(addr_family, sizeof(addr_family));
    target = strchr(message, '1');
    if (target)
        memcpy(addr_family, message, (int)(target - message));

    ret = wally_addr_segwit_to_bytes(message, addr_family, 0, buf, buf_len, &written);
    if (!ret)
        node->kind = MINISCRIPT_KIND_BECH32;

    wally_bzero(buf, buf_len);
    wally_free(buf);
    return ret;
}

static int analyze_miniscript_value(
    const char *message,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    miniscript_node_t *node,
    miniscript_node_t *parent_node)
{
    int ret;
    size_t index;
    size_t str_len;
    size_t buf_len;
    char *buf = NULL;
    char *err_ptr = NULL;
    int size = 0;
    const char *target = message;

    if (!node || !parent_node || !parent_node->info || !message || !message[0])
        return WALLY_EINVAL;

    str_len = strlen(message);

    /* check raw (parent is raw) */
    if (parent->info->type == MINISCRIPT_TYPE_SCRIPT_RAW) {
        buf = wally_strdup(message);
        if (!buf)
            return WALLY_ENOMEM;

        ret = wally_hex_to_bytes(message, buf, str_len, &buf_len);
        if (!ret) {
            strncpy(buf, message, str_len);
            node->data = buf;
            node->data_size = str_len;
            node->kind = MINISCRIPT_KIND_RAW;
        }
        return ret;
    }

    /* check address (parent is addr) */
    if (parent->info->type == MINISCRIPT_TYPE_SCRIPT_ADDR) {
        return analyze_miniscript_addr(message, node, parent_node);
    }

    /* check key_name_array */
    if (array_len) {
        for (index = 0; index < array_len; ++index) {
            if (strncmp(message, key_name_array[index], str_len + 1) == 0) {
                node->data = wally_strdup(key_value_array[index]);
                if (!node->data)
                    return WALLY_ENOMEM;

                str_len = strlen(key_value_array[index]);
                node->data_size = str_len;
                target = node->data;
                break;
            }
        }
    }

    if (!node->data) {
        node->data = wally_strdup(message);
        node->data_size = str_len;
    }

    /* check number */
    node->number = strtoll(node->data, &err_ptr, 10);
    if (err_ptr == NULL) {
        node->kind = MINISCRIPT_KIND_NUMBER;
        return WALLY_OK;
    }

    if (node->data[0] == '[') {
        buf = strchr(node->data, ']');
        if (buf) {
            /* cut parent path */
            size = (int)(buf - node->data + 1);
            memmove(node->data, buf, str_len - size);
        }
    }

    /* check key (pubkey/privkey) */

    /* check bip32 */

        #define MINISCRIPT_KIND_NUMBER    0x08    /* Output Descriptor */
        #define MINISCRIPT_KIND_KEY       0x20    /* Output Descriptor */

        #define MINISCRIPT_KIND_PUBKEY    0x1000    /* Output Descriptor */
        #define MINISCRIPT_KIND_PRIVKEY   0x2000    /* Output Descriptor */
        #define MINISCRIPT_KIND_BIP32     0x4000    /* Output Descriptor */
        struct miniscript_node_t {
            const miniscript_item_t *info;
            struct miniscript_node_t *next;
            struct miniscript_node_t *back;
            struct miniscript_node_t *child;
            unsigned int chain_count;
            int kind;
            uint32_t wrapper;
            int64_t number;
            char *data;
            char *derive_path;
            unsigned short data_size;
            unsigned short derive_path_len;
            unsigned char is_derive;
        };


    return ret;
}

static int realloc_substr_buffer(size_t need_len, char **buffer, size_t *buffer_len)
{
    size_t need_size = ((need_len / 64) + 1) * 64;
    if (need_len > *buffer_len) {
        wally_free_string(*buffer);
        *buffer = (char *) wally_malloc(need_len);
        if (*buffer == NULL)
            return WALLY_ENOMEM;

        *buffer_len = need_len;
    }
    return WALLY_OK;
}

static int analyze_miniscript(
    const char *miniscript,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    miniscript_node_t *prev_node,
    miniscript_node_t *parent_node,
    miniscript_node_t **generate_node)
{
    int ret;
    char wrapper[12];
    char *sub_str = NULL;
    size_t index;
    size_t str_len;
    size_t sub_str_len = 0;
    size_t offset = 0;
    size_t child_offset = 0;
    uint32_t indent = 0;
    bool collect_child = false;
    bool exist_indent = false;
    bool copy_child = false;
    char buffer[64];
    char checksum[12];
    char work_checksum[12];
    size_t checksum_len = 0;
    size_t checksum_index = 0;
    char prev = 0;
    int child_count = 0;
    miniscript_node_t *node;
    miniscript_node_t *child = NULL;
    miniscript_node_t *prev_child = NULL;

    str_len = strlen(miniscript);

    node = (miniscript_node_t) wally_malloc(sizeof(miniscript_node_t));
    if (!node)
        return WALLY_ENOMEM;

    wally_bzero(node, sizeof(miniscript_node_t));
    wally_bzero(wrapper, sizeof(wrapper));
    wally_bzero(buffer, sizeof(buffer));
    wally_bzero(checksum, sizeof(checksum));
    wally_bzero(work_checksum, sizeof(work_checksum));

    for (index = 0; index < str_len; ++index) {
        if (!node->info && (miniscript[index] == ':')) {
            memcpy(wrapper, miniscript[offset], index - offset - 1);
            offset = index + 1;
        } else if (miniscript[index] == '(') {
            if (!node->info && (indent == 0)) {
                collect_child = true;
                memcpy(buffer, miniscript[offset], index - offset - 1);
                node->info = search_miniscript_info(buffer);
                if (!node->info) {
                    ret = WALLY_EINVAL;
                    break;
                }
                offset = index + 1;
                child_offset = offset;
            }
            ++indent;
            exist_indent = true;
        } else if (miniscript[index] == ')') {
            if (indent) {
                --indent;
                if (collect_child && (indent == 0)) {
                    collect_child = false;
                    offset = index + 1;
                    copy_child = true;
                }
            }
            exist_indent = true;
        } else if (miniscript[index] == ',') {
            if (collect_child && (indent == 1)) {
                copy_child = true;
            }
            exist_indent = true;
        } else if (miniscript[index] == '#') {
            if (!parent_node && node->info && !collect_child && (indent == 0)) {
                checksum_index = index;
                checksum_len = strlen(&miniscript[index + 1]);
                if (sizeof(checksum) > checksum_len) {
                    memcpy(checksum, &miniscript[index + 1], checksum_len);
                } else {
                    ret = WALLY_EINVAL;
                }
                break;  /* end */
            }
        }

        if (copy_child) {
            ret = realloc_substr_buffer(index - child_offset, &sub_str, &sub_str_len);
            if (ret)
                break;

            memcpy(sub_str, miniscript[child_offset], index - child_offset);
            sub_str[index - child_offset] = '\0';
            ret = analyze_miniscript(sub_str, key_name_array, key_value_array, array_len, prev_child, node, &child)
            if (ret)
                break;
            if (sub_str)
                wally_free_string(sub_str);

            prev_child = child;
            child = NULL;
            copy_child = false;
        }
        prev = miniscript[index];
    }

    if (!ret && !exist_indent)
        ret = analyze_miniscript_value(miniscript, key_name_array, key_value_array, array_len, node, parent_node);

    if (!ret && node->info && node->info->verify_function)
        ret = node->info->verify_function(node, parent_node);

    if (!ret && !parent_node && checksum_index) {
        /* check checksum */
        ret = realloc_substr_buffer(checksum_index + 1, &sub_str, &sub_str_len);
        if (!ret) {
            memcpy(sub_str, miniscript, checksum_index);
            sub_str[checksum_index] = '\0';
            ret = generate_descriptor_checksum(sub_str, work_checksum);
            if (!ret && (memcmp(checksum, work_checksum, MINISCRIPT_CHECKSUM_LENGTH) != 0)) {
                ret = WALLY_EINVAL;
            }
        }
    }

    if (!ret) {
        *generate_node = node;
        if (wrapper[0])
            node->wrapper = convert_miniscript_wrapper_flag(wrapper);
        if (parent_node && !parent_node->child)
            parent_node->child = node;
        if (prev_node) {
            node->chain_count = prev_node->chain_count + 1;
            node->back = prev_node;
            prev_node->next = node;
        } else {
            node->chain_count = 1;
        }
    } else {
        free_miniscript_node(node);
    }

    if (sub_str)
        wally_free_string(sub_str);
    return ret;
}

static int check_ascii_string(const char* message, size_t max)
{
    size_t index;

    if (!message)
        return WALLY_EINVAL;

    for (index = 0; message[index] != '\0'; ++index)
        if ((message[index] < 0x20) || (message[index] == 0x7f) || (index > max))
            return WALLY_EINVAL;

    return WALLY_OK;
}

static int convert_script_from_node(
    miniscript_node_t *top_node,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;

    /* FIXME convert string */


    return ret;
}

int wally_parse_miniscript(
    const char *miniscript,
    const char **key_name_array,
    const char **key_value_array,
    size_t array_len,
    unsigned char *script,
    size_t script_len,
    size_t *write_len)
{
    int ret;
    size_t index;

    if (!miniscript || !script || !write_len || !script_len ||
        (array_len && (!key_name_array || !key_value_array)) ||
        (!array_len && (key_name_array || key_value_array)) ||
        check_ascii_string(miniscript, MINISCRIPT_LIMIT_LENGTH) != WALLY_OK)
        return WALLY_EINVAL;

    if (array_len) {
        for (index = 0; index < array_len; ++index) {
            if (!key_name_array[index] || !key_value_array[index])
                return WALLY_EINVAL;
            if (check_ascii_string(key_name_array[index], MINISCRIPT_KEY_NAME_MAX_LENGTH) != WALLY_OK ||
                check_ascii_string(key_value_array[index], MINISCRIPT_KEY_VALUE_MAX_LENGTH) != WALLY_OK) {
                return WALLY_EINVAL;
            }
        }
    }

    *write_len = 0;
    miniscript_node_t *top_node = NULL;
    ret = analyze_miniscript(miniscript, key_name_array, key_value_array, array_len, NULL, NULL, &top_node);
    if (!ret)
        ret = convert_script_from_node(top_node, script, script_len, write_len);

    free_miniscript_node(top_node);
    return ret;
}
