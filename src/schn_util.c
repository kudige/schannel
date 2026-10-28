/* Editor Settings: expandtabs and use 4 spaces for indentation
 * ex: set softtabstop=4 tabstop=8 expandtab shiftwidth=4: *
 */

/*
 * Copyright © BeyondTrust Software 2004 - 2019
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * BEYONDTRUST MAKES THIS SOFTWARE AVAILABLE UNDER OTHER LICENSING TERMS AS
 * WELL. IF YOU HAVE ENTERED INTO A SEPARATE LICENSE AGREEMENT WITH
 * BEYONDTRUST, THEN YOU MAY ELECT TO USE THE SOFTWARE UNDER THE TERMS OF THAT
 * SOFTWARE LICENSE AGREEMENT INSTEAD OF THE TERMS OF THE APACHE LICENSE,
 * NOTWITHSTANDING THE ABOVE NOTICE.  IF YOU HAVE QUESTIONS, OR WISH TO REQUEST
 * A COPY OF THE ALTERNATE LICENSING TERMS OFFERED BY BEYONDTRUST, PLEASE CONTACT
 * BEYONDTRUST AT beyondtrust.com/contact
 */

/*
 * Authors: Rafal Szczesniak (rafal@likewisesoftware.com)
 */

#include "includes.h"

#ifdef AES_ENABLED
const unsigned char schannel_sig_sign[] = {0x13, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00};
const unsigned char schannel_sig_seal[] = {0x13, 0x00, 0x1a, 0x00, 0xff, 0xff, 0x00, 0x00};
#else
const unsigned char schannel_sig_sign[] = {0x77, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00};
const unsigned char schannel_sig_seal[] = {0x77, 0x00, 0x7a, 0x00, 0xff, 0xff, 0x00, 0x00};
#endif

#ifdef AES_ENABLED
/* Nonce and payload form one continuous CFB8 stream. */
int schn_aes_crypt(const unsigned char key[16], const unsigned char iv[16],
                   unsigned char *first, size_t first_len,
                   unsigned char *second, size_t second_len, int encrypt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char final[EVP_MAX_BLOCK_LENGTH];
    unsigned char *parts[] = {first, second};
    size_t lengths[] = {first_len, second_len};
    int written, i;
    int ok = ctx && EVP_CipherInit_ex(ctx, EVP_aes_128_cfb8(), NULL,
                                     key, iv, encrypt) == 1;

    for (i = 0; ok && i < 2; i++) {
        while (ok && lengths[i]) {
            int chunk = lengths[i] > INT_MAX ? INT_MAX : (int)lengths[i];
            ok = EVP_CipherUpdate(ctx, parts[i], &written, parts[i], chunk) == 1 &&
                 written == chunk;
            parts[i] += chunk;
            lengths[i] -= chunk;
        }
    }
    if (ok) {
        ok = EVP_CipherFinal_ex(ctx, final, &written) == 1 && written == 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
#endif


int schn_sign_digest(unsigned char sess_key[16],
                      const unsigned char nonce[8],
                      const unsigned char schannel_sig[8],
                      const struct schn_blob *blob,
                      unsigned char digest[32])
{
#ifdef AES_ENABLED
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    char name[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, name, 0),
        OSSL_PARAM_END
    };
    size_t length = 0;
    int ok = ctx && EVP_MAC_init(ctx, sess_key, 16, params) == 1 &&
        EVP_MAC_update(ctx, schannel_sig, 8) == 1;

    if (ok && memcmp(schannel_sig, schannel_sig_seal, 8) == 0) {
        ok = EVP_MAC_update(ctx, nonce, 8) == 1;
    }
    if (ok) {
        ok = EVP_MAC_update(ctx, blob->base, blob->len) == 1 &&
            EVP_MAC_final(ctx, digest, &length, 32) == 1 && length == 32;
    }
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;

#else
    unsigned int digest_len;
    MD5_CTX   ctx;
    HMAC_CTX *hmac_ctx;
    unsigned char init_buffer[4];
    unsigned char dig[16];

    memset(init_buffer, 0, sizeof(init_buffer));
    memset(&ctx, 0, sizeof(ctx));
    MD5_Init(&ctx);
    MD5_Update(&ctx, init_buffer, 4);
    MD5_Update(&ctx, schannel_sig, 8);
    if (memcmp((void*)schannel_sig, (void*)schannel_sig_seal, 8) == 0)
    {
        MD5_Update(&ctx, nonce, 8);
    }
    MD5_Update(&ctx, blob->base, blob->len);
    MD5_Final(dig, &ctx);

    hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, (void*)sess_key, 16, EVP_md5(), NULL);
    HMAC_Update(hmac_ctx, (unsigned char*)dig, sizeof(dig));
    HMAC_Final(hmac_ctx, (unsigned char*)digest, &digest_len);

    HMAC_CTX_free(hmac_ctx);
    return 1;
#endif    
}


void schn_sign_get_seq_number(void *sec_ctx,
                              uint32 sender_flags,
                              uint8 seq_number[8])
{
    struct schn_auth_ctx *schn_ctx = NULL;

    schn_ctx = (struct schn_auth_ctx*)sec_ctx;

    /* LSB last */
    seq_number[0] = (uint8)((schn_ctx->seq_num >> 24) & 0xff);
    seq_number[1] = (uint8)((schn_ctx->seq_num >> 16) & 0xff);
    seq_number[2] = (uint8)((schn_ctx->seq_num >> 8)  & 0xff);
    seq_number[3] = (uint8)((schn_ctx->seq_num)       & 0xff);

    /* LSB first */
    seq_number[4] = (uint8)((sender_flags)       & 0xff);
    seq_number[5] = (uint8)((sender_flags >> 8)  & 0xff);
    seq_number[6] = (uint8)((sender_flags >> 16) & 0xff);
    seq_number[7] = (uint8)((sender_flags >> 24) & 0xff);
}


int schn_sign_update_seqnum(const unsigned char digest[8],
                             const unsigned char sess_key[16],
                             uint32 *seq_num,
                             unsigned char sequence[8])
{
#ifdef AES_ENABLED
    unsigned char ivec[16];

    memcpy(ivec, digest, 8);
    memcpy(ivec + 8, digest, 8);
    if (!schn_aes_crypt(sess_key, ivec, sequence, 8, NULL, 0, 1)) {
        return 0;
    }

#else
    unsigned char seq_key[16];
    unsigned char init_buffer[4];
    unsigned char dig[16];
    HMAC_CTX *hmac_ctx;
    unsigned int dig_len;
    unsigned int seq_key_len;
    RC4_KEY rc4_key;

    memset(init_buffer, 0, sizeof(init_buffer));
    memset(&rc4_key, 0, sizeof(rc4_key));

    hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, (unsigned char*)sess_key, 16, EVP_md5(), NULL);
    HMAC_Update(hmac_ctx, (unsigned char*)init_buffer, 4);
    HMAC_Final(hmac_ctx, (unsigned char*)dig, &dig_len);
    HMAC_CTX_free(hmac_ctx);

    hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, (unsigned char *)dig, 16, EVP_md5(), NULL);
    HMAC_Update(hmac_ctx, (unsigned char*)digest, 8);
    HMAC_Final(hmac_ctx, (unsigned char*)seq_key, &seq_key_len);
        HMAC_CTX_free(hmac_ctx);

    RC4_set_key(&rc4_key, sizeof(seq_key), (unsigned char*)seq_key);
    RC4(&rc4_key, 8, (unsigned char*)sequence,(unsigned char*)sequence);
#endif
    (*seq_num)++;
    return 1;
}


void schn_seal_generate_key(const unsigned char sess_key[16],
                            const unsigned char seq_number[8],
                            unsigned char seal_key[16])
{
    uint32 i;
    unsigned char key[16];
    key[0] = seq_number[0]; // For unused warning
    for (i = 0; i < sizeof(key); i++) {
        key[i] = sess_key[i] ^ 0xf0;
    }
    memmove(seal_key, key, sizeof key);
    
#ifndef AES_ENABLED
    unsigned char init_buffer[4] = {0, 0, 0, 0};
    HMAC_CTX *hmac_ctx;
    unsigned int digest_len, seal_key_len;
    unsigned char digest[16];

    memset(init_buffer, 0, sizeof(init_buffer));

    hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, (unsigned char*)key, 16, EVP_md5(), NULL);
    HMAC_Update(hmac_ctx, (unsigned char*)init_buffer, 4);
    HMAC_Final(hmac_ctx, digest, &digest_len);
    //HMAC_CTX_free(hmac_ctx);

    hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, (unsigned char *)digest, 16, EVP_md5(), NULL);
    HMAC_Update(hmac_ctx, (unsigned char*)seq_number, 8);
    HMAC_Final(hmac_ctx, seal_key, &seal_key_len);
    //HMAC_CTX_reset(hmac_ctx);
    //HMAC_CTX_free(hmac_ctx);
#endif    
}


void schn_free_blob(struct schn_blob *b)
{
    if (b == NULL) return;

    memset(b->base, 0, b->len);
    free(b->base);

    b->base = NULL;
    b->len  = 0;
}


#pragma GCC diagnostic ignored "-Wunused-but-set-parameter"
void schn_debug_printf(const char *fmt, ...) {
#ifdef SCHANNEL_DEBBUG
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#else
    fmt = fmt+1;
#endif
}

void schn_error_printf(const char *fmt, ...) {
#ifdef SCHANNEL_ERRLOG
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
#else
    fmt = fmt+1;    
#endif
}

#pragma GCC diagnostic ignored "-Wunused-but-set-parameter"
void schn_display_buffer(const char *name, unsigned char *buffer, int length) {
#ifdef SCHANNEL_DEBUG
    int i;
    printf("Buffer %s: ", name);
    for (i = 0; i < length; i++) {
        printf(" %02x", (int)buffer[i]);
    }
    printf("\n");
#else
// For warnings
    name   = name+1;
    buffer = buffer+1;
    length = length+1;
#endif
}

/*
local variables:
mode: c
c-basic-offset: 4
indent-tabs-mode: nil
tab-width: 4
end:
*/
