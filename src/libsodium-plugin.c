/* Copyright (c) 2016 Dovecot Oy, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "buffer.h"
#include "str.h"
#include "password-scheme.h"
#include "safe-memset.h"
#include "base64.h"
#include "hex-binary.h"
#include "randgen.h"
#include "sodium.h"
#include "libsodium-plugin.h"

#ifdef crypto_pwhash_scryptsalsa208sha256_STRPREFIX
static void scrypt_generate(const char *plaintext, const char *user ATTR_UNUSED,
                   const unsigned char **raw_password_r, size_t *size_r)
{
        char *password;

        password = t_malloc(crypto_pwhash_scryptsalsa208sha256_STRBYTES);
        if (crypto_pwhash_scryptsalsa208sha256_str
                (password, plaintext, strlen(plaintext),
                 crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                 crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
                abort();
        }
        *raw_password_r = (const unsigned char *)password;
        *size_r = strlen(password);
}

static int scrypt_verify(const char *plaintext, const char *user ATTR_UNUSED,
                       const unsigned char *raw_password, size_t size,
                       const char **error_r)
{
        if (size <= strlen(crypto_pwhash_scryptsalsa208sha256_STRPREFIX)) {
                *error_r = "Scrypt password is too short";
                return -1;
        }
        return crypto_pwhash_scryptsalsa208sha256_str_verify
                ((const char *) raw_password, plaintext, strlen(plaintext)) == 0;
}
#endif

#ifdef crypto_pwhash_STRPREFIX
static void argon2_generate(const char *plaintext, const char *user ATTR_UNUSED,
                   const unsigned char **raw_password_r, size_t *size_r)
{
        char *password;

        password = t_malloc(crypto_pwhash_scryptsalsa208sha256_STRBYTES);
        if (crypto_pwhash_str
                (password, plaintext, strlen(plaintext),
                 crypto_pwhash_OPSLIMIT_INTERACTIVE,
                 crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
                abort();
        }
        *raw_password_r = (const unsigned char *)password;
        *size_r = strlen(password);
}

static int argon2_verify(const char *plaintext, const char *user ATTR_UNUSED,
                       const unsigned char *raw_password, size_t size,
                       const char **error_r)
{
        if (size <= strlen(crypto_pwhash_STRPREFIX)) {
                *error_r = "Argon2 password is too short";
                return -1;
        }
        return crypto_pwhash_str_verify
                ((const char *) raw_password, plaintext, strlen(plaintext)) == 0;
}
#endif

static const struct password_scheme libsodium_schemes[] = {
#ifdef crypto_pwhash_scryptsalsa208sha256_STRPREFIX
        { "SCRYPT", PW_ENCODING_NONE, 0, scrypt_verify, scrypt_generate },
#endif
#ifdef crypto_pwhash_STRPREFIX
        { "ARGON2", PW_ENCODING_NONE, 0, argon2_verify, argon2_generate },
#endif
};

void sodium_plugin_init(struct module *module ATTR_UNUSED)
{
        unsigned int i;

        for (i = 0; i < N_ELEMENTS(libsodium_schemes); i++) {
                password_scheme_register(&libsodium_schemes[i]);
        }
}

void sodium_plugin_deinit(void)
{
        unsigned int i;

        for (i = 0; i < N_ELEMENTS(libsodium_schemes); i++) {
                password_scheme_unregister(&libsodium_schemes[i]);
        }
}

const char *password_scheme_version = DOVECOT_ABI_VERSION;
