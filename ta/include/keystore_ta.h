/*
 *
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_OPTEE_KEYSTORE_TA_H
#define ANDROID_OPTEE_KEYSTORE_TA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "operations.h"
#include "tables.h"
#include "parsel.h"
#include "master_crypto.h"
#include "paddings.h"
#include "parameters.h"
#include "generator.h"
#include "asn1.h"
#include "crypto_aes.h"
#include "crypto_rsa.h"

/* ASN.1 parser static TA */
#define ASN1_PARSER_UUID \
		{ 0x273fcb14, 0xe831, 0x4cf2, \
			{ 0x93, 0xc4, 0x76, 0x15, 0xdb, 0xd3, 0x0e, 0x90 } }

/* RNG entropy static TA */
#define RNG_ENTROPY_UUID \
		{ 0x57ff3310, 0x0919, 0x4935, \
			{ 0xb9, 0xc8, 0x32, 0xa4, 0x1d, 0x94, 0xb9, 0x5b } }

#define CMD_ADD_RNG_ENTROPY 0

/* Empty definitions */
#define EMPTY_CERT_CHAIN {.entries = NULL, .entry_count = 0}
#define EMPTY_BLOB {.data = NULL, .data_length = 0}
#define EMPTY_KEY_BLOB {.key_material = NULL, .key_material_size = 0}
#define EMPTY_PARAM_SET {.params = NULL, .length = 0}
#define EMPTY_CHARACTS {					\
			.hw_enforced = EMPTY_PARAM_SET,	\
			.sw_enforced = EMPTY_PARAM_SET}
#define EMPTY_OPERATION {					\
			.key = NULL,					\
			.nonce = EMPTY_BLOB,			\
			.op_handle = UNDEFINED,			\
			.purpose = UNDEFINED,			\
			.padding = UNDEFINED,			\
			.mode = UNDEFINED,				\
			.sf_item = NULL,				\
			.last_access = NULL,			\
			.operation = TEE_HANDLE_NULL,	\
			.digest_op = TEE_HANDLE_NULL,	\
			.prev_in_size = UNDEFINED,		\
			.min_sec = UNDEFINED,			\
			.mac_length = UNDEFINED,		\
			.a_data_length = 0,				\
			.a_data = NULL,					\
			.do_auth = false,				\
			.got_input = false,				\
			.buffering = false,				\
			.padded = false}

uint64_t identifier_rsa[] = {1, 2, 840, 113549, 1, 1, 1};
/* RSAPrivateKey ::= SEQUENCE {
 *    version Version,
 *    modulus INTEGER, -- n
 *    publicExponent INTEGER, -- e
 *    privateExponent INTEGER, -- d
 *    prime1 INTEGER, -- p
 *    prime2 INTEGER, -- q
 *    exponent1 INTEGER, -- d mod (p-1)
 *    exponent2 INTEGER, -- d mod (q-1)
 *    coefficient INTEGER -- (inverse of q) mod p }
 */

uint64_t identifier_ec[] = {1, 2, 840, 10045, 2, 1};
/* ECPrivateKey ::= SEQUNCE {
 *    version Version,
 *    secretValue OCTET_STRING,
 *    publicValue CONSTRUCTED {
 *        XYValue BIT_STRING } }
 */

static bool TA_is_stream_cipher(keymaster_block_mode_t mode)
{
	switch (mode) {
	case KM_MODE_CBC:
	case KM_MODE_ECB:
		return false;
	default:/*KM_MODE_GCM, KM_MODE_CTR*/
		return true;
	}
}

static keymaster_error_t TA_append_input(keymaster_blob_t *input,
			keymaster_operation_t *operation,
			const uint32_t to_copy);

static keymaster_error_t check_patch_and_ver(const uint32_t patch,
			const uint32_t ver);

static keymaster_error_t TA_save_gcm_tag(keymaster_blob_t *input,
				keymaster_operation_t *operation);

static keymaster_error_t TA_Configure(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Add_rng_entropy(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Generate_key(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Get_key_characteristics(
					TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Import_key(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Export_key(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Attest_key(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Upgrade_key(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Delete_key(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Delete_all_keys(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Begin(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Update(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Finish(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_Abort(TEE_Param params[TEE_NUM_PARAMS]);
#endif  /* ANDROID_OPTEE_KEYSTORE_TA_H */
