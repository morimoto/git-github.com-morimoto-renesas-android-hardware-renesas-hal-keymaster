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

#ifndef ANDROID_OPTEE_PARAMETERS_H
#define ANDROID_OPTEE_PARAMETERS_H

#define KM_DIGEST_MD5_SIZE 128
#define KM_DIGEST_SHA1_SIZE 160
#define KM_DIGEST_SHA_2_224_SIZE 224
#define KM_DIGEST_SHA_2_256_SIZE 256
#define KM_DIGEST_SHA_2_384_SIZE 384
#define KM_DIGEST_SHA_2_512_SIZE 512

#define MAX_GCM_MAC 128
#define MAX_ENFORCED_PARAMS_COUNT 30
#define MIN_MML 96
#define MAX_MML 128
#define MIN_MML_HMAC 64
#define MAX_KEY_HMAC 1024
#define MIN_KEY_HMAC 64
#define MAX_KEY_RSA (4 * 1024)

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "tables.h"
#include "auth.h"
#include "common.h"

uint32_t get_digest_size(const keymaster_digest_t *digest);

keymaster_error_t TA_check_permission(const keymaster_key_param_set_t *params,
				const keymaster_blob_t client_id,
				const keymaster_blob_t app_data,
				bool *exportable);

keymaster_error_t TA_check_params(keymaster_key_blob_t *key,
				const keymaster_key_param_set_t *key_params,
				const keymaster_key_param_set_t *in_params,
				keymaster_algorithm_t *algorithm,
				const keymaster_purpose_t op_purpose,
				keymaster_digest_t *digest,
				keymaster_block_mode_t *mode,
				keymaster_padding_t *padding,
				uint32_t *mac_length,
				keymaster_blob_t *nonce, uint32_t *min_sec,
				bool *do_auth);

void TA_push_param(keymaster_key_param_set_t *params,
			const keymaster_key_param_t *param);

keymaster_error_t TA_parse_params(const keymaster_key_param_set_t params,
				keymaster_algorithm_t *algorithm,
				uint32_t *key_size,
				uint64_t *rsa_public_exponent,
				keymaster_digest_t *digest,
				const bool import);

keymaster_error_t TA_fill_characteristics(
			keymaster_key_characteristics_t *chararecteristics,
			const keymaster_key_param_set_t *params,
			uint32_t *size);

void TA_add_origin(keymaster_key_param_set_t *params_t,
		const keymaster_key_origin_t origin, const bool replace_origin);

bool cmpBlobParam(const keymaster_blob_t blob,
			const keymaster_key_param_t param);

bool is_origination_purpose(const keymaster_purpose_t purpose);

void TA_add_to_params(keymaster_key_param_set_t *params,
				const uint32_t key_size,
				const uint64_t rsa_public_exponent);

void TA_free_params(keymaster_key_param_set_t *params);

#endif/* ANDROID_OPTEE_PARAMETERS_H */
