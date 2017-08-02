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

#ifndef ANDROID_OPTEE_PARSEL_H
#define ANDROID_OPTEE_PARSEL_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "common.h"
#include "ta_ca_defs.h"

#define MAX_OCTET_COUNT 10
#define ADDITIONAL_TAGS 3 /*
			   * Number of tags that can be added
			   * (KM_TAG_ORIGIN, KM_TAG_KEY_SIZE,
			   * KM_TAG_RSA_PUBLIC_EXPONENT)
			   */

#define IS_OUT_OF_BOUNDS(ptr, end, required) \
			(end ? (ptr + required > end) : false)

/* Serealizers */
int TA_serialize_blob(uint8_t *out, const keymaster_blob_t *export_data);

int TA_serialize_characteristics(uint8_t *out,
			const keymaster_key_characteristics_t *characteristics);

int TA_serialize_key_blob(uint8_t *out, const keymaster_key_blob_t *key_blob);

int TA_serialize_cert_chain(uint8_t *out,
			const keymaster_cert_chain_t *cert_chain,
			keymaster_error_t *res);

int TA_serialize_param_set(uint8_t *out,
			const keymaster_key_param_set_t *params);

/* Deseriazers */
int TA_deserialize_blob(uint8_t *in, const uint8_t *end,
			keymaster_blob_t *blob_t,
			const bool check_presence, keymaster_error_t *res,
			bool is_input);

int TA_deserialize_param_set(uint8_t *in, const uint8_t *end,
			keymaster_key_param_set_t *params_t,
			const bool check_presence, keymaster_error_t *res);

int TA_deserialize_key_blob(const uint8_t *in, const uint8_t *end,
			keymaster_key_blob_t *key_blob,
			keymaster_error_t *res);

int TA_deserialize_op_handle(const uint8_t *in, const uint8_t *in_end,
			keymaster_operation_handle_t *op_handle,
			keymaster_error_t *res);

int TA_deserialize_purpose(const uint8_t *in, const uint8_t *in_end,
			keymaster_purpose_t *purpose, keymaster_error_t *res);

int TA_deserialize_key_format(const uint8_t *in, const uint8_t *in_end,
			keymaster_key_format_t *key_format,
			keymaster_error_t *res);
#endif/* ANDROID_OPTEE_PARSEL_H */
