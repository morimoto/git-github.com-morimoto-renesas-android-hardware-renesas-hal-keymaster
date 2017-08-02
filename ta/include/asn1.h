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

#ifndef ANDROID_OPTEE_ASN1_H
#define ANDROID_OPTEE_ASN1_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "generator.h"

#define CMD_PARSE 0
#define CMD_X509_ENCODE 1
#define CMD_EC_SIGN_ENCODE 2
#define CMD_EC_SIGN_DECODE 3

keymaster_error_t TA_decode_pkcs8(const TEE_TASessionHandle sessionSTA,
				keymaster_blob_t key_data,
				TEE_Attribute **attrs,
				uint32_t *attrs_count,
				const keymaster_algorithm_t algorithm,
				uint32_t *key_size,
				uint64_t *rsa_public_exponent);

keymaster_error_t TA_encode_ec_sign(const TEE_TASessionHandle sessionSTA,
				uint8_t *out, uint32_t *out_l);

keymaster_error_t TA_decode_ec_sign(const TEE_TASessionHandle sessionSTA,
				keymaster_blob_t *signature,
				uint32_t key_size);

keymaster_error_t TA_encode_key(const TEE_TASessionHandle sessionSTA,
				keymaster_blob_t *export_data,
				const uint32_t type,
				const TEE_ObjectHandle *obj_h,
				const uint32_t key_size);

#endif/*ANDROID_OPTEE_ASN1_H*/
