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

#include "asn1.h"

keymaster_error_t TA_decode_pkcs8(const TEE_TASessionHandle sessionSTA,
				keymaster_blob_t key_data,
				TEE_Attribute **attrs,
				uint32_t *attrs_count,
				const keymaster_algorithm_t algorithm,
				uint32_t *key_size,
				uint64_t *rsa_public_exponent)
{
	uint8_t *buf = NULL;
	uint8_t *output = NULL;
	uint32_t output_size = 8 * 1024;
	uint32_t max_attrs = 0;
	uint32_t tag = 0;
	uint32_t padding = 0;
	uint32_t attr_size = 0;
	uint32_t *attrs_list = TA_get_attrs_list_short(algorithm, true);
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);
	TEE_Param params[TEE_NUM_PARAMS];

	output = TEE_Malloc(output_size, TEE_MALLOC_FILL_ZERO);
	if (!output) {
		EMSG("Failed to allocate memory for ASN.1 parser output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	params[2].memref.buffer = output;
	params[2].memref.size = output_size;
	params[1].value.a = algorithm;
	params[0].memref.buffer = key_data.data;
	params[0].memref.size = key_data.data_length;
	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
				CMD_PARSE, exp_param_types, params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for ASN.1 parser failed");
		goto out;
	}
	if (params[2].memref.size == 0) {
		EMSG("ASN.1 parser output is empty");
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}
	if (*key_size == UNDEFINED)
		*key_size = params[3].value.a;
	if (algorithm == KM_ALGORITHM_RSA)
		max_attrs = KM_ATTR_COUNT_RSA;
	else
		max_attrs = KM_ATTR_COUNT_EC;
	*attrs = TEE_Malloc(sizeof(TEE_Attribute) * max_attrs,
							TEE_MALLOC_FILL_ZERO);
	if (!(*attrs)) {
		EMSG("Failed to allocate memory for attributes on key import");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	while (*attrs_count < max_attrs) {
		if (padding > params[2].memref.size) {
			EMSG("Failed to get all key params from ASN.1 parser");
			res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
			goto out;
		}
		tag = attrs_list[*attrs_count];
		TEE_MemMove(&attr_size, output + padding, sizeof(attr_size));
		padding += sizeof(attr_size);
		buf = TEE_Malloc(attr_size, TEE_MALLOC_FILL_ZERO);
		if (!buf) {
			EMSG("Failed to allocate memory for imported attribute buffer");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		TEE_MemMove(buf, output + padding, attr_size);
		padding += attr_size;
		if (algorithm == KM_ALGORITHM_RSA && *attrs_count == 1 &&
					*rsa_public_exponent == UNDEFINED)
			TEE_MemMove(rsa_public_exponent, buf, attr_size);
		TEE_InitRefAttribute(*attrs + *attrs_count,
				tag, buf, attr_size);
		(*attrs_count)++;
		if (algorithm == KM_ALGORITHM_EC && *attrs_count == max_attrs - 1)
			/* the Curve attribute is defined later */
			break;
	}
out:
	if (output)
		TEE_Free(output);
	return res;
}

keymaster_error_t TA_encode_ec_sign(const TEE_TASessionHandle sessionSTA,
				uint8_t *out, uint32_t *out_l)
{
	uint32_t r_size = *out_l / 2;
	uint32_t s_size = *out_l / 2;
	uint8_t r[r_size];
	uint8_t s[s_size];
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS];

	TEE_MemMove(r, out, r_size);
	TEE_MemMove(s, out + r_size, s_size);
	params[2].memref.buffer = out;
	params[2].memref.size = 0;
	params[1].memref.buffer = s;
	params[1].memref.size = s_size;
	params[0].memref.buffer = r;
	params[0].memref.size = r_size;
	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
				CMD_EC_SIGN_ENCODE, exp_param_types,
				params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for ASN.1 parser (EC sign) failed");
		goto out;
	}
	if (params[2].memref.size == 0) {
		EMSG("ASN.1 parser (EC sign) output is empty");
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}
out:
	*out_l = params[2].memref.size;
	return res;
}

keymaster_error_t TA_encode_key(const TEE_TASessionHandle sessionSTA,
				keymaster_blob_t *export_data,
				const uint32_t type,
				const TEE_ObjectHandle *obj_h,
				const uint32_t key_size)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t attr1_l = KM_RSA_ATTR_SIZE;
	uint32_t attr2_l = KM_RSA_ATTR_SIZE;
	uint8_t *attr1 = TEE_Malloc(attr1_l, TEE_MALLOC_FILL_ZERO);
	uint8_t *attr2 = TEE_Malloc(attr2_l, TEE_MALLOC_FILL_ZERO);
	uint8_t *output = NULL;
	uint32_t output_size = 1024;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT);
	TEE_Param params[TEE_NUM_PARAMS];

	if (!attr1 || !attr2) {
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		EMSG("Failed to allocate memory for local buffers");
		goto out;
	}
	if (type == TEE_TYPE_RSA_KEYPAIR) {
		res = TEE_GetObjectBufferAttribute(*obj_h,
					TEE_ATTR_RSA_MODULUS, attr1, &attr1_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get modulus attribute res = %x", res);
			goto out;
		}
		res = TEE_GetObjectBufferAttribute(*obj_h,
				TEE_ATTR_RSA_PUBLIC_EXPONENT, attr2, &attr2_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get public exponent attribute res = %x",
									res);
			goto out;
		}
	} else {
		res = TEE_GetObjectBufferAttribute(*obj_h,
				TEE_ATTR_ECC_PUBLIC_VALUE_X, attr1, &attr1_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get public X attribute res = %x", res);
			goto out;
		}
		res = TEE_GetObjectBufferAttribute(*obj_h,
				TEE_ATTR_ECC_PUBLIC_VALUE_Y, attr2, &attr2_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get public Y attribute res = %x", res);
			goto out;
		}
	}
	output = TEE_Malloc(output_size, TEE_MALLOC_FILL_ZERO);
	if (!output) {
		EMSG("Failed to allocate memory for x.509 buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	params[3].memref.buffer = output;
	params[3].memref.size = output_size;
	params[2].value.a = type;
	params[2].value.b = key_size;
	params[1].memref.buffer = attr2;
	params[1].memref.size = attr2_l;
	params[0].memref.buffer = attr1;
	params[0].memref.size = attr1_l;
	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
				CMD_X509_ENCODE, exp_param_types, params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for x.509 ASN.1 encoder failed");
		goto out;
	}
	if (params[3].memref.size == 0) {
		EMSG("x.509 ASN.1 encoder output is empty");
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}
	export_data->data_length = params[3].memref.size;
	export_data->data = TEE_Malloc(export_data->data_length,
							TEE_MALLOC_FILL_ZERO);
	if (!export_data->data) {
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		EMSG("Failed to allocate memory for x.509 output");
		goto out;
	}
	TEE_MemMove(export_data->data, params[3].memref.buffer,
					export_data->data_length);
out:
	if (attr1)
		TEE_Free(attr1);
	if (attr2)
		TEE_Free(attr2);
	if (output)
		TEE_Free(output);
	return res;
}
