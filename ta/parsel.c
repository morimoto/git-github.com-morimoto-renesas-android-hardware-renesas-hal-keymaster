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

#include "parsel.h"

/* Deserializers */
int TA_deserialize_blob(uint8_t *in, const uint8_t *end,
			keymaster_blob_t *blob,
			const bool check_presence,
			keymaster_error_t *res,
			bool is_input)
{
	uint8_t *data;
	const uint8_t *start = in;
	presence p = KM_POPULATED;

	TEE_MemFill(blob, 0, sizeof(*blob));
	if (check_presence) {
		if (IS_OUT_OF_BOUNDS(in, end, sizeof(p))) {
			EMSG("Out of input array bounds on deserialization");
			*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			return in - start;
		}
		TEE_MemMove(&p, in, sizeof(p));
		in += sizeof(p);
	}
	if (p == KM_NULL)
		return sizeof(p);
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return in - start;
	}
	TEE_MemMove(&blob->data_length, in, sizeof(blob->data_length));
	in += SIZE_LENGTH;
	if (IS_OUT_OF_BOUNDS(in, end, blob->data_length)) {
		EMSG("Out of input array bounds on deserialization %lu", blob->data_length);
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return in - start;
	}
	if (!is_input) {
		/* Freed when deserialized blob is destroyed by caller */
		data = TEE_Malloc(blob->data_length, TEE_MALLOC_FILL_ZERO);
		if (!data) {
			EMSG("Failed to allocate memory for blob");
			*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			return in - start;
		}
		TEE_MemMove(data, in, blob->data_length);
		in += blob->data_length;
		blob->data = data;
	} else {
		/* Not allocate memory, it can be too large */
		blob->data = in;
	}
	return in - start;
}

int TA_deserialize_param_set(uint8_t *in, const uint8_t *end,
			keymaster_key_param_set_t *params,
			const bool check_presence, keymaster_error_t *res)
{
	const uint8_t *start = in;
	presence p = KM_POPULATED;

	TEE_MemFill(params, 0, sizeof(*params));
	if (check_presence) {
		if (IS_OUT_OF_BOUNDS(in, end, sizeof(p))) {
			EMSG("Out of input array bounds on deserialization");
			*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			return in - start;
		}
		TEE_MemMove(&p, in, sizeof(p));
		in += sizeof(p);
	}
	if (p == KM_NULL)
		return in - start;
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return in - start;
	}
	TEE_MemMove(&params->length, in, sizeof(params->length));
	in += SIZE_LENGTH;
	/* Do +3 to params count to have memory for
	 * adding KM_TAG_ORIGIN params and key size with RSA
	 * public exponent on import
	 */
	params->params = TEE_Malloc(sizeof(keymaster_key_param_t)
			* (params->length + ADDITIONAL_TAGS),
			TEE_MALLOC_FILL_ZERO);
	/* Freed when deserialized params set is destroyed by caller */
	if (!params->params) {
		EMSG("Failed to allocate memory for params");
		*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		return in - start;
	}
	for (size_t i = 0; i < params->length; i++) {
		if (IS_OUT_OF_BOUNDS(in, end, SIZE_OF_ITEM(params->params))) {
			EMSG("Out of input array bounds on deserialization");
			*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			return in - start;
		}
		TEE_MemMove(params->params + i, in,
			SIZE_OF_ITEM(params->params));
		in += SIZE_OF_ITEM(params->params);
		if (keymaster_tag_get_type(params->params[i].tag)
				== KM_BIGNUM || keymaster_tag_get_type(
				params->params[i].tag) == KM_BYTES) {
			in += TA_deserialize_blob(in, end,
				&(params->params[i].key_param.blob),
				false, res, false);
			if (*res != KM_ERROR_OK)
				return in - start;
	}
	}
	return in - start;
}

int TA_deserialize_key_blob(const uint8_t *in, const uint8_t *end,
			keymaster_key_blob_t *key_blob,
			keymaster_error_t *res)
{
	uint8_t *key_material;

	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(&key_blob->key_material_size, in,
				sizeof(key_blob->key_material_size));
	in += SIZE_LENGTH;
	if (IS_OUT_OF_BOUNDS(in, end, key_blob->key_material_size)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return SIZE_LENGTH;
	}
	/* Freed when deserialized key blob is destoyrd by caller */
	key_material = TEE_Malloc(key_blob->key_material_size,
							TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Fialed to allocate memory for key_material");
		*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		return 0;
	}
	TEE_MemMove(key_material, in, key_blob->key_material_size);
	key_blob->key_material = key_material;
	return KEY_BLOB_SIZE(key_blob);
}

int TA_deserialize_op_handle(const uint8_t *in, const uint8_t *in_end,
			keymaster_operation_handle_t *op_handle,
			keymaster_error_t *res)
{
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(*op_handle))) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(op_handle, in,
		sizeof(*op_handle));
	return sizeof(*op_handle);
}

int TA_deserialize_purpose(const uint8_t *in, const uint8_t *in_end,
			keymaster_purpose_t *purpose, keymaster_error_t *res)
{
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(*purpose))) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(purpose, in, sizeof(*purpose));
	return sizeof(*purpose);
}

int TA_deserialize_key_format(const uint8_t *in, const uint8_t *in_end,
			keymaster_key_format_t *key_format,
			keymaster_error_t *res)
{
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(*key_format))) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(key_format, in, sizeof(*key_format));
	return sizeof(*key_format);
}

/* Serializers */
int TA_serialize_blob(uint8_t *out, const keymaster_blob_t *blob)
{
	TEE_MemMove(out, &blob->data_length, sizeof(blob->data_length));
	out += SIZE_LENGTH;
	TEE_MemMove(out, blob->data, blob->data_length);
	return BLOB_SIZE(blob);
}

int TA_serialize_characteristics(uint8_t *out,
			const keymaster_key_characteristics_t *characteristics)
{
	uint8_t *start = out;

	TEE_MemMove(out, &characteristics->hw_enforced.length,
				sizeof(characteristics->hw_enforced.length));
	out += SIZE_LENGTH;
	for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
		TEE_MemMove(out, characteristics->hw_enforced.params + i,
			SIZE_OF_ITEM(characteristics->hw_enforced.params));
		out += SIZE_OF_ITEM(characteristics->hw_enforced.params);
		if (keymaster_tag_get_type(characteristics->
				hw_enforced.params[i].tag) == KM_BIGNUM ||
				keymaster_tag_get_type(characteristics->
				hw_enforced.params[i].tag) == KM_BYTES) {
			out += TA_serialize_blob(out, &(characteristics->
				hw_enforced.params[i].key_param.blob));
		}
	}
	TEE_MemMove(out, &characteristics->sw_enforced.length,
				sizeof(characteristics->sw_enforced.length));
	out += SIZE_LENGTH;
	for (size_t i = 0; i < characteristics->sw_enforced.length; i++) {
		TEE_MemMove(out, characteristics->sw_enforced.params + i,
			SIZE_OF_ITEM(characteristics->sw_enforced.params));
		out += SIZE_OF_ITEM(characteristics->sw_enforced.params);
		if (keymaster_tag_get_type(characteristics->
				sw_enforced.params[i].tag) == KM_BIGNUM ||
				keymaster_tag_get_type(characteristics->
				sw_enforced.params[i].tag) == KM_BYTES) {
			out += TA_serialize_blob(out, &((characteristics->
				sw_enforced.params + i)->key_param.blob));
		}
	}
	return out - start;
}

int TA_serialize_key_blob(uint8_t *out, const keymaster_key_blob_t *key_blob)
{
	TEE_MemMove(out, &key_blob->key_material_size,
				sizeof(key_blob->key_material_size));
	out += SIZE_LENGTH;
	TEE_MemMove(out, key_blob->key_material, key_blob->key_material_size);
	return KEY_BLOB_SIZE(key_blob);
}

int TA_serialize_cert_chain(uint8_t *out,
			const keymaster_cert_chain_t *cert_chain,
			keymaster_error_t *res)
{
	uint8_t *start = out;

	if (!cert_chain) {
		EMSG("Failed to allocate memory for certificate chain entries");
		*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		return 0;
	}
	TEE_MemMove(out, &cert_chain->entry_count,
				sizeof(cert_chain->entry_count));
	out += SIZE_LENGTH;
	for (size_t i = 0; i < cert_chain->entry_count; i++) {
		TEE_MemMove(out, &cert_chain->entries[i].data_length,
				sizeof(cert_chain->entries[i].data_length));
		out += SIZE_LENGTH;
		cert_chain->entries[i].data = TEE_Malloc(
				cert_chain->entries[i].data_length *
				SIZE_OF_ITEM(cert_chain->entries[i].data),
				TEE_MALLOC_FILL_ZERO);
		if (!cert_chain->entries[i].data) {
			EMSG("Failed to allocate memory for certificate chain");
			*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			return 0;
		}
		TEE_MemMove(out, cert_chain->entries[i].data,
				cert_chain->entries[i].data_length);
		out += cert_chain->entries[i].data_length;
	}
	return out - start;
}

int TA_serialize_param_set(uint8_t *out,
			const keymaster_key_param_set_t *params)
{
	uint8_t *start = out;

	TEE_MemMove(out, &params->length, sizeof(params->length));
	out += SIZE_LENGTH;
	for (size_t i = 0; i < params->length; i++) {
		TEE_MemMove(out, params->params + i,
				SIZE_OF_ITEM(params->params));
		out += SIZE_OF_ITEM(params->params);
		if (keymaster_tag_get_type(params->params[i].tag) == KM_BIGNUM
				|| keymaster_tag_get_type(params->
				params[i].tag) == KM_BYTES) {
			out += TA_serialize_blob(out,
				&(params->params[i].key_param.blob));
		}
	}
	return out - start;
}
