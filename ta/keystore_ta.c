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
#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "common.h"
#include "ta_ca_defs.h"
#include "keystore_ta.h"

static bool config_success;
static bool configured;
static TEE_TASessionHandle sessionSTA = TEE_HANDLE_NULL;
static TEE_TASessionHandle session_rngSTA = TEE_HANDLE_NULL;

TEE_Result TA_CreateEntryPoint(void)
{
	configured = false;
	config_success = false;
	TA_reset_operations_table();
	TA_create_secret_key();
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	TA_free_master_key();
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[TEE_NUM_PARAMS], void **sess_ctx __unused)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	TEE_UUID uuid = ASN1_PARSER_UUID;
	TEE_UUID uuid_rng = RNG_ENTROPY_UUID;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE,
			exp_param_types, params, &sessionSTA, NULL);
	if (res != TEE_SUCCESS)
		EMSG("Failed to create session with static TA (%x)", res);
	res = TEE_OpenTASession(&uuid_rng, TEE_TIMEOUT_INFINITE,
			exp_param_types, params, &session_rngSTA, NULL);
	if (res != TEE_SUCCESS)
		EMSG("Failed to create session with RNG static TA (%x)", res);
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
	TEE_CloseTASession(sessionSTA);
	TEE_CloseTASession(session_rngSTA);
}

static uint32_t TA_possibe_size(const uint32_t type, const uint32_t key_size,
				const keymaster_blob_t input,
				const uint32_t tag_len)
{
	switch (type) {
	case TEE_TYPE_AES:
		/*
		 * Input can be extended to block size and one block
		 * can be added as a padding.
		 * Additionaly GCM tag can be added
		 */
		return ((input.data_length + BLOCK_SIZE - 1)
				/ BLOCK_SIZE + 1) * BLOCK_SIZE + tag_len;
	case TEE_TYPE_RSA_KEYPAIR:
		return (key_size + 7) / 8;
	case TEE_TYPE_ECDSA_KEYPAIR:
		/*
		 * Output is a sign with r and s parameters each sized as
		 * a key in ASN.1 format
		 */
		return 3 * key_size;
	default:/* HMAC */
		return KM_MAX_DIGEST_SIZE;
	}
}

static keymaster_error_t check_patch_and_ver(const uint32_t patch,
						const uint32_t ver)
{
	/* TODO CONFIGURE. Add coparasion
	 * velues with enother from bootloader
	 */
	if (patch != UNDEFINED && ver != UNDEFINED)
		config_success = true;
	return KM_ERROR_OK;
}

static keymaster_error_t TA_Configure(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	unsigned int os_ver = UNDEFINED;
	unsigned int os_patch = UNDEFINED;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;	/* IN */
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	if (configured) {
		DMSG("Keystore already configured");
		goto out;
	}
	configured = true;
	in += TA_deserialize_param_set(in, in_end, &params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto out;

	for (size_t i = 0; i < params_t.length; i++) {
		switch ((params_t.params + i)->tag) {
		case KM_TAG_OS_VERSION:
			os_ver = (params_t.params + i)->key_param.integer;
			break;
		case KM_TAG_OS_PATCHLEVEL:
			os_patch = (params_t.params + i)->key_param.integer;
			break;
		default:
			IMSG("Undefined parameter\n");
		}
	}
	if (os_ver == UNDEFINED || os_patch == UNDEFINED) {
		EMSG("Configureation failed. Not all parameters are passed\n");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto out;
	}
	res = check_patch_and_ver(os_patch, os_ver);
out:
	TA_free_params(&params_t);
	return res;
}

static keymaster_error_t TA_Add_rng_entropy(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	uint8_t *data = NULL;			/* IN */
	size_t data_length = 0;		/* IN */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param params_tee[TEE_NUM_PARAMS];
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *) params[0].memref.buffer;
	in_size = (size_t) params[0].memref.size;
	in_end = in + in_size;

	if (in_size == 0)
		return KM_ERROR_OK;
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(data_length))) {
		EMSG("Out of input array bounds on deserialization");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}
	TEE_MemMove(&data_length, in, sizeof(data_length));
	in += sizeof(data_length);
	if (IS_OUT_OF_BOUNDS(in, in_end, data_length)) {
		EMSG("Out of input array bounds on deserialization");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}
	data = TEE_Malloc(data_length, TEE_MALLOC_FILL_ZERO);
	if (!data) {
		EMSG("Failed to allocate memory for data");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(data, in, data_length);
	if (session_rngSTA == TEE_HANDLE_NULL) {
		EMSG("Session with RNG static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	params_tee[0].memref.buffer = data;
	params_tee[0].memref.size = data_length;
	res = TEE_InvokeTACommand(session_rngSTA, TEE_TIMEOUT_INFINITE,
				CMD_ADD_RNG_ENTROPY, exp_param_types, params_tee, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for RNG Entropy add failed");
		goto out;
	}
out:
	if (data)
		TEE_Free(data);
	return res;
}

static keymaster_error_t TA_Generate_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *key_material = NULL;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;		/* IN */
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB;		/* OUT */
	keymaster_key_characteristics_t characts = EMPTY_CHARACTS;/* OUT */
	keymaster_algorithm_t algorithm = UNDEFINED;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_digest_t digest = UNDEFINED;
	uint32_t padding = 0;
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint64_t rsa_public_exponent = UNDEFINED;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_param_set(in, in_end, &params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&params_t, KM_ORIGIN_GENERATED, true);
	if (res != KM_ERROR_OK)
		goto out;

	res = TA_parse_params(params_t, &algorithm, &key_size,
					&rsa_public_exponent, &digest, false);
	if (res != KM_ERROR_OK)
		goto out;

	if (key_size == UNDEFINED) {
		EMSG("Key size must be specified");
		res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
		goto out;
	}
	if (algorithm == KM_ALGORITHM_RSA &&
		  rsa_public_exponent == UNDEFINED) {
		EMSG("RSA public exponent is missed");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto out;
	}

	res = TA_fill_characteristics(&characts, &params_t,
							&characts_size);
	if (res != KM_ERROR_OK)
		goto out;

	padding = TA_get_key_size(algorithm);
	key_blob.key_material_size = characts_size + padding;
	if (key_blob.key_material_size % BLOCK_SIZE != 0) {
		/* do size alignment */
		key_blob.key_material_size += BLOCK_SIZE -
			(key_blob.key_material_size % BLOCK_SIZE);
	}
	key_material = TEE_Malloc(key_blob.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	res = TA_generate_key(algorithm, key_size, key_material, digest,
						  rsa_public_exponent);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to generate key");
		goto out;
	}

	TA_serialize_param_set(key_material + padding, &params_t);
	res = TA_encrypt(key_material, key_blob.key_material_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to encript blob");
		goto out;
	}
	key_blob.key_material = key_material;

	out += TA_serialize_key_blob(out, &key_blob);
	out += TA_serialize_characteristics(out, &characts);
out:
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&characts.sw_enforced);
	TA_free_params(&characts.hw_enforced);
	TA_free_params(&params_t);
	return res;
}

static keymaster_error_t TA_Get_key_characteristics(
					TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *key_material = NULL;
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB;	/* IN */
	keymaster_blob_t client_id = EMPTY_BLOB;	/* IN */
	keymaster_blob_t app_data = EMPTY_BLOB;		/* IN */
	keymaster_key_characteristics_t chr = EMPTY_CHARACTS;	/* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_error_t res = KM_ERROR_OK;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	uint32_t characts_size = 0;
	uint32_t key_size = 0;
	uint32_t type = 0;
	bool exportable = false;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_key_blob(in, in_end, &key_blob, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &client_id, true, &res, false);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &app_data, true, &res, false);
	if (res != KM_ERROR_OK)
		goto out;
	if (key_blob.key_material_size == 0) {
		EMSG("Bad key blob");
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		goto out;
	}
	key_material = TEE_Malloc(key_blob.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	res = TA_restore_key(key_material, &key_blob, &key_size, &type,
						 &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;

	res = TA_check_permission(&params_t, client_id, app_data, &exportable);
	if (res != KM_ERROR_OK)
		goto out;

	res = TA_fill_characteristics(&chr, &params_t, &characts_size);
	if (res != KM_ERROR_OK)
		goto out;
	out += TA_serialize_characteristics(out, &chr);
out:
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_blob.key_material)
		TEE_Free(key_blob.key_material);
	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&chr.sw_enforced);
	TA_free_params(&chr.hw_enforced);
	TA_free_params(&params_t);
	return res;
}

static keymaster_error_t TA_Import_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;	/* IN */
	keymaster_key_format_t key_format = UNDEFINED;		/* IN */
	keymaster_blob_t key_data = EMPTY_BLOB;			/* IN */
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB;/* OUT */
	keymaster_key_characteristics_t characts = EMPTY_CHARACTS;/* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_algorithm_t algorithm = UNDEFINED;
	keymaster_digest_t digest = UNDEFINED;
	TEE_Attribute *attrs_in = NULL;
	uint8_t *key_material = NULL;
	uint32_t padding = 0;
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint32_t attrs_in_count = 0;
	uint32_t curve = UNDEFINED;
	uint64_t rsa_public_exponent = UNDEFINED;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_param_set(in, in_end, &params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&params_t, KM_ORIGIN_IMPORTED, true);
	TEE_MemMove(&key_format, in, sizeof(key_format));
	in += TA_deserialize_key_format(in, in_end, &key_format, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &key_data, false, &res, false);
	if (res != KM_ERROR_OK)
		goto out;

	res = TA_parse_params(params_t, &algorithm, &key_size,
					&rsa_public_exponent, &digest, true);
	if (res != KM_ERROR_OK)
		goto out;
	if (key_format == KM_KEY_FORMAT_RAW) {
		if (algorithm != KM_ALGORITHM_AES &&
				algorithm != KM_ALGORITHM_HMAC) {
			EMSG("Only HMAC and AES keys can imported in raw fromat");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		}
		if (key_size == UNDEFINED)
			key_size = key_data.data_length * 8;
		if (algorithm == KM_ALGORITHM_HMAC) {
			res = TA_check_hmac_key_size(&key_data, digest);
			if (res != KM_ERROR_OK) {
				EMSG("HMAC key check failed");
				goto out;
			}
		}
		attrs_in_count = 1;
		attrs_in = TEE_Malloc(sizeof(TEE_Attribute) * attrs_in_count,
							TEE_MALLOC_FILL_ZERO);
		TEE_InitRefAttribute(attrs_in, TEE_ATTR_SECRET_VALUE,
				(void *) key_data.data, key_data.data_length);
		if (algorithm == KM_ALGORITHM_HMAC && (key_size % 8 != 0 ||
						key_size > MAX_KEY_HMAC ||
						key_size < MIN_KEY_HMAC)) {
			EMSG("HMAC key size must be multiple of 8 in range from %d to %d",
						MIN_KEY_HMAC, MAX_KEY_HMAC);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		} else if (algorithm == KM_ALGORITHM_AES &&
				key_size != 128 && key_size != 192
				&& key_size != 256) {
			EMSG("Unsupported key size! Supported only 128, 192 and 256");
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		}
	} else {/* KM_KEY_FORMAT_PKCS8 */
		if (algorithm != KM_ALGORITHM_RSA &&
				algorithm != KM_ALGORITHM_EC) {
			EMSG("Only RSA and EC keys can imported in PKCS8 fromat");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		}
		res = TA_decode_pkcs8(sessionSTA, key_data, &attrs_in,
				&attrs_in_count, algorithm, &key_size,
				&rsa_public_exponent);
		if (res != KM_ERROR_OK)
			goto out;
		if (algorithm == KM_ALGORITHM_RSA && (key_size % 8 != 0 ||
						key_size > MAX_KEY_RSA)) {
			EMSG("RSA key size must be multiple of 8 and less than %u",
								MAX_KEY_RSA);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		}
		if (algorithm == KM_ALGORITHM_EC) {
			curve = TA_get_curve_nist(key_size);
			if (curve == UNDEFINED) {
				EMSG("Failed to get ECC curve nist");
				res = KM_ERROR_UNSUPPORTED_EC_CURVE;
				goto out;
			}
			TEE_InitValueAttribute(
					attrs_in + attrs_in_count,
					TEE_ATTR_ECC_CURVE,
					curve,
					0);
			attrs_in_count++;
		} else { /* KM_ALGORITHM_RSA */
			if (key_size > MAX_KEY_RSA) {
				EMSG("RSA key size must be multiple of 8 and less than %u",
								MAX_KEY_RSA);
				return KM_ERROR_UNSUPPORTED_KEY_SIZE;
			}
		}
	}
	TA_add_to_params(&params_t, key_size, rsa_public_exponent);
	res = TA_fill_characteristics(&characts,
					&params_t, &characts_size);
	if (res != KM_ERROR_OK)
		goto out;
	padding = TA_get_key_size(algorithm);
	key_blob.key_material_size = characts_size + padding;
	if (key_blob.key_material_size % BLOCK_SIZE != 0) {
		/* size alignment */
		key_blob.key_material_size += BLOCK_SIZE -
			(key_blob.key_material_size % BLOCK_SIZE);
	}
	key_material = TEE_Malloc(key_blob.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	res = TA_import_key(algorithm, key_size, key_material, digest,
						attrs_in, attrs_in_count);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to import key");
		goto out;
	}
	TA_serialize_param_set(key_material + padding, &params_t);
	res = TA_encrypt(key_material, key_blob.key_material_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to encrypt blob");
		goto out;
	}
	key_blob.key_material = key_material;

	out += TA_serialize_key_blob(out, &key_blob);
	out += TA_serialize_characteristics(out, &characts);
out:
	TA_free_params(&params_t);
	if (key_data.data)
		TEE_Free(key_data.data);
	free_attrs(attrs_in, attrs_in_count);
	TA_free_params(&characts.sw_enforced);
	TA_free_params(&characts.hw_enforced);
	if (key_material)
		TEE_Free(key_material);
	return res;
}

static keymaster_error_t TA_Export_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_key_format_t export_format = UNDEFINED;	/* IN */
	keymaster_key_blob_t key_to_export = EMPTY_KEY_BLOB;	/* IN */
	keymaster_blob_t client_id = EMPTY_BLOB;	/* IN */
	keymaster_blob_t app_data = EMPTY_BLOB;		/* IN */
	keymaster_blob_t export_data = EMPTY_BLOB;	/* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool exportable = false;
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t type = 0;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_key_format(in, in_end, &export_format, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_blob(in, in_end, &key_to_export, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &client_id, true, &res, false);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &app_data, true, &res, false);
	if (res != KM_ERROR_OK)
		goto out;

	if (export_format != KM_KEY_FORMAT_X509) {
		EMSG("Unsupported key export format");
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		goto out;
	}
	key_material = TEE_Malloc(key_to_export.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	res = TA_restore_key(key_material, &key_to_export, &key_size, &type,
						 &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	res = TA_check_permission(&params_t, client_id, app_data, &exportable);
	if (res != KM_ERROR_OK)
		goto out;
	if (!exportable && type != TEE_TYPE_RSA_KEYPAIR
			&& type != TEE_TYPE_ECDSA_KEYPAIR) {
		res = KM_ERROR_KEY_EXPORT_OPTIONS_INVALID;
		EMSG("This asymetric key is not exportable");
		goto out;
	}
	res = TA_encode_key(sessionSTA, &export_data, type, &obj_h, key_size);
	if (res != KM_ERROR_OK)
		goto out;
	out += TA_serialize_blob(out, &export_data);
out:
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (key_to_export.key_material)
		TEE_Free(key_to_export.key_material);
	if (key_material)
		TEE_Free(key_material);
	if (export_data.data)
		TEE_Free(export_data.data);
	TA_free_params(&params_t);
	return TEE_SUCCESS;
}

static keymaster_error_t TA_Attest_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_key_blob_t key_to_attest = EMPTY_KEY_BLOB;/* IN */
	keymaster_key_param_set_t attest_params = EMPTY_PARAM_SET;/* IN */
	keymaster_cert_chain_t cert_chain = EMPTY_CERT_CHAIN;/* OUT */
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_key_blob(in, in_end, &key_to_attest, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_param_set(in, in_end, &attest_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&attest_params, KM_ORIGIN_UNKNOWN, false);

	/* TODO Attest key */

	out += TA_serialize_cert_chain(out, &cert_chain, &res);
	if (res != KM_ERROR_OK)
		goto out;
out:
	TA_free_params(&attest_params);
	if (key_to_attest.key_material)
		TEE_Free(key_to_attest.key_material);
	return res;
}

static keymaster_error_t TA_Upgrade_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_key_blob_t key_to_upgrade = EMPTY_KEY_BLOB;/* IN */
	keymaster_key_param_set_t upgr_params = EMPTY_PARAM_SET;/* IN */
	keymaster_key_blob_t upgraded_key = EMPTY_KEY_BLOB;/* OUT */
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_key_blob(in, in_end, &key_to_upgrade, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_param_set(in, in_end, &upgr_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&upgr_params, KM_ORIGIN_UNKNOWN, false);

	/* TODO Upgrade Key */

	out += TA_serialize_key_blob(out, &upgraded_key);
out:
	TA_free_params(&upgr_params);
	if (key_to_upgrade.key_material)
		TEE_Free(key_to_upgrade.key_material);
	return res;
}

static keymaster_error_t TA_Delete_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	keymaster_key_blob_t key = EMPTY_KEY_BLOB;		/* IN */
	keymaster_error_t res = KM_ERROR_OK;

	/* TODO Delete Key */

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;

	in += TA_deserialize_key_blob(in, in_end, &key, &res);

	if (key.key_material)
		TEE_Free(key.key_material);
	return res;
}

static keymaster_error_t TA_Delete_all_keys(TEE_Param params[TEE_NUM_PARAMS])
{
	(void)&params[0];
	/* TODO Delete all keys */
	return KM_ERROR_OK;
}

static keymaster_error_t TA_Begin(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *key_material = NULL;
	uint8_t *secretIV = NULL;
	uint32_t mac_length = UNDEFINED;
	uint32_t key_size = 0;
	uint32_t IVsize = UNDEFINED;
	uint32_t min_sec = UNDEFINED;
	uint32_t type = 0;
	bool do_auth = false;
	keymaster_purpose_t purpose = UNDEFINED;		/* IN */
	keymaster_key_blob_t key = EMPTY_KEY_BLOB;		/* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET;	/* IN */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET;	/* OUT */
	keymaster_operation_handle_t operation_handle = 0;	/* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_key_param_t nonce_param;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_algorithm_t algorithm = UNDEFINED;
	keymaster_blob_t nonce = EMPTY_BLOB;
	keymaster_digest_t digest = UNDEFINED;
	keymaster_block_mode_t mode = UNDEFINED;
	keymaster_padding_t padding = UNDEFINED;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	TEE_OperationHandle *operation = TEE_HANDLE_NULL;
	TEE_OperationHandle *digest_op = TEE_HANDLE_NULL;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	/* Freed when operation is aborted (TA_abort_operation) */
	operation = TEE_Malloc(sizeof(TEE_OperationHandle),
					TEE_MALLOC_FILL_ZERO);
	if (!operation) {
		EMSG("Failed to allocate memory for operation");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	/* Freed when operation is aborted (TA_abort_operation) */
	digest_op = TEE_Malloc(sizeof(TEE_OperationHandle),
					TEE_MALLOC_FILL_ZERO);
	if (!digest_op) {
		EMSG("Failed to allocate memory for digest operation");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	*operation = TEE_HANDLE_NULL;
	*digest_op = TEE_HANDLE_NULL;

	in += TA_deserialize_purpose(in, in_end, &purpose, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_blob(in, in_end, &key, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_param_set(in, in_end, &in_params, true, &res);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(key.key_material_size, TEE_MALLOC_FILL_ZERO);
	res = TA_restore_key(key_material, &key, &key_size,
						 &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	switch (type) {
	case TEE_TYPE_AES:
		algorithm = KM_ALGORITHM_AES;
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		algorithm = KM_ALGORITHM_RSA;
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		algorithm = KM_ALGORITHM_EC;
		break;
	default:/* HMAC */
		algorithm = KM_ALGORITHM_HMAC;
	}
	res = TA_check_params(&key, &params_t, &in_params,
				&algorithm, purpose, &digest, &mode,
				&padding, &mac_length, &nonce,
				&min_sec, &do_auth);
	if (res != KM_ERROR_OK)
		goto out;
	if (algorithm == KM_ALGORITHM_AES && mode !=
		    KM_MODE_ECB && nonce.data_length == 0) {
		if (mode == KM_MODE_CBC || mode == KM_MODE_CTR) {
			IVsize = 16;
		} else {/* GCM mode */
			IVsize = 12;
		}
		out_params.length = 1;
		secretIV = TEE_Malloc(IVsize, TEE_MALLOC_FILL_ZERO);
		TEE_GenerateRandom(secretIV, IVsize);
		nonce_param.tag = KM_TAG_NONCE;
		nonce_param.key_param.blob.data = secretIV;
		nonce_param.key_param.blob.data_length = IVsize;
		out_params.params = &nonce_param;
		nonce.data_length = IVsize;
		nonce.data = secretIV;
	}

	res = TA_create_operation(operation, obj_h, purpose,
				algorithm, key_size, nonce,
				digest, mode, padding, mac_length);
	if (res != KM_ERROR_OK)
		goto out;

	TEE_GenerateRandom(&operation_handle, sizeof(operation_handle));
	if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY ||
			(algorithm == KM_ALGORITHM_RSA &&
			padding == KM_PAD_RSA_PSS)) {
		res = TA_create_digest_op(digest_op, digest);
		if (res != KM_ERROR_OK)
			goto out;
	}
	res = TA_start_operation(operation_handle, key, min_sec,
					operation, purpose, digest_op, do_auth,
					padding, mode, mac_length, nonce);
	if (res != KM_ERROR_OK)
		goto out;
	out += TA_serialize_param_set(out, &out_params);
	TEE_MemMove(out, &operation_handle, sizeof(operation_handle));
out:
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (secretIV)
		TEE_Free(secretIV);
	if (key.key_material)
		TEE_Free(key.key_material);
	if (res != KM_ERROR_OK) {
		if (*digest_op != TEE_HANDLE_NULL)
			TEE_FreeOperation(*digest_op);
		if (*operation != TEE_HANDLE_NULL)
			TEE_FreeOperation(*operation);
		TEE_Free(operation);
		TEE_Free(digest_op);
	}
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&in_params);
	TA_free_params(&params_t);
	TA_free_params(&out_params);
	return res;
}

static keymaster_error_t TA_Update(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_operation_handle_t operation_handle = 0;		/* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET;	/* IN */
	keymaster_blob_t input = EMPTY_BLOB;	/* IN */
	size_t input_consumed = 0;	/* OUT */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET;	/* OUT */
	keymaster_blob_t output = EMPTY_BLOB;	/* OUT */
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t type = 0;
	uint32_t out_size = 0;
	uint32_t input_provided = 0;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_operation_t operation = EMPTY_OPERATION;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool is_input_ext = false;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_param_set(in, in_end, &in_params, true, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &input, false, &res, true);
	if (res != KM_ERROR_OK)
		goto out;

	input_provided = input.data_length;
	res = TA_get_operation(operation_handle, &operation);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(operation.key->key_material_size,
						TEE_MALLOC_FILL_ZERO);
	res = TA_restore_key(key_material, operation.key, &key_size,
						 &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t);
		if (res != KM_ERROR_OK) {
			EMSG("Authentication failed");
			goto out;
		}
	}

	if (input.data_length != 0)
		operation.got_input = true;
	out_size = TA_possibe_size(type, key_size, input, 0);
	output.data = TEE_Malloc(out_size, TEE_MALLOC_FILL_ZERO);
	if (!output.data) {
		EMSG("Failed to allocate memory for output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	switch (type) {
	case TEE_TYPE_AES:
		res = TA_aes_update(&operation, &input, &output, &out_size,
					input_provided, &input_consumed,
					&in_params, &is_input_ext);
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_update(&operation, &input, &output, &out_size,
					key_size, &input_consumed,
					input_provided, obj_h);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		res = TA_ec_update(&operation, &input, &output,
					&input_consumed, input_provided);
		break;
	default:/* HMAC */
		TEE_MACUpdate(*operation.operation,
			input.data, input.data_length);
		input_consumed = input_provided;
	}
	if (res != KM_ERROR_OK) {
		EMSG("Update operation failed with error code %x", res);
		goto out;
	}

	TEE_MemMove(out, &input_consumed, sizeof(input_consumed));
	out += SIZE_LENGTH;
	out += TA_serialize_blob(out, &output);
	out += TA_serialize_param_set(out, &out_params);
	TA_update_operation(operation_handle, &operation);
out:
	if (input.data && is_input_ext)
		TEE_Free(input.data);
	if (output.data)
		TEE_Free(output.data);
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_material)
		TEE_Free(key_material);
	if (res != KM_ERROR_OK)
		TA_abort_operation(operation_handle);
	TA_free_params(&params_t);
	TA_free_params(&in_params);
	TA_free_params(&out_params);
	return res;
}

static keymaster_error_t TA_Finish(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_operation_handle_t operation_handle = 0;		/* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET;	/* IN */
	keymaster_blob_t input = EMPTY_BLOB;		/* IN */
	keymaster_blob_t signature = EMPTY_BLOB;		/* IN */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET;/* OUT */
	keymaster_blob_t output = EMPTY_BLOB;		/* OUT */
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t type = 0;
	uint32_t out_size = 0;
	uint32_t tag_len = 0;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_operation_t operation = EMPTY_OPERATION;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool is_input_ext = false;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_param_set(in, in_end, &in_params, true, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &input, true, &res, true);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob(in, in_end, &signature, true, &res, false);
	if (res != KM_ERROR_OK)
		goto out;

	res = TA_get_operation(operation_handle, &operation);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(operation.key->key_material_size,
					TEE_MALLOC_FILL_ZERO);
	res = TA_restore_key(key_material, operation.key, &key_size, &type,
						 &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t);
		if (res != KM_ERROR_OK) {
			EMSG("Authentication failed");
			goto out;
		}
	}
	if (type == TEE_TYPE_AES && operation.mode == KM_MODE_GCM)
		tag_len = operation.mac_length / 8;/* from bits to bytes */

	out_size = TA_possibe_size(type, key_size, input, tag_len);
	output.data = TEE_Malloc(out_size, TEE_MALLOC_FILL_ZERO);
	if (!output.data) {
		EMSG("Failed to allocate memory for output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	switch (type) {
	case TEE_TYPE_AES:
		res = TA_aes_finish(&operation, &input, &output, &out_size,
					tag_len, &is_input_ext);
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_finish(&operation, &input, &output, &out_size,
				key_size, signature, obj_h, &is_input_ext);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		res = TA_ec_finish(&operation, &input, &output, &signature,
					&out_size, key_size,
					&sessionSTA, &is_input_ext);
		break;
	default: /* HMAC */
		if (operation.purpose == KM_PURPOSE_SIGN) {
			TEE_MACComputeFinal(*operation.operation,
						input.data,
						input.data_length,
						output.data,
						&out_size);
		} else {/* KM_PURPOSE_VERIFY */
			res = TEE_MACCompareFinal(*operation.operation,
						input.data,
						input.data_length,
						signature.data,
						signature.data_length);
			/* Convert error code to Android style */
			if (res == (int) TEE_ERROR_MAC_INVALID)
				res = KM_ERROR_VERIFICATION_FAILED;
		}
	}
	if (res != TEE_SUCCESS) {
		EMSG("Operation failed with error code %x", res);
		goto out;
	}
	output.data_length = out_size;

	out += TA_serialize_param_set(out, &out_params);
	out += TA_serialize_blob(out, &output);
out:
	TA_abort_operation(operation_handle);
	if (input.data && is_input_ext)
		TEE_Free(input.data);
	if (output.data)
		TEE_Free(output.data);
	if (signature.data)
		TEE_Free(signature.data);
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&params_t);
	TA_free_params(&in_params);
	TA_free_params(&out_params);
	return res;
}

static keymaster_error_t TA_Abort(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	keymaster_error_t res=  KM_ERROR_OK;
	keymaster_operation_handle_t operation_handle = 0;		/* IN */

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_abort_operation(operation_handle);
out:
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
			uint32_t cmd_id, uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		EMSG("Wrong parameters");
		return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
	}
	if (cmd_id != KM_CONFIGURE && !config_success) {
		EMSG("Keystore was not configured!");
		return KM_ERROR_KEYMASTER_NOT_CONFIGURED;
	}
	switch(cmd_id) {
	case KM_CONFIGURE:
		return TA_Configure(params);
	case KM_ADD_RNG_ENTROPY:
		return TA_Add_rng_entropy(params);
	case KM_GENERATE_KEY:
		return TA_Generate_key(params);
	case KM_GET_KEY_CHARACTERISTICS:
		return TA_Get_key_characteristics(params);
	case KM_IMPORT_KEY:
		return TA_Import_key(params);
	case KM_EXPORT_KEY:
		return TA_Export_key(params);
	case KM_ATTEST_KEY:
		return TA_Attest_key(params);
	case KM_UPGRADE_KEY:
		return TA_Upgrade_key(params);
	case KM_DELETE_KEY:
		return TA_Delete_key(params);
	case KM_DELETE_ALL_KEYS:
		return TA_Delete_all_keys(params);
	case KM_BEGIN:
		return TA_Begin(params);
	case KM_UPDATE:
		return TA_Update(params);
	case KM_FINISH:
		return TA_Finish(params);
	case KM_ABORT:
		return TA_Abort(params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
