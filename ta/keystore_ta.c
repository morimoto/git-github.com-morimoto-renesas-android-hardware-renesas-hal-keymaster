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

#include "common.h"
#include "ta_ca_defs.h"

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{

}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[TEE_NUM_PARAMS], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
}

/*
	Deserializers
*/
static int TA_deserialize_param_set(uint8_t* in, keymaster_key_param_set_t* params_t)
{
	memcpy(&params_t->length, in, sizeof(size_t));
	in += sizeof(size_t);
	params_t->params = (keymaster_key_param_t*) malloc(sizeof(keymaster_key_param_t) * params_t->length);
	for (size_t i = 0; i < params_t->length; i++) {
		memcpy(params_t->params + i, in, sizeof(keymaster_key_param_t));
		in += sizeof(keymaster_key_param_t);
	}
	return sizeof(keymaster_key_param_t) * params_t->length + sizeof(size_t);
}

static int TA_deserialize_blob(uint8_t* in, keymaster_blob_t* blob_t)
{
	uint8_t* data;
	memcpy(&blob_t->data_length, in, sizeof(size_t));
	in += sizeof(size_t);
	data = (uint8_t*) malloc(blob_t->data_length * sizeof(uint8_t));
	for (size_t i = 0; i < blob_t->data_length; i++) {
		memcpy(data + i, in, sizeof(uint8_t));
		in += sizeof(uint8_t);
	}
	blob_t->data = data;
	return sizeof(size_t) + sizeof(uint8_t) * blob_t->data_length;
}

static int TA_deserialize_key_blob(uint8_t* in, keymaster_key_blob_t* key_blob)
{
	uint8_t* key_material;
	memcpy(&key_blob->key_material_size, in, sizeof(size_t));
	in += sizeof(size_t);
	key_material = (uint8_t*) malloc(key_blob->key_material_size * sizeof(uint8_t));
	for (size_t i = 0; i < key_blob->key_material_size; i++) {
		memcpy(key_material + i, in, sizeof(uint8_t));
		in += sizeof(uint8_t);
	}
	key_blob->key_material = key_material;
	return sizeof(size_t) + sizeof(uint8_t) * key_blob->key_material_size;
}

/*
	Serializers
*/
static int TA_serialize_characteristics(uint8_t* out, keymaster_key_characteristics_t* characteristics)
{
	characteristics->hw_enforced.params = (keymaster_key_param_t*) malloc(sizeof(keymaster_key_param_t) * characteristics->hw_enforced.length);//
	characteristics->sw_enforced.params = (keymaster_key_param_t*) malloc(sizeof(keymaster_key_param_t) * characteristics->sw_enforced.length);//
	memcpy(out, &characteristics->hw_enforced.length, sizeof(size_t));
	out += sizeof(size_t);
	for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
		memcpy(out, characteristics->hw_enforced.params + i, sizeof(keymaster_key_param_t));
		out += sizeof(keymaster_key_param_t);
	}
	memcpy(out, &characteristics->sw_enforced.length, sizeof(size_t));
	out += sizeof(size_t);
	for (size_t i = 0; i < characteristics->sw_enforced.length; i++) {
		memcpy(out, characteristics->sw_enforced.params + i, sizeof(keymaster_key_param_t));
		out += sizeof(keymaster_key_param_t);
	}
	return 2 * sizeof(size_t) + characteristics->hw_enforced.length * sizeof(keymaster_key_param_t) + characteristics->sw_enforced.length * sizeof(keymaster_key_param_t);
}

static int TA_serialize_key_blob(uint8_t* out, keymaster_key_blob_t* key_blob)
{
	key_blob->key_material = (uint8_t*) malloc(sizeof(uint8_t) * key_blob->key_material_size);
	memcpy(out, &key_blob->key_material_size, sizeof(size_t));
	out += sizeof(size_t);
	for (size_t i = 0; i < key_blob->key_material_size; i++) {
		memcpy(out, key_blob->key_material + i, sizeof(uint8_t));
		out += sizeof(uint8_t);
	}
	return sizeof(size_t) + key_blob->key_material_size * sizeof(uint8_t);
}

static int TA_serialize_blob(uint8_t* out, keymaster_blob_t* export_data)
{
	export_data->data = (uint8_t*) malloc(sizeof(uint8_t) * export_data->data_length);
	memcpy(out, &export_data->data_length, sizeof(size_t));
	out += sizeof(size_t);
	for (size_t i = 0; i < export_data->data_length; i++) {
		memcpy(out, export_data->data + i, sizeof(uint8_t));
		out += sizeof(uint8_t);
	}
	return sizeof(size_t) + export_data->data_length * sizeof(uint8_t);
}

static int TA_serialize_cert_chain(uint8_t* out, keymaster_cert_chain_t* cert_chain)
{
	int total_size = 0;
	cert_chain->entries = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t) * cert_chain->entry_count);
	memcpy(out, &cert_chain->entry_count, sizeof(size_t));
	out += sizeof(size_t);
	total_size += sizeof(size_t);
	for (size_t i = 0; i < cert_chain->entry_count; i++) {
		memcpy(out, &(cert_chain->entries + i)->data_length, sizeof(size_t));
		out += sizeof(size_t);
		total_size += sizeof(size_t);
		(cert_chain->entries + i)->data = (uint8_t*) malloc((cert_chain->entries + i)->data_length * sizeof(uint8_t));
		for (size_t j = 0; j < (cert_chain->entries + i)->data_length; j++) {
			memcpy(out, (cert_chain->entries + i)->data + j, sizeof(uint8_t));
			out += sizeof(uint8_t);
			total_size += sizeof(uint8_t);
		}
	}
	return total_size;
}

static int TA_serialize_param_set(uint8_t* out, keymaster_key_param_set_t* params)
{
	memcpy(out, &params->length, sizeof(size_t));
	out += sizeof(size_t);
	for (size_t i = 0; i < params->length; i++) {
		memcpy(out, params->params + i, sizeof(keymaster_key_param_t));
		out += sizeof(keymaster_key_param_t);
	}
	return sizeof(size_t) + params->length * sizeof(keymaster_key_param_t);
}

static int TA_Configure(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	keymaster_key_param_set_t* params_t;	//IN
	in = (uint8_t*) params[0].memref.buffer;

	params_t = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, params_t);

	//TODO CONFIGURE

	free(params_t);

	return TEE_SUCCESS;
}

static int TA_Add_rng_entropy(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	size_t i = 0;
	uint8_t* data;			//IN
	size_t data_length;		//IN
	in = (uint8_t*) params[0].memref.buffer;

	memcpy(&data_length, in, sizeof(size_t));
	in += sizeof(size_t);
	data = (uint8_t*) malloc(data_length * sizeof(uint8_t));
	while(i < data_length) {
		memcpy(data + i, in, sizeof(uint8_t));
		in += sizeof(uint8_t);
		i++;
	}
	free(data);
	return TEE_SUCCESS;
}

static int TA_Generate_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_key_param_set_t* params_t;				//IN
	keymaster_key_blob_t* key_blob;						//OUT
	keymaster_key_characteristics_t* characteristics;	//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	params_t = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, params_t);

	//TODO Generate Key

	key_blob = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	characteristics = (keymaster_key_characteristics_t*) malloc(sizeof(keymaster_key_characteristics_t));
	out += TA_serialize_key_blob(out, key_blob);
	out += TA_serialize_characteristics(out, characteristics);
	free(params_t);
	free(key_blob);
	free(characteristics);
	return TEE_SUCCESS;
}

static int TA_Get_key_characteristics(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_key_blob_t* key_blob;			//IN
	keymaster_blob_t* client_id;			//IN
	keymaster_blob_t* app_data;				//IN
	keymaster_key_characteristics_t* chr;	//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	key_blob = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	in += TA_deserialize_key_blob(in, key_blob);
	client_id = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, client_id);
	app_data = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, app_data);

	//TODO Get Key Characteristics

	chr = (keymaster_key_characteristics_t*) malloc(sizeof(keymaster_key_characteristics_t));
	out += TA_serialize_characteristics(out, chr);
	free(key_blob);
	free(client_id);
	free(app_data);
	free(chr);
	return TEE_SUCCESS;
}

static int TA_Import_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_key_param_set_t* params_t;				//IN
	keymaster_key_format_t key_format;					//IN
	keymaster_blob_t* key_data;							//IN
	keymaster_key_blob_t* key_blob;						//OUT
	keymaster_key_characteristics_t* characteristics;	//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	params_t = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, params_t);
	memcpy(&key_format, in, sizeof(keymaster_key_format_t));
	in += sizeof(keymaster_key_format_t);
	key_data = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, key_data);

	//TODO Import Key

	key_blob = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	characteristics = (keymaster_key_characteristics_t*) malloc(sizeof(keymaster_key_characteristics_t));
	out += TA_serialize_key_blob(out, key_blob);
	out += TA_serialize_characteristics(out, characteristics);
	free(params_t);
	free(key_data);
	free(key_blob);
	free(characteristics);
	return TEE_SUCCESS;
}

static int TA_Export_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_key_format_t export_format;	//IN
	keymaster_key_blob_t* key_to_export;	//IN
	keymaster_blob_t* client_id;			//IN
	keymaster_blob_t* app_data;				//IN
	keymaster_blob_t* export_data;			//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	memcpy(&export_format, in, sizeof(keymaster_key_format_t));
	in += sizeof(keymaster_key_format_t);
	key_to_export = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	in += TA_deserialize_key_blob(in, key_to_export);
	client_id = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, client_id);
	app_data = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, app_data);

	//TODO Export key
	export_data = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	out += TA_serialize_blob(out, export_data);
	free(key_to_export);
	free(client_id);
	free(app_data);
	free(export_data);
	return TEE_SUCCESS;
}

static int TA_Attest_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_key_blob_t* key_to_attest;			//IN
	keymaster_key_param_set_t* attest_params;		//IN
	keymaster_cert_chain_t* cert_chain;				//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	key_to_attest = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	in += TA_deserialize_key_blob(in, key_to_attest);
	attest_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, attest_params);

	cert_chain = (keymaster_cert_chain_t*) malloc(sizeof(keymaster_cert_chain_t));
	out += TA_serialize_cert_chain(out, cert_chain);
	free(key_to_attest);
	free(attest_params);
	free(cert_chain);
	return TEE_SUCCESS;
}

static int TA_Upgrade_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_key_blob_t* key_to_upgrade;			//IN
	keymaster_key_param_set_t* upgrade_params;		//IN
	keymaster_key_blob_t* upgraded_key;				//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	key_to_upgrade = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	in += TA_deserialize_key_blob(in, key_to_upgrade);
	upgrade_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, upgrade_params);

	//TODO Upgrade Key

	upgraded_key = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	out += TA_serialize_key_blob(out, upgraded_key);
	free(key_to_upgrade);
	free(upgrade_params);
	free(upgraded_key);
	return TEE_SUCCESS;
}

static int TA_Delete_key(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	keymaster_key_blob_t* key;			//IN
	in = (uint8_t*) params[0].memref.buffer;
	key = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	in += TA_deserialize_key_blob(in, key);
	free(key);
	return TEE_SUCCESS;
}

static int TA_Delete_all_keys(TEE_Param params[TEE_NUM_PARAMS])
{
	(void)&params[0];
	//TODO Delete all keys
	return TEE_SUCCESS;
}

static int TA_Begin(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_purpose_t purpose;						//IN
	keymaster_key_blob_t* key;							//IN
	keymaster_key_param_set_t* in_params;				//IN
	keymaster_key_param_set_t* out_params;				//OUT
	keymaster_operation_handle_t* operation_handle;		//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	memcpy(&purpose, in, sizeof(keymaster_purpose_t));
	in += sizeof(keymaster_purpose_t);
	key = (keymaster_key_blob_t*) malloc(sizeof(keymaster_key_blob_t));
	in += TA_deserialize_key_blob(in, key);
	in_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, in_params);

	//TODO Begin

	out_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	out += TA_serialize_param_set(out, out_params);
	operation_handle = (keymaster_operation_handle_t*) malloc(sizeof(keymaster_operation_handle_t));
	memcpy(out, operation_handle, sizeof(keymaster_operation_handle_t));

	free(key);
	free(in_params);
	free(out_params);
	free(operation_handle);
	return TEE_SUCCESS;
}

static int TA_Update(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_operation_handle_t operation_handle;		//IN
	keymaster_key_param_set_t* in_params;				//IN
	keymaster_blob_t* input;							//IN
	size_t* input_consumed;								//OUT
	keymaster_key_param_set_t* out_params;				//OUT
	keymaster_blob_t* output;							//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	memcpy(&operation_handle, in, sizeof(keymaster_operation_handle_t));
	in += sizeof(keymaster_operation_handle_t);
	in_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, in_params);
	input = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, input);

	//TODO Update

	input_consumed = (size_t*) malloc(sizeof(size_t));
	memcpy(out, input_consumed, sizeof(size_t));
	out += sizeof(size_t);
	out_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	out += TA_serialize_param_set(out, out_params);
	output = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	out += TA_serialize_blob(out, output);

	free(in_params);
	free(input);
	free(input_consumed);
	free(out_params);
	free(output);
	return TEE_SUCCESS;
}

static int TA_Finish(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	uint8_t* out;
	keymaster_operation_handle_t operation_handle;		//IN
	keymaster_key_param_set_t* in_params;				//IN
	keymaster_blob_t* input;							//IN
	keymaster_blob_t* signature;						//IN
	keymaster_key_param_set_t* out_params;				//OUT
	keymaster_blob_t* output;							//OUT
	in = (uint8_t*) params[0].memref.buffer;
	out = (uint8_t*) params[1].memref.buffer;

	memcpy(&operation_handle, in, sizeof(keymaster_operation_handle_t));
	in += sizeof(keymaster_operation_handle_t);
	in_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	in += TA_deserialize_param_set(in, in_params);
	input = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, input);
	signature = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	in += TA_deserialize_blob(in, signature);

	//TODO Finish

	out_params = (keymaster_key_param_set_t*) malloc(sizeof(keymaster_key_param_set_t));
	out += TA_serialize_param_set(out, out_params);
	output = (keymaster_blob_t*) malloc(sizeof(keymaster_blob_t));
	out += TA_serialize_blob(out, output);
	free(in_params);
	free(input);
	free(signature);
	free(out_params);
	free(output);
	return TEE_SUCCESS;
}

static int TA_Abort(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t* in;
	keymaster_operation_handle_t operation_handle;		//IN
	in = (uint8_t*) params[0].memref.buffer;
	memcpy(&operation_handle, in, sizeof(keymaster_operation_handle_t));
	//TODO abort
	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		DMSG("Wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	switch(cmd_id) {
		case KM_CONFIGURE :
			TA_Configure(params);
			break;
		case KM_ADD_RNG_ENTROPY :
			TA_Add_rng_entropy(params);
			break;
		case KM_GENERATE_KEY :
			TA_Generate_key(params);
			break;
		case KM_GET_KEY_CHARACTERISTICS :
			TA_Get_key_characteristics(params);
			break;
		case KM_IMPORT_KEY :
			TA_Import_key(params);
			break;
		case KM_EXPORT_KEY :
			TA_Export_key(params);
			break;
		case KM_ATTEST_KEY :
			TA_Attest_key(params);
			break;
		case KM_UPGRADE_KEY :
			TA_Upgrade_key(params);
			break;
		case KM_DELETE_KEY :
			TA_Delete_key(params);
			break;
		case KM_DELETE_ALL_KEYS :
			TA_Delete_all_keys(params);
			break;
		case KM_BEGIN :
			TA_Begin(params);
			break;
		case KM_UPDATE :
			TA_Update(params);
			break;
		case KM_FINISH :
			TA_Finish(params);
			break;
		case KM_ABORT :
			TA_Abort(params);
			break;
		default :
			return TEE_ERROR_BAD_PARAMETERS;
	}
	(void)&sess_ctx; /* Unused parameter */
	return TEE_SUCCESS;
}
