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

#include "paddings.h"

bool TA_check_pkcs7_pad(keymaster_blob_t *output, const bool aligned)
{
	uint32_t last_i;
	uint8_t pad;

	if (output->data == NULL || output->data_length == 0 ||
			output->data_length < BLOCK_SIZE ||
			output->data_length % BLOCK_SIZE != 0)
		return false;
	last_i = output->data_length - 1;
	pad = output->data[last_i];
	if (pad > BLOCK_SIZE || pad > output->data_length)
		return false;
	for (uint32_t i = 0; i < pad; i++) {
		if (output->data[last_i - i] != pad)
			return false;
	}
	if (aligned && pad != BLOCK_SIZE)
		return false;
	return true;
}

keymaster_error_t TA_do_pkcs7_pad(keymaster_blob_t *input,
				const keymaster_action_t action,
				keymaster_blob_t *output,
				uint32_t *out_size, const bool force)
{
	uint32_t pad = 0;
	uint8_t *data;
	keymaster_error_t res = KM_ERROR_OK;

	switch (action) {
	case KM_ADD:
		if (input->data_length == 0 && !force)
			return KM_ERROR_OK;
		pad = BLOCK_SIZE - (input->data_length % BLOCK_SIZE);
		DMSG("PKCS7 ADD pad = %x", pad);
		/* if input data size is a multiple of block size add
		 * one extra block as padding
		 */
		if (pad == 0)
			pad = BLOCK_SIZE;
		/* Freed before input blob is destroyed by caller */
		data = TEE_Malloc(pad + input->data_length,
							TEE_MALLOC_FILL_ZERO);
		if (!data) {
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			EMSG("Failed to allocate memory for buffer on padding adding");
			break;
		}
		TEE_MemMove(data, input->data, input->data_length);
		TEE_MemFill(data + input->data_length, pad, pad);
		TEE_Free(input->data);
		input->data = data;
		input->data_length = input->data_length + pad;

		*out_size = 2 * input->data_length;
		/* Freed before output blob is destroyed by caller */
		data = TEE_Malloc(*out_size, TEE_MALLOC_FILL_ZERO);
		if (!data) {
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			EMSG("Failed to allocate memory for output buffer on padding adding");
			break;
		}
		TEE_Free(output->data);
		output->data = data;
		break;
	default:/* KM_REMOVE */
		if (output->data_length == 0)
			return KM_ERROR_OK;
		pad = output->data[output->data_length - 1];
		DMSG("PKCS7 REMOVE pad = %x", pad);
		if (!TA_check_pkcs7_pad(output, false)) {
			EMSG("Failed to read PKCS7 padding");
			res = KM_ERROR_INVALID_ARGUMENT;
			break;
		}
		/* Freed before output blob is destroyed by caller */
		data = TEE_Malloc(output->data_length - pad,
						TEE_MALLOC_FILL_ZERO);
		if (!data) {
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			EMSG("Failed to allocate memory for buffer on padding adding");
			break;
		}
		TEE_MemMove(data, output->data, output->data_length - pad);
		TEE_Free(output->data);
		output->data = data;
		output->data_length = output->data_length - pad;
		*out_size = output->data_length;
		break;
	}
	return res;
}

keymaster_error_t TA_do_rsa_pad(uint8_t **input, uint32_t *input_l,
				const uint32_t key_size,
				keymaster_blob_t *output, uint32_t *out_size)
{
	uint8_t *buf;
	uint32_t key_size_bytes = key_size / 8;

	/* Freed before input blob is destroyed by caller */
	buf = TEE_Malloc(key_size_bytes, TEE_MALLOC_FILL_ZERO);
	if (!buf) {
		EMSG("Failed to allocate memory for buffer on adding RSA padding");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(buf + key_size_bytes - *input_l,
				*input, *input_l);
	TEE_Free(*input);
	*input = buf;
	*input_l = key_size_bytes;
	if (output == NULL)
		return KM_ERROR_OK;
	TEE_Free(output->data);
	output->data_length = 2 * *input_l;
	/* Freed before output blob is destroyed by caller */
	output->data = TEE_Malloc(output->data_length, TEE_MALLOC_FILL_ZERO);
	if (!output->data) {
		EMSG("Failed to allocate memory for ne RSA output");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	*out_size = (uint32_t) output->data_length;
	return KM_ERROR_OK;
}
