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

#include "crypto_ec.h"


keymaster_error_t TA_ec_update(keymaster_operation_t *operation,
				const keymaster_blob_t *input,
				keymaster_blob_t *output,
				size_t *input_consumed,
				const uint32_t input_provided)
{
	keymaster_error_t res = KM_ERROR_OK;

	switch (operation->purpose) {
	case KM_PURPOSE_VERIFY:
	case KM_PURPOSE_SIGN:
		if (*operation->digest_op != TEE_HANDLE_NULL) {
			TEE_DigestUpdate(*operation->digest_op, input->data,
							input->data_length);
		} else {
			/* if digest is not specified save all
			 * blocks to use it in finish
			 */
			res = TA_store_sf_data(input, operation);
		}
		*input_consumed = input_provided;
		output->data_length = 0;
		break;
	default:
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
	}
	return res;
}

keymaster_error_t TA_ec_finish(const keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				keymaster_blob_t *signature,
				uint32_t *out_size,
				const uint32_t key_size,
				bool *is_input_ext)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t digest_out_size = KM_MAX_DIGEST_SIZE;
	uint8_t digest_out[KM_MAX_DIGEST_SIZE];
	uint8_t *in_buf = NULL;
	uint32_t in_buf_l = 0;
	bool clear_in_buf = false;

	switch (operation->purpose) {
	case KM_PURPOSE_VERIFY:
	case KM_PURPOSE_SIGN:
		if (*operation->digest_op != TEE_HANDLE_NULL) {
			res = TEE_DigestDoFinal(*operation->digest_op,
					input->data,
					input->data_length,
					digest_out,
					&digest_out_size);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to obtain digest for EC, res=%x", res);
				break;
			}
			in_buf = digest_out;
			in_buf_l = digest_out_size;
		} else {
			res = TA_append_sf_data(input, operation, is_input_ext);
			if (res != KM_ERROR_OK)
				break;
			/* Output size wount change ahen
			 * stored data is appended
			 */
			in_buf = input->data;
			in_buf_l = input->data_length;
		}
		if (operation->purpose == KM_PURPOSE_SIGN) {
			res = TEE_AsymmetricSignDigest(*operation->operation,
							NULL, 0, in_buf,
							in_buf_l, output->data,
							out_size);
			if (res == TEE_SUCCESS && *out_size > 0) {
				EMSG("Failed to sign data, res=0x%x", res);
			}
		} else {
			*out_size = 0;
			res = TEE_AsymmetricVerifyDigest(*operation->operation,
							NULL, 0, in_buf,
							in_buf_l,
							signature->data,
							signature->data_length);
			/* Convert error code to Android style */
			if (res == (int) TEE_ERROR_SIGNATURE_INVALID)
				res = KM_ERROR_VERIFICATION_FAILED;
		}
		break;
	default:
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
	}
	if (in_buf && clear_in_buf)
		TEE_Free(in_buf);
	return res;
}
