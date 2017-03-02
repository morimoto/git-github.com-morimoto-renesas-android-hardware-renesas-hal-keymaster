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

 #include "crypto_aes.h"

void TA_append_tag(keymaster_blob_t *output, uint32_t *out_size,
			const uint8_t *tag, const uint32_t tag_len)
{
	/* is assumed that output has enough allocated memory */
	TEE_MemMove(output->data + *out_size, tag, tag_len);
	*out_size += tag_len;
}

keymaster_error_t TA_aes_finish(keymaster_operation_t *operation,
 				keymaster_blob_t *input,
 				keymaster_blob_t *output, uint32_t *out_size,
 				uint32_t tag_len)
{
	TEE_Result tee_res = TEE_SUCCESS;
	keymaster_error_t res = KM_ERROR_OK;
	uint8_t *tag = NULL;

	if (operation->padding == KM_PAD_PKCS7 &&
			operation->purpose == KM_PURPOSE_ENCRYPT) {
		res = TA_do_pkcs7_pad(input, KM_ADD, output,
					out_size, !operation->padded);
		if (res != KM_ERROR_OK)
			goto out;
		operation->padded = true;
	} else if (operation->padding == KM_PAD_NONE && (operation->mode ==
			KM_MODE_CBC || operation->mode == KM_MODE_ECB) &&
			input->data_length % BLOCK_SIZE != 0) {
		EMSG("Input data size for AES CBC and ECB modes without padding must be a multiple of block size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	}
	if (operation->mode == KM_MODE_GCM) {
		/* For KM_MODE_GCM */
		if (operation->purpose == KM_PURPOSE_ENCRYPT) {
			/* During encryption */
			tag = TEE_Malloc(tag_len, TEE_MALLOC_FILL_ZERO);
			if (!tag) {
				EMSG("Failed to allocate memory for GCM tag");
				res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto out;
			}
			res = TEE_AEEncryptFinal(*operation->operation,
						input->data,
						input->data_length,
						output->data,
						out_size, tag, &tag_len);
			/* after processing all plaintext, compute the
			 * tag (KM_TAG_MAC_LENGTH bytes) and append it
			 * to the returned ciphertext
			 */
			TA_append_tag(output, out_size, tag, tag_len);
		} else {/* KM_PURPOSE_DECRYPT	During decryption
			 * process the last KM_TAG_MAC_LENGTH bytes from
			 * input data of last Update as the tag
			 */
			tee_res = TEE_AEDecryptFinal(*operation->operation,
						input->data,
						input->data_length,
						output->data, out_size,
						operation->a_data,
						operation->mac_length / 8);
			if (tee_res == TEE_ERROR_MAC_INVALID) {
				/* tag verification fails */
				EMSG("AES GCM verification failed");
				res = KM_ERROR_VERIFICATION_FAILED;
				goto out;
			}
		}
	} else {
		res = TEE_CipherDoFinal(*operation->operation, input->data,
					input->data_length, output->data,
					out_size);
	}
	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7
			&& operation->purpose == KM_PURPOSE_DECRYPT
			&& output->data_length > 0) {
		output->data_length = *out_size;
		res = TA_do_pkcs7_pad(input, KM_REMOVE, output,
							  out_size, false);
		if (res == KM_ERROR_OK)
			operation->padded = true;
	}
	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7
			&& operation->purpose == KM_PURPOSE_DECRYPT
			&& !operation->padded) {
		res = KM_ERROR_INVALID_ARGUMENT;
	}
out:
	if (tag)
		TEE_Free(tag);
	return res;
}
