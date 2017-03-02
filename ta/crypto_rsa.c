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

 #include "crypto_rsa.h"

keymaster_error_t TA_rsa_finish(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output, uint32_t *out_size,
				const uint32_t key_size,
				const keymaster_blob_t signature,
				const TEE_ObjectHandle obj_h)
{
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Attribute *attrs = NULL;
	TEE_Attribute attr;
	uint32_t attrs_count = 0;
	uint32_t digest_out_size = KM_MAX_DIGEST_SIZE;
	uint32_t modulus_size = KM_RSA_ATTR_SIZE;
	uint8_t digest_out[KM_MAX_DIGEST_SIZE];
	uint8_t *modulus = NULL;
	uint8_t *in_buf = NULL;
	uint32_t in_buf_l = 0;

	if (*operation->digest_op != TEE_HANDLE_NULL) {
		TEE_DigestDoFinal(*operation->digest_op, input->data,
			input->data_length, digest_out, &digest_out_size);
		in_buf = digest_out;
		in_buf_l = digest_out_size;
	} else {
		res = TA_append_sf_data(input, *operation, output, out_size);
		if (res != KM_ERROR_OK)
			goto out;
		in_buf = input->data;
		in_buf_l = input->data_length;
	}
	if (in_buf_l == 0) {
		*out_size = 0;
		goto out;
	}
	if (operation->padding == KM_PAD_NONE) {
		/* For unpadded
		 * signing and encryption operations
		 */
		if (operation->purpose == KM_PURPOSE_SIGN ||
			  operation->purpose == KM_PURPOSE_ENCRYPT) {
			/* if the provided data is shorter than the key */
			if (in_buf_l < key_size / 8) {
				/* the data must be zero-padded on
				 * the left before signing/encryption
				 */
				res = TA_do_rsa_pad(&in_buf, &in_buf_l, key_size,
							output, out_size);
				if (res != KM_ERROR_OK)
					goto out;
			} else if (in_buf_l == key_size / 8) {
				/* If the data is the same length as the key */
				if (!modulus) {
					modulus = TEE_Malloc(modulus_size,
							TEE_MALLOC_FILL_ZERO);
					if (!modulus) {
						EMSG("Failed to allocate memory for RSA modulus");
						res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
						goto out;
					}
				}
				res = TEE_GetObjectBufferAttribute(obj_h,
							TEE_ATTR_RSA_MODULUS,
							modulus,
							&modulus_size);
				if (res != KM_ERROR_OK) {
					EMSG("Failed to read RSA key");
					goto out;
				}
				if (TEE_MemCompare(
						in_buf, modulus,
						in_buf_l) > 0) {
					/* but numerically larger */
					res = KM_ERROR_INVALID_ARGUMENT;
					EMSG("For RSA Sign and Encrypt with KM_PAD_NONE input data value must be not bigger then key");
					goto out;
				}
			}
		} else {/* For verification and decryption operations */
			if (in_buf_l != key_size / 8) {
				/* the data must be exactly
				 * as long as the key
				 */
				res = KM_ERROR_INVALID_INPUT_LENGTH;
				EMSG("For RSA Verify and Decrypt with KM_PAD_NONE input data langth must be equal to key length");
				goto out;
			}
		}
	}
	switch (operation->purpose) {
	case KM_PURPOSE_ENCRYPT:
		res = TEE_AsymmetricEncrypt(*operation->operation, NULL, 0,
					in_buf, in_buf_l,
					output->data, out_size);
		break;
	case KM_PURPOSE_DECRYPT:
		res = TEE_AsymmetricDecrypt(*operation->operation, NULL, 0,
					in_buf, in_buf_l,
					output->data, out_size);
		break;
	case KM_PURPOSE_VERIFY:
	case KM_PURPOSE_SIGN:
		if (operation->padding == KM_PAD_RSA_PSS) {
			TEE_InitValueAttribute(&attr,
				TEE_ATTR_RSA_PSS_SALT_LENGTH,
				KM_SALT_LENGTH, 0);
			attrs = &attr;
			attrs_count = 1;
		}
		if (operation->purpose == KM_PURPOSE_VERIFY) {
			res = TEE_AsymmetricVerifyDigest(*operation->operation,
						attrs, attrs_count, in_buf,
						in_buf_l,
						signature.data,
						signature.data_length);
		} else {/* KM_PURPOSE_SIGN */
			res = TEE_AsymmetricSignDigest(*operation->operation,
						attrs,
						attrs_count,
						in_buf,
						in_buf_l,
						output->data,
						out_size);
		}
		break;
	default:
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
		goto out;
	}
out:
	if (modulus)
		TEE_Free(modulus);
	return res;
}
