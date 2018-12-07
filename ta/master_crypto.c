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

#include "master_crypto.h"

//Master key for encryption/decryption of all CA's keys,
//and also used as HBK during attestation
static uint8_t objID[] = {0xa7U, 0x62U, 0xcfU, 0x11U};
static uint8_t iv[IV_LENGTH];

TEE_Result TA_open_secret_key(TEE_ObjectHandle *secretKey)
{
	return TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			objID, sizeof(objID),
			TEE_DATA_FLAG_ACCESS_READ, secretKey);
}

TEE_Result TA_create_secret_key(void)
{
	TEE_Result res;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_ObjectHandle key = TEE_HANDLE_NULL;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				objID, sizeof(objID),
				TEE_DATA_FLAG_ACCESS_READ, &object);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//No such key, create it

		res = TEE_AllocateTransientObject(TEE_TYPE_AES, KEY_SIZE, &key);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a transient object for a key, res = %x", res);
			goto error;
		}

		res = TEE_GenerateKey(key, KEY_SIZE, NULL, 0);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to generate key, res = %x", res);
			goto error;
		}

		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				objID, sizeof(objID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				key, NULL, 0U, &object);

		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a secret persistent key, res = %x", res);
			goto error;
		}
error:
		TEE_CloseObject(key);
		TEE_CloseObject(object);
	} else if (res == TEE_SUCCESS) {
		//Key already exits
		TEE_CloseObject(object);
	} else {
		//Something wrong...
		EMSG("Failed to open secret key, res=%x", res);
	}

	return res;
}

/* This function encrypts or decrypts key-blob.
 * New key-blob has a format:
 * key_blob = IV || enc_data || TAG (AES-GCM).
 * As we mentioned above: IV - nonce for AES-GCM; enc_data - encrypted key data;
 * TAG - tag from AES-GCM algorithm for integrity check. */
TEE_Result TA_execute(uint8_t *data, const size_t size, const uint32_t mode)
{
	uint8_t *outbuf = NULL;
	uint8_t *outptr = NULL;
	uint32_t outbuf_size = size;
	/* zero_size for outsize in AEEncrypt/DecryptFinal operations */
	uint32_t zero_size = 0;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;

	res = TA_open_secret_key(&secretKey);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read secret key");
		return res;
	}

	outbuf = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	outptr = outbuf;
	if (!outbuf) {
		EMSG("failed to allocate memory for out buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		return res;
	}

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, mode, KEY_SIZE);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate AES operation, res=%x", res);
		goto exit;
	}

	// Use persistent key objects
	res = TEE_SetOperationKey(op, secretKey);
	TEE_CloseObject(secretKey);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set secret key, res=%x", res);
		goto exit;
	}

	if (mode == TEE_MODE_ENCRYPT) {
		/* new IV generation for new key-blob */
		TEE_GenerateRandom(iv, IV_LENGTH);
		TEE_MemMove(outptr, iv, IV_LENGTH);
		outptr += IV_LENGTH;
		outbuf_size -= IV_LENGTH;
	} else {
		/* copy IV from old key-blob for decryption. */
		memcpy(iv, data, IV_LENGTH);
		data += IV_LENGTH;
	}

	res = TEE_AEInit(op, iv, IV_LENGTH, 8 * TAG_LENGTH, 0, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Error TEE_AEInit res=%x", res);
		goto exit;
	}

	res = TEE_AEUpdate(op, data, size - IV_LENGTH - TAG_LENGTH,
		outptr, &outbuf_size);
	if (res != TEE_SUCCESS) {
		EMSG("Error TEE_AEUpdate res=%x", res);
		goto exit;
	}

	if (mode == TEE_MODE_ENCRYPT) {
		outptr += outbuf_size;
		outbuf_size = size - outbuf_size - IV_LENGTH;
		res = TEE_AEEncryptFinal(op, NULL, 0, NULL, &zero_size, outptr,
			&outbuf_size);
	} else {
		data += outbuf_size;
		res = TEE_AEDecryptFinal(op, NULL, 0, NULL, &zero_size, data,
			TAG_LENGTH);
		data -= (size - TAG_LENGTH);
	}
	if (res != TEE_SUCCESS) {
		EMSG("Error TEE_AEEFinal res=%x", res);
		goto exit;
	}

	TEE_MemMove(data, outbuf, size);
exit:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	if (outbuf)
		TEE_Free(outbuf);
	return res;
}

TEE_Result TA_encrypt(uint8_t *data, const size_t size)
{
	return TA_execute(data, size, TEE_MODE_ENCRYPT);
}

TEE_Result TA_decrypt(uint8_t *data, const size_t size)
{
	return TA_execute(data, size, TEE_MODE_DECRYPT);
}
