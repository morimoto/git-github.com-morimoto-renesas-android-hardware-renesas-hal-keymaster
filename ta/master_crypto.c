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

static uint8_t objID[] = {0xa7U, 0x62U, 0xcfU, 0x11U};
static uint8_t iv[KEY_LENGTH];

TEE_Result TA_read_secret_key(TEE_ObjectHandle *secretKey)
{
	static TEE_ObjectHandle masterKey = TEE_HANDLE_NULL;
	TEE_Result res;
	TEE_Attribute attrs[1];
	uint8_t	keyData[KEY_LENGTH];
	uint32_t readSize = 0;
	TEE_ObjectHandle object;

	if (masterKey != TEE_HANDLE_NULL) {
		*secretKey = masterKey;
		return TEE_SUCCESS;
	}
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, objID,
		sizeof(objID), TEE_DATA_FLAG_ACCESS_READ, &object);
	if (res == TEE_SUCCESS) {
		res = TEE_ReadObjectData(object, keyData,
					sizeof(keyData), &readSize);
		if (res != TEE_SUCCESS || readSize != KEY_LENGTH) {
			EMSG("TEE_ReadObjectData keyData\n");
			goto close;
		}
		res = TEE_ReadObjectData(object, iv, sizeof(iv), &readSize);
		if (res != TEE_SUCCESS || readSize != KEY_LENGTH) {
			EMSG("TEE_ReadObjectData IV\n");
			goto close;
		}
		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE,
						keyData, sizeof(keyData));
		res = TEE_AllocateTransientObject(TEE_TYPE_AES,
						KEY_SIZE, &masterKey);
		if (res != TEE_SUCCESS)
			EMSG("Error TEE_AllocateTransientObject\n");
		if (res == TEE_SUCCESS) {
			res = TEE_PopulateTransientObject(masterKey, attrs,
					sizeof(attrs)/sizeof(TEE_Attribute));
			if (res != TEE_SUCCESS)
				EMSG("Error TEE_PopulateTransientObject\n");
		}
close:
		TEE_CloseObject(object);
	}
	if (res == TEE_SUCCESS)
		*secretKey = masterKey;
	return res;
}

TEE_Result TA_create_secret_key(void)
{
	TEE_Result res;
	uint8_t	keyData[KEY_LENGTH];
	TEE_ObjectHandle object = TEE_HANDLE_NULL;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				objID, sizeof(objID),
				TEE_DATA_FLAG_ACCESS_READ, &object);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		TEE_GenerateRandom(keyData, sizeof(keyData));
		TEE_GenerateRandom((void *)iv, sizeof(iv));
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, objID,
						sizeof(objID),
						TEE_DATA_FLAG_ACCESS_WRITE,
						NULL, NULL, 0U, &object);
		if (res != TEE_SUCCESS) {
			EMSG("TEE_CreatePersistentObject failed");
		} else {
			res = TEE_WriteObjectData(object,
					(void *)keyData, sizeof(keyData));
			if (res != TEE_SUCCESS)
				EMSG("TEE_WriteObjectData keyData failed");
			res = TEE_WriteObjectData(object,
						(void *)iv, sizeof(iv));
			if (res != TEE_SUCCESS)
				EMSG("TEE_WriteObjectData IV failed");
			TEE_CloseObject(object);
		}
	} else if (res == TEE_SUCCESS) {
		TEE_CloseObject(object);
	} else {
		EMSG("Failed to open secret, error=%X", res);
	}
	return res;
}

TEE_Result TA_execute(uint8_t *data, const size_t size, const uint32_t mode)
{
	uint8_t *outbuf = NULL;
	uint32_t outbuf_size = size;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectInfo info;
	TEE_Result res;
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;

	res = TA_read_secret_key(&secretKey);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read secret key");
		goto exit;
	}
	outbuf = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
	if (!outbuf) {
		EMSG("failed to allocate memory for out buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	if (size % BLOCK_SIZE != 0) {
		/* check size alignment */
		EMSG("Size alignment check failed");
		res = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
	TEE_GetObjectInfo1(secretKey, &info);
	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
						mode, info.maxKeySize);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate AES operation");
		goto exit;
	}
	res = TEE_SetOperationKey(op, secretKey);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set secret key");
		goto free_op;
	}
	TEE_CipherInit(op, iv, sizeof(iv));
	if (res == TEE_SUCCESS && size > 0)
		res = TEE_CipherDoFinal(op, data, size,
					outbuf, &outbuf_size);
	if (res != TEE_SUCCESS)
		EMSG("Error TEE_CipherDoFinal");
	else
		TEE_MemMove(data, outbuf, size);
free_op:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
exit:
	if (outbuf != NULL)
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

void TA_free_master_key(void)
{
	TEE_ObjectHandle secretKey = TEE_HANDLE_NULL;

	if (TA_read_secret_key(&secretKey) == TEE_SUCCESS)
		TEE_FreeTransientObject(secretKey);
}
