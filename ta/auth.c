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

#include "auth.h"

keymaster_error_t TA_do_auth(const keymaster_key_param_set_t in_params,
				const keymaster_key_param_set_t key_params)
{
	uint64_t suid[MAX_SUID];
	uint32_t suid_count = 0;
	bool found_token = false;
	hw_authenticator_type_t auth_type = UNDEFINED;
	hw_auth_token_t auth_token;
	keymaster_error_t res = KM_ERROR_OK;

	for (size_t i = 0; i < key_params.length; i++) {
		switch (key_params.params[i].tag) {
		case KM_TAG_USER_SECURE_ID:
			if (suid_count + 1 > MAX_SUID) {
				EMSG("To many SUID. Expected max count %u",
								MAX_SUID);
				break;
			}
			suid[suid_count] = key_params.params[i].
						key_param.long_integer;
			suid_count++;
			break;
		case KM_TAG_USER_AUTH_TYPE:
			auth_type = (hw_authenticator_type_t)
				key_params.params[i].key_param.enumerated;
			break;
		default:
			break;
		}
	}

	for (size_t i = 0; i < in_params.length; i++) {
		if (found_token)
			break;
		switch (in_params.params[i].tag) {
		case KM_TAG_AUTH_TOKEN:
			if (in_params.params[i].key_param.blob.data_length >=
							sizeof(auth_token)) {
				found_token = true;
				TEE_MemMove(&auth_token,
					in_params.params[i].key_param.blob.data,
					sizeof(auth_token));
			}
			break;
		default:
			break;
		}
	}

	if (suid_count > 0 && found_token) {
		res = TA_check_auth_token(suid, suid_count,
						auth_type, auth_token);
	} else {
		EMSG("Authentication failed. Key can not be used");
		res = KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
	}
	return res;
}

keymaster_error_t TA_check_auth_token(const uint64_t *suid,
					const uint32_t suid_count,
					const hw_authenticator_type_t auth_type,
					const hw_auth_token_t auth_token)
{
	keymaster_error_t res = KM_ERROR_OK;
	bool in_list = false;
	/*TODO verify sign*/
	/*Check auth token
	 *KM_TAG_USER_SECURE_ID is enforced by this method only if the key also
	 *has KM_TAG_AUTH_TIMEOUT. If the key has both, then this method must
	 *have received a KM_TAG_AUTH_TOKEN in in_params and that token must
	 *be valid, meaning that the HMAC field validates correctly. In
	 *addition, at least one of the KM_TAG_USER_SECURE_ID values from the
	 *key must match at least one of the secure ID values in the token.
	 *Finally, the key must also have a KM_TAG_USER_AUTH_TYPE and it must
	 *match the auth type in the token. If any of these requirements is not
	 *met, the method must return KM_ERROR_KEY_USER_NOT_AUTHENTICATED.
	*/
	for (uint32_t i = 0; i < suid_count; i++) {
		if (auth_token.user_id == suid[i]) {
			in_list = true;
			break;
		}
	}
	if (!in_list) {
		EMSG("Suid from auth token not in list of this key");
		return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
	}
	if ((TEE_U32_FROM_BIG_ENDIAN(auth_token.authenticator_type) &
						(uint32_t) auth_type) == 0) {
		EMSG("Authentication type not passed");
		return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
	}
	return res;
}
