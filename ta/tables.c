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

#include "tables.h"

static keymaster_use_timer_t use_timers[KM_MAX_USE_TIMERS];
static keymaster_use_counter_t use_counters[KM_MAX_USE_COUNTERS];
static uint32_t in_use_c;

keymaster_error_t TA_count_key_uses(const keymaster_key_blob_t *key,
				const uint32_t max_uses)
{
	uint32_t i;
	uint8_t *tag_pointer = key->key_material +
				(key->key_material_size - TAG_LENGTH);

	if (in_use_c == KM_MAX_USE_COUNTERS) {
		return KM_ERROR_TOO_MANY_OPERATIONS;
	}

	for (i = 0; i < in_use_c; i++) {
		if (use_counters[i].key_tag && !TEE_MemCompare(tag_pointer,
			use_counters[i].key_tag, TAG_LENGTH)) {
			if (use_counters[i].count < max_uses) {
				use_counters[i].count++;
				break;
			}
			EMSG("Reached max key use count!");
			return KM_ERROR_KEY_MAX_OPS_EXCEEDED;
		}
	}

	if (i == in_use_c) {
		use_counters[i].key_tag = TEE_Malloc(TAG_LENGTH,
			TEE_MALLOC_FILL_ZERO);
		if (use_counters[i].key_tag) {
			TEE_MemMove(use_counters[in_use_c].key_tag, tag_pointer,
				TAG_LENGTH);
			use_counters[in_use_c].count = 1;
			in_use_c++;
		} else {
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}

	}
	return KM_ERROR_OK;
}

void TA_clean_timers(void)
{
	TEE_Time cur_t;

	TEE_GetSystemTime(&cur_t);
	for (uint32_t i = 0; i < KM_MAX_USE_TIMERS; i++) {
		if (use_timers[i].last_access.seconds != 0 &&
				use_timers[i].last_access.seconds +
				use_timers[i].min_sec > cur_t.seconds) {
			if (use_timers[i].key_tag) {
				TEE_Free(use_timers[i].key_tag);
			}
			use_timers[i].key_tag = NULL;
			use_timers[i].min_sec = 0;
			use_timers[i].last_access.seconds = 0;
			use_timers[i].last_access.millis = 0;
		}
	}
}

keymaster_error_t TA_check_key_use_timer(const keymaster_key_blob_t *key,
					const uint32_t min_sec)
{
	TEE_Time cur_t;
	uint8_t *tag_pointer = key->key_material +
				(key->key_material_size - TAG_LENGTH);

	TA_clean_timers();
	TEE_GetSystemTime(&cur_t);
	for (uint32_t i = 0; i < KM_MAX_USE_TIMERS; i++) {
		if (use_timers[i].key_tag && !TEE_MemCompare(tag_pointer,
			use_timers[i].key_tag, TAG_LENGTH)) {
			if (use_timers[i].last_access.seconds +
						min_sec > cur_t.seconds) {
				return KM_ERROR_KEY_RATE_LIMIT_EXCEEDED;
			}
			break;
		}
	}
	return KM_ERROR_OK;
}

keymaster_error_t TA_trigger_timer(const keymaster_key_blob_t *key,
				const uint32_t min_sec)
{
	TEE_Time cur_t;
	uint32_t free_n = KM_MAX_USE_TIMERS;
	uint8_t *tag_pointer = key->key_material +
				(key->key_material_size - TAG_LENGTH);

	TA_clean_timers();
	TEE_GetSystemTime(&cur_t);
	for (uint32_t i = 0; i < KM_MAX_USE_TIMERS; i++) {
		if (free_n == KM_MAX_USE_TIMERS && !use_timers[i].key_tag) {
			free_n = i;
		}
		if (use_timers[i].key_tag && !TEE_MemCompare(tag_pointer,
			use_timers[i].key_tag, TAG_LENGTH)) {
			use_timers[i].last_access = cur_t;
			return KM_ERROR_OK;
		}
	}
	if (free_n == KM_MAX_USE_TIMERS) {
		EMSG("Table of last access key time is full");
		return KM_ERROR_TOO_MANY_OPERATIONS;
	}
	use_timers[free_n].key_tag = TEE_Malloc(TAG_LENGTH,
		TEE_MALLOC_FILL_ZERO);
	if (use_timers[free_n].key_tag) {
		TEE_MemMove(use_timers[free_n].key_tag, tag_pointer,
			TAG_LENGTH);
		use_timers[free_n].last_access = cur_t;
		use_timers[free_n].min_sec = min_sec;
	} else {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	return KM_ERROR_OK;
}
