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

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <type_traits>
#include <memory>
#include <utils/Log.h>
#include <utils/Errors.h>

#include "optee_keymaster.h"
#include "optee_keymaster_ipc.h"

#undef LOG_TAG
#define LOG_TAG "OpteeKeymaster"

namespace renesas {

const uint32_t RECV_BUF_SIZE = 8192;

OpteeKeymasterDevice::OpteeKeymasterDevice(const hw_module_t* module)
    : connected(false) {

    static_assert(std::is_standard_layout<OpteeKeymasterDevice>::value,
                    "OpteeKeymasterDevice must be standard layout");
    static_assert(offsetof(OpteeKeymasterDevice, device_) == 0,
                    "device_ must be the first member of OpteeKeymasterDevice");
    static_assert(offsetof(OpteeKeymasterDevice, device_.common) == 0,
                    "common must be the first member of keymaster2_device");

    memset(&device_, 0, sizeof(device_));
    device_.common.tag = HARDWARE_DEVICE_TAG;
    device_.common.version = 1;
    device_.common.module = const_cast<hw_module_t*>(module);
    device_.common.close = close_device;

    device_.configure = configure;
    device_.add_rng_entropy = add_rng_entropy;
    device_.generate_key = generate_key;
    device_.get_key_characteristics = get_key_characteristics;
    device_.import_key = import_key;
    device_.export_key = export_key;
    device_.upgrade_key = upgrade_key;
    device_.delete_key = nullptr;/* delete_key; */
    device_.delete_all_keys = nullptr;/* delete_all_keys; */
    device_.begin = begin;
    device_.update = update;
    device_.finish = finish;
    device_.abort = abort;
}

bool OpteeKeymasterDevice::connect(void) {
    if (connected) {
        ALOGE("Keymaster device is already connected");
        return false;
    }
    if (!optee_keystore_connect()) {
        ALOGE("Fail to load Keystore TA");
        return false;
    }
    connected = true;
    ALOGV("Keymaster connected");
    return true;
}

void OpteeKeymasterDevice::disconnect(void) {
    if (connected) {
        optee_keystore_disconnect();
        connected = false;
    }
    ALOGV("Keymaster has been disconnected");
}

hw_device_t* OpteeKeymasterDevice::hw_device(void) {
    return &device_.common;
}

int OpteeKeymasterDevice::close_device(hw_device_t* dev) {
    delete reinterpret_cast<OpteeKeymasterDevice*>(dev);
    return 0;
}

OpteeKeymasterDevice::~OpteeKeymasterDevice() {
    disconnect();
}

int OpteeKeymasterDevice::serialize(uint8_t* ptr, const size_t count,
                                    const uint8_t* source,
                                    const uint32_t str_size) {
    memcpy(ptr, &count, sizeof(count));
    ptr += SIZE_LENGTH;
    memcpy(ptr, source, str_size * count);
    return SIZE_LENGTH + count * str_size;
}

int OpteeKeymasterDevice::serializeParams(uint8_t* ptr,
                        const keymaster_key_param_set_t* params) {
    uint8_t* start = ptr;
    memcpy(ptr, &params->length, sizeof(params->length));
    ptr += SIZE_LENGTH;
    for (size_t i = 0; i < params->length; i++) {
        memcpy(ptr, params->params + i, SIZE_OF_ITEM(params->params));
        ptr += SIZE_OF_ITEM(params->params);
        if (keymaster_tag_get_type((params->params + i)->tag) == KM_BIGNUM ||
                keymaster_tag_get_type((params->params + i)->tag) == KM_BYTES) {
            ptr += serialize(ptr, params->params[i].blob.data_length,
                     params->params[i].blob.data,
                     SIZE_OF_ITEM(params->params[i].blob.data));
        }
    }
    return ptr - start;
}

int OpteeKeymasterDevice::serializePresence(uint8_t* ptr, const presence p) {
    memcpy(ptr, &p, sizeof(presence));
    return sizeof(presence);
}

keymaster_error_t OpteeKeymasterDevice::Configure(
            const keymaster_key_param_set_t* params) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    int in_size = PARAM_SET_SIZE(params);
    uint8_t in[in_size];
    memset(in, 0, in_size);
    serializeParams(in, params);
    keymaster_error_t res = optee_keystore_call(KM_CONFIGURE,
                                                    in, in_size, nullptr, 0);
    if (res != KM_ERROR_OK) {
        ALOGE("Configure failed with code %d", res);
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Add_rng_entropy(const uint8_t* data,
                                                size_t data_length) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    int in_size = 0;
    keymaster_error_t res = KM_ERROR_OK;
    if (!data)
        in_size = 0;
    else
        in_size = data_length * SIZE_OF_ITEM(data) + SIZE_LENGTH;
    uint8_t in[in_size];
    memset(in, 0, in_size);
    serialize(in, data_length, data, SIZE_OF_ITEM(data));
    res = optee_keystore_call(KM_ADD_RNG_ENTROPY, in, in_size, nullptr, 0);
    if (res != KM_ERROR_OK) {
        ALOGE("Add RNG entropy failed with code %d", res);
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Generate_key(
                              const keymaster_key_param_set_t* params,
                              keymaster_key_blob_t* key_blob,
                              keymaster_key_characteristics_t* characteristics) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    keymaster_error_t res = KM_ERROR_OK;
    int in_size = PARAM_SET_SIZE(params);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    serializeParams(in, params);

    res = optee_keystore_call(KM_GENERATE_KEY, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Generate key failed with code %d", res);
        return res;
    }

    ptr = out;
    ptr += deserialize_key_blob(ptr, key_blob, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize key blob");
        return res;
    }
    ptr += deserialize_characteristics(ptr, characteristics, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize characteristics");
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Get_key_characteristics(
                          const keymaster_key_blob_t* key_blob,
                          const keymaster_blob_t* client_id,
                          const keymaster_blob_t* app_data,
                          keymaster_key_characteristics_t* characteristics) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    int in_size = KEY_BLOB_SIZE(key_blob);
    in_size += sizeof(presence);/* place to mark presence of client_id */
    if (client_id)
        in_size += BLOB_SIZE(client_id);
    in_size += sizeof(presence);/* place to mark presence of app_data */
    if (app_data)
        in_size += BLOB_SIZE(app_data);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    ptr += serialize(ptr, key_blob->key_material_size, key_blob->key_material,
                     SIZE_OF_ITEM(key_blob->key_material));
    ptr += check_and_push_blob(ptr, client_id);
    ptr += check_and_push_blob(ptr, app_data);

    res = optee_keystore_call(KM_GET_KEY_CHARACTERISTICS, in,
                                               in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Get key characteristics failed with code %d", res);
        return res;
    }

    deserialize_characteristics(out, characteristics, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize characteristics");
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Import_key(
                            const keymaster_key_param_set_t* params,
                             keymaster_key_format_t key_format,
                             const keymaster_blob_t* key_data,
                             keymaster_key_blob_t* key_blob,
                             keymaster_key_characteristics_t* characteristics) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    int in_size = PARAM_SET_SIZE(params) + SIZE_OF_ITEM(params->params) +
        BLOB_SIZE(key_data);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    ptr += serializeParams(ptr, params);
    memcpy(ptr, &key_format, sizeof(key_format));
    ptr += sizeof(key_format);
    ptr += serialize(ptr, key_data->data_length, key_data->data,
                                               SIZE_OF_ITEM(key_data->data));

    res = optee_keystore_call(KM_IMPORT_KEY, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Import key failed with code %d", res);
        return res;
    }

    ptr = out;
    ptr += deserialize_key_blob(ptr, key_blob, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to allocate memory on blob deserialization");
        return res;
    }
    ptr += deserialize_characteristics(ptr, characteristics, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to allocate memory on characteristics deserialization");
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Export_key(
                                keymaster_key_format_t export_format,
                                const keymaster_key_blob_t* key_to_export,
                                const keymaster_blob_t* client_id,
                                const keymaster_blob_t* app_data,
                                keymaster_blob_t* export_data) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    int in_size = KEY_BLOB_SIZE(key_to_export) + sizeof(export_format);
    in_size += sizeof(presence);/* place to mark presence of client_id */
    if (client_id)
        in_size += BLOB_SIZE(client_id);
    in_size += sizeof(presence);/* place to mark presence of app_data */
    if (app_data)
        in_size += BLOB_SIZE(app_data);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    memcpy(ptr, &export_format, sizeof(export_format));
    ptr += sizeof(export_format);
    ptr += serialize(ptr, key_to_export->key_material_size,
                     key_to_export->key_material,
                     SIZE_OF_ITEM(key_to_export->key_material));
    ptr += check_and_push_blob(ptr, client_id);
    ptr += check_and_push_blob(ptr, app_data);

    res = optee_keystore_call(KM_EXPORT_KEY, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Export key failed with code %d", res);
        return res;
    }

    deserialize_blob(out, export_data, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize blob from TA");
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Attest_key(
                                const keymaster_key_blob_t* key_to_attest,
                                const keymaster_key_param_set_t* attest_params,
                                keymaster_cert_chain_t* cert_chain) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    uint8_t* perm;
    int out_size = RECV_BUF_SIZE;
    int in_size = PARAM_SET_SIZE(attest_params) + KEY_BLOB_SIZE(key_to_attest);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    ptr += serialize(ptr, key_to_attest->key_material_size,
                     key_to_attest->key_material,
                     SIZE_OF_ITEM(key_to_attest->key_material));
    ptr += serializeParams(ptr, attest_params);

    res = optee_keystore_call(KM_ATTEST_KEY, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Attest key failed with code %d", res);
        return res;
    }

    ptr = out;
    memcpy(&cert_chain->entry_count, ptr, sizeof(cert_chain->entry_count));
    ptr += SIZE_LENGTH;
    cert_chain->entries = new keymaster_blob_t[cert_chain->entry_count];
    if (!cert_chain->entries) {
        ALOGE("Failed to allocate memory for cert chain");
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    for(size_t i = 0; i < cert_chain->entry_count; i++) {
        memcpy(&(cert_chain->entries[i].data_length), ptr,
                       sizeof(cert_chain->entries[i].data_length));
        ptr += SIZE_LENGTH;
        perm = new uint8_t[cert_chain->entries[i].data_length];
        if (!perm) {
            ALOGE("Failed to allocate memory on certificate chain deserialization");
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        memcpy(perm, ptr, cert_chain->entries[i].data_length);
        ptr += cert_chain->entries[i].data_length;
        cert_chain->entries[i].data = perm;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Upgrade_key(
                               const keymaster_key_blob_t* key_to_upgrade,
                               const keymaster_key_param_set_t* upgrade_params,
                               keymaster_key_blob_t* upgraded_key) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    int in_size = KEY_BLOB_SIZE(key_to_upgrade) +
                                       PARAM_SET_SIZE(upgrade_params);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    ptr += serialize(ptr, key_to_upgrade->key_material_size,
                   key_to_upgrade->key_material,
                   SIZE_OF_ITEM(key_to_upgrade->key_material));
    ptr += serializeParams(ptr, upgrade_params);

    res = optee_keystore_call(KM_UPGRADE_KEY, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Upgrade key failed with code %d", res);
        return res;
    }

    deserialize_key_blob(out, upgraded_key, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize key blob");
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Delete_key(const keymaster_key_blob_t* key) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    int in_size = KEY_BLOB_SIZE(key);
    uint8_t in[in_size];
    memset(in, 0, in_size);
    serialize(in, key->key_material_size, key->key_material,
                                               SIZE_OF_ITEM(key->key_material));

    res = optee_keystore_call(KM_DELETE_KEY, in, in_size, nullptr, 0);
    if (res != KM_ERROR_OK) {
        ALOGE("Attest key failed with code %d", res);
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Delete_all_keys() {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = optee_keystore_call(
                                KM_DELETE_ALL_KEYS, nullptr, 0, nullptr, 0);
    if (res != KM_ERROR_OK) {
        ALOGE("Delete all keys failed with code %d", res);
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Begin(keymaster_purpose_t purpose,
                            const keymaster_key_blob_t* key,
                            const keymaster_key_param_set_t* in_params,
                            keymaster_key_param_set_t* out_params,
                            keymaster_operation_handle_t* operation_handle) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    int in_size = sizeof(purpose) + KEY_BLOB_SIZE(key);
    in_size += sizeof(presence);/* place to mark presence of in_params */
    if (in_params)
        in_size += PARAM_SET_SIZE(in_params);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    memcpy(ptr, &purpose, sizeof(purpose));
    ptr += sizeof(purpose);
    ptr += serialize(ptr, key->key_material_size, key->key_material,
                                               SIZE_OF_ITEM(key->key_material));
    ptr += check_and_push_params(ptr, in_params);

    res = optee_keystore_call(KM_BEGIN, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Begin failed with code %d", res);
        return res;
    }

    ptr = out;
    ptr += deserialize_param_set(ptr, out_params, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserailize param set from TA");
        return res;
    }
    memcpy(operation_handle, ptr, sizeof(*operation_handle));
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Update(
             keymaster_operation_handle_t operation_handle,
             const keymaster_key_param_set_t* in_params,
             const keymaster_blob_t* input, size_t* input_consumed,
             keymaster_key_param_set_t* out_params, keymaster_blob_t* output) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    int in_size = sizeof(operation_handle) + BLOB_SIZE(input);
    in_size += sizeof(presence);/* place to mark presence of in_params */
    if (in_params)
        in_size += PARAM_SET_SIZE(in_params);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    memcpy(ptr, &operation_handle, sizeof(operation_handle));
    ptr += sizeof(operation_handle);
    ptr += check_and_push_params(ptr, in_params);
    ptr += serialize(ptr, input->data_length, input->data,
                                               SIZE_OF_ITEM(input->data));

    res = optee_keystore_call(KM_UPDATE, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Update failed with code %d", res);
        return res;
    }

    ptr = out;
    memcpy(input_consumed, ptr, sizeof(*input_consumed));
    ptr += SIZE_LENGTH;
    ptr += deserialize_blob(ptr, output, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize blob from TA");
        return res;
    }
    ptr += deserialize_param_set(ptr, out_params, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize param set from TA");
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Finish(
            keymaster_operation_handle_t operation_handle,
            const keymaster_key_param_set_t* in_params,
            const keymaster_blob_t* input, const keymaster_blob_t* signature,
            keymaster_key_param_set_t* out_params, keymaster_blob_t* output) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    uint8_t* ptr;
    int out_size = RECV_BUF_SIZE;
    int in_size = sizeof(operation_handle);
    in_size += sizeof(presence);/* place to mark presence of signature */
    if (signature)
        in_size += BLOB_SIZE(signature);
    in_size += sizeof(presence);/* place to mark presence of input */
    if (input)
        in_size += BLOB_SIZE(input);
    in_size += sizeof(presence);/* place to mark presence of in_params */
    if (in_params)
        in_size += PARAM_SET_SIZE(in_params);
    uint8_t in[in_size];
    uint8_t out[out_size];
    memset(in, 0, in_size);
    memset(out, 0, out_size);
    ptr = in;
    memcpy(ptr, &operation_handle, sizeof(operation_handle));
    ptr += sizeof(operation_handle);
    ptr += check_and_push_params(ptr, in_params);
    ptr += check_and_push_blob(ptr, input);
    ptr += check_and_push_blob(ptr, signature);

    res = optee_keystore_call(KM_FINISH, in, in_size, out, out_size);
    if (res != KM_ERROR_OK) {
        ALOGE("Finish failed with code %d", res);
        return res;
    }

    ptr = out;
    ptr += deserialize_param_set(ptr, out_params, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed deserialize param set from TA");
        return res;
    }
    ptr += deserialize_blob(ptr, output, &res);
    if (res != KM_ERROR_OK) {
        ALOGE("Failed to deserialize blob from TA");
        return res;
    }
    return res;
}

keymaster_error_t OpteeKeymasterDevice::Abort(
                        keymaster_operation_handle_t operation_handle) {
    if (!connected) {
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }
    keymaster_error_t res = KM_ERROR_OK;
    int in_size = sizeof(operation_handle);
    uint8_t in[in_size];
    memset(in, 0, in_size);
    memcpy(in, &operation_handle, sizeof(operation_handle));
    res = optee_keystore_call(KM_ABORT, in, in_size, nullptr, 0);
    if (res != KM_ERROR_OK) {
        ALOGE("Abort failed with code %d", res);
    }
    return res;
}

static inline OpteeKeymasterDevice* convert_device(
                                            const keymaster2_device* dev) {
    return reinterpret_cast<OpteeKeymasterDevice*>(const_cast<keymaster2_device*>(dev));
}

keymaster_error_t OpteeKeymasterDevice::configure(
                                const struct keymaster2_device* dev,
                                const keymaster_key_param_set_t* params) {
    if (dev == nullptr || params == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    return convert_device(dev)->Configure(params);
}

keymaster_error_t OpteeKeymasterDevice::add_rng_entropy(
                                     const struct keymaster2_device* dev,
                                     const uint8_t* data, size_t data_length) {
    if (dev == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    return convert_device(dev)->Add_rng_entropy(data, data_length);
}

keymaster_error_t OpteeKeymasterDevice::generate_key(
                         const struct keymaster2_device* dev,
                         const keymaster_key_param_set_t* params,
                         keymaster_key_blob_t* key_blob,
                         keymaster_key_characteristics_t* characteristics) {
    if (dev == nullptr || params == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (key_blob == nullptr) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    return convert_device(dev)->Generate_key(params,
                                             key_blob, characteristics);
}

keymaster_error_t OpteeKeymasterDevice::get_key_characteristics(
                            const struct keymaster2_device* dev,
                            const keymaster_key_blob_t* key_blob,
                            const keymaster_blob_t* client_id,
                            const keymaster_blob_t* app_data,
                            keymaster_key_characteristics_t* characteristics) {
    if (dev == nullptr || key_blob == nullptr || key_blob->key_material == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (characteristics == nullptr) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    return convert_device(dev)->Get_key_characteristics(key_blob,client_id,
                                                app_data, characteristics);
}

keymaster_error_t OpteeKeymasterDevice::import_key(
                            const struct keymaster2_device* dev,
                            const keymaster_key_param_set_t* params,
                            keymaster_key_format_t key_format,
                            const keymaster_blob_t* key_data,
                            keymaster_key_blob_t* key_blob,
                            keymaster_key_characteristics_t* characteristics) {
    if (dev == nullptr || params == nullptr || key_data == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (key_blob == nullptr) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    return convert_device(dev)->Import_key(params, key_format, key_data,
                                           key_blob, characteristics);
}

keymaster_error_t OpteeKeymasterDevice::export_key(
                                    const struct keymaster2_device* dev,
                                    keymaster_key_format_t export_format,
                                    const keymaster_key_blob_t* key_to_export,
                                    const keymaster_blob_t* client_id,
                                    const keymaster_blob_t* app_data,
                                    keymaster_blob_t* export_data) {
    if (dev == nullptr || key_to_export == nullptr ||
        key_to_export->key_material == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (export_data == nullptr) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    return convert_device(dev)->Export_key(export_format, key_to_export,
                                         client_id, app_data, export_data);
}

keymaster_error_t OpteeKeymasterDevice::attest_key(
                               const struct keymaster2_device* dev,
                               const keymaster_key_blob_t* key_to_attest,
                               const keymaster_key_param_set_t* attest_params,
                               keymaster_cert_chain_t* cert_chain) {
    if (dev == nullptr || key_to_attest == nullptr || attest_params == nullptr
        || cert_chain == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    return convert_device(dev)->Attest_key(key_to_attest,
                                           attest_params, cert_chain);
}

keymaster_error_t OpteeKeymasterDevice::upgrade_key(
                              const struct keymaster2_device* dev,
                              const keymaster_key_blob_t* key_to_upgrade,
                              const keymaster_key_param_set_t* upgrade_params,
                              keymaster_key_blob_t* upgraded_key) {
    if (dev == nullptr || key_to_upgrade == nullptr || upgrade_params == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (upgraded_key == nullptr) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    return convert_device(dev)->Upgrade_key(key_to_upgrade,
                                            upgrade_params, upgraded_key);
}

keymaster_error_t OpteeKeymasterDevice::delete_key(
                                        const struct keymaster2_device* dev,
                                        const keymaster_key_blob_t* key) {
    if (dev == nullptr || key == nullptr || key->key_material == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    return convert_device(dev)->Delete_key(key);
}

keymaster_error_t OpteeKeymasterDevice::delete_all_keys(
                                    const struct keymaster2_device* dev) {
    if (dev == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    return convert_device(dev)->Delete_all_keys();
}

keymaster_error_t OpteeKeymasterDevice::begin(
                            const struct keymaster2_device* dev,
                            keymaster_purpose_t purpose,
                            const keymaster_key_blob_t* key,
                            const keymaster_key_param_set_t* in_params,
                            keymaster_key_param_set_t* out_params,
                            keymaster_operation_handle_t* operation_handle) {
    if (dev == nullptr || key == nullptr || key->key_material == NULL) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (operation_handle == nullptr) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    return convert_device(dev)->Begin(purpose, key, in_params,
                                      out_params, operation_handle);
}

keymaster_error_t OpteeKeymasterDevice::update(
            const struct keymaster2_device* dev,
            keymaster_operation_handle_t operation_handle,
            const keymaster_key_param_set_t* in_params,
            const keymaster_blob_t* input, size_t* input_consumed,
            keymaster_key_param_set_t* out_params, keymaster_blob_t* output) {
    if (dev == nullptr || input == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (input_consumed == nullptr) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    return convert_device(dev)->Update(operation_handle, in_params, input,
                                       input_consumed, out_params, output);
}

keymaster_error_t OpteeKeymasterDevice::finish(
             const struct keymaster2_device* dev,
             keymaster_operation_handle_t operation_handle,
             const keymaster_key_param_set_t* in_params,
             const keymaster_blob_t* input, const keymaster_blob_t* signature,
             keymaster_key_param_set_t* out_params, keymaster_blob_t* output) {
    if (dev == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    return convert_device(dev)->Finish(operation_handle, in_params,
                                       input, signature, out_params, output);
}

keymaster_error_t OpteeKeymasterDevice::abort(const struct keymaster2_device* dev,
                                keymaster_operation_handle_t operation_handle) {
    if (dev == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    return convert_device(dev)->Abort(operation_handle);
}

int OpteeKeymasterDevice::deserialize_key_blob(const uint8_t* out,
                                keymaster_key_blob_t* const key_blob,
                                keymaster_error_t* const res) {
    size_t size;
    uint8_t* material;
    const uint8_t* start = out;

    *res = KM_ERROR_OK;
    memcpy(&size, out, sizeof(size));
    out += SIZE_LENGTH;
    if (size > 0 && !key_blob) {
        ALOGE("Key blob deserialization can not be done, pointer is nullptr");
        *res = KM_ERROR_OUTPUT_PARAMETER_NULL;
        return out - start;
    }
    if (!key_blob)
        return out - start;
    key_blob->key_material_size = size;
    material = new uint8_t[key_blob->key_material_size];
    if (!material) {
        *res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return out - start;
    }
    memcpy(material, out, key_blob->key_material_size);
    out += key_blob->key_material_size;
    key_blob->key_material = material;
    return out - start;
}

int OpteeKeymasterDevice::deserialize_characteristics(const uint8_t* out,
                        keymaster_key_characteristics_t* const characteristics,
                        keymaster_error_t* const res) {
    size_t size;
    const uint8_t* start = out;

    *res = KM_ERROR_OK;
    memcpy(&size, out, sizeof(size));
    out += SIZE_LENGTH;
    if (size > 0 && !characteristics) {
        ALOGE("Characteristics deserialization can not be done, pointer is nullptr");
        *res = KM_ERROR_OUTPUT_PARAMETER_NULL;
        return out - start;
    }
    if (!characteristics)
        return out - start;
    characteristics->hw_enforced.length = size;
    characteristics->hw_enforced.params =
               new keymaster_key_param_t[characteristics->hw_enforced.length];
    if (!characteristics->hw_enforced.params) {
        *res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return out - start;
    }
    for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
        memcpy(characteristics->hw_enforced.params + i,
               out, SIZE_OF_ITEM(characteristics->hw_enforced.params));
        out += SIZE_OF_ITEM(characteristics->hw_enforced.params);
        if (keymaster_tag_get_type(
             characteristics->hw_enforced.params[i].tag) == KM_BIGNUM ||
             keymaster_tag_get_type(characteristics->hw_enforced.params[i].tag)
             == KM_BYTES) {
            out += deserialize_blob(out,
                        &(characteristics->hw_enforced.params[i].blob), res);
        }
    }
    memcpy(&characteristics->sw_enforced.length, out,
                       sizeof(characteristics->sw_enforced.length));
    out += SIZE_LENGTH;
    characteristics->sw_enforced.params =
               new keymaster_key_param_t[characteristics->sw_enforced.length];
    if (!characteristics->sw_enforced.params) {
        *res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return out - start;
    }
    for (size_t i = 0; i < characteristics->sw_enforced.length; i++) {
        memcpy(characteristics->sw_enforced.params + i, out,
               SIZE_OF_ITEM(characteristics->sw_enforced.params));
        out += SIZE_OF_ITEM(characteristics->sw_enforced.params);
        if (keymaster_tag_get_type(
             characteristics->sw_enforced.params[i].tag) == KM_BIGNUM ||
             keymaster_tag_get_type(characteristics->sw_enforced.params[i].tag)
             == KM_BYTES) {
            out += deserialize_blob(out,
                        &(characteristics->sw_enforced.params[i].blob), res);
        }
    }
    return out - start;
}

int OpteeKeymasterDevice::deserialize_blob(const uint8_t* out,
                            keymaster_blob_t* const blob,
                            keymaster_error_t* const res) {
    size_t size;
    uint8_t* data;
    const uint8_t* start = out;

    *res = KM_ERROR_OK;
    memcpy(&size, out, sizeof(size));
    out += SIZE_LENGTH;
    if (size > 0 && !blob) {
        ALOGE("Blob deserialization can not be done, pointer is nullptr");
        *res = KM_ERROR_OUTPUT_PARAMETER_NULL;
        return out - start;
    }
    if (!blob)
        return out - start;
    blob->data_length = size;
    data = new uint8_t[blob->data_length];
    if (!data) {
        ALOGE("Failed to allocate memory for blob");
        *res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return out - start;
    }
    memcpy(data, out, blob->data_length);
    out += blob->data_length;
    blob->data = data;
    return out - start;
}

int OpteeKeymasterDevice::deserialize_param_set(const uint8_t* out,
                            keymaster_key_param_set_t* const params,
                            keymaster_error_t* const res) {
    size_t size;
    const uint8_t* start = out;

    *res = KM_ERROR_OK;
    memcpy(&size, out, sizeof(size));
    out += SIZE_LENGTH;
    if (size > 0 && !params) {
        ALOGE("Parameters deserialization can not be done, pointer is nullptr");
        *res = KM_ERROR_OUTPUT_PARAMETER_NULL;
        return out - start;
    }
    if (!params)
        return out - start;
    params->length = size;
    params->params = new keymaster_key_param_t[params->length];
    if (!params->params) {
        ALOGE("Failed to allocate memory for param set");
        *res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return out - start;
    }
    for(size_t i = 0; i < params->length; i++) {
        memcpy(params->params + i, out, SIZE_OF_ITEM(params->params));
        out += SIZE_OF_ITEM(params->params);
        if (keymaster_tag_get_type(
                params->params[i].tag) == KM_BIGNUM ||
                keymaster_tag_get_type(params->params[i].tag) == KM_BYTES) {
            out += deserialize_blob(out, &(params->params[i].blob), res);
            if (*res != KM_ERROR_OK) {
                ALOGE("Failed to deserialize blob in param");
                return out - start;
            }
        }
    }
    return out - start;
}

int OpteeKeymasterDevice::get_blob_size_in_params(
                               const keymaster_key_param_set_t* params) {
    int size = 0;
    for (size_t i = 0; i < params->length; i++) {
        if (keymaster_tag_get_type(
                params->params[i].tag) == KM_BIGNUM ||
                keymaster_tag_get_type(params->params[i].tag) == KM_BYTES) {
            size += params->params[i].blob.data_length + SIZE_LENGTH;
        }
    }
    return size;
}

int OpteeKeymasterDevice::check_and_push_params(uint8_t* ptr,
                       const keymaster_key_param_set_t* params) {
    uint8_t* start = ptr;
    if (params) {
        ptr += serializePresence(ptr, KM_POPULATED);
        ptr += serializeParams(ptr, params);
    } else {
        ptr += serializePresence(ptr, KM_NULL);
    }
    return ptr - start;
}

int OpteeKeymasterDevice::check_and_push_blob(uint8_t* ptr,
                       const keymaster_blob_t* blob) {
    uint8_t* start = ptr;
    if (blob) {
        ptr += serializePresence(ptr, KM_POPULATED);
        ptr += serialize(ptr, blob->data_length, blob->data,
                                               SIZE_OF_ITEM(blob->data));
    } else {
        ptr += serializePresence(ptr, KM_NULL);
    }
    return ptr - start;
}

};
