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
#include <utils/Log.h>
#include <hardware/keymaster2.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <utils/Errors.h>
#include <cstring>
#include <new>
#include <cerrno>
#include <memory>
#include <sys/stat.h>

#include "optee_keymaster.h"

#undef LOG_TAG
#define LOG_TAG "Salvator Keymaster HAL"

#define SLEEP_TIME 500000
#define MAX_SLEEP_TIME 5000000
#define MAX_TRY_COUNT MAX_SLEEP_TIME/SLEEP_TIME
#define DRV_PATH "/dev/opteearmtz00"

static bool optee_check_drv() {
    struct stat buf;

    /* One try is not enough */
    for (int i = 0; i < MAX_TRY_COUNT; i++) {
        if (stat(DRV_PATH, &buf) == 0) {
            ALOGI("File is ready : try %d", i + 1);
            return true;
        } else {
            ALOGE("Failed to open TEE driver: %s", strerror(errno));
        }
        /*
         * To be sure that driver has enough time to start,
         * wait few seconds before every attempt to access driver file
         */
        usleep(SLEEP_TIME);
     }
     /* All attemptes are failed */
     return false;
}

static int optee_keymaster_open(const hw_module_t* module,
                                const char* name,
                                hw_device_t** device) {
    using renesas::OpteeKeymasterDevice;
    bool created = false;

    ALOGI("Open Keymaster");

    if (strcmp(name, KEYSTORE_KEYMASTER) != 0) {
        ALOGE("Expected HAL name is %s, but was received %s",
              name, KEYSTORE_KEYMASTER);
        return android::BAD_VALUE;
    }
    /*
     * First use of OP-TEE driver can be earlier that than it starts
     * Before use check if driver is available
     */
    created = optee_check_drv();
    if (!created) {
        ALOGE("Time is out");
        return android::TIMED_OUT;
    }
    std::unique_ptr<OpteeKeymasterDevice> keymaster(
        new (std::nothrow) OpteeKeymasterDevice(module));
    if (!keymaster) {
        ALOGE("Failed to create Keymaster device, not enough memory");
        return android::NO_MEMORY;
    }
    if (!keymaster->connect()) {
        ALOGE("Failed to connect to keymaster device");
        return android::UNKNOWN_ERROR;
    }
    *device = (keymaster.release())->hw_device();
    return android::OK;
}

static struct hw_module_methods_t keymaster_module_methods = {
    .open = optee_keymaster_open,
};

struct keystore_module HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = KEYMASTER_MODULE_API_VERSION_2_0,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = KEYSTORE_HARDWARE_MODULE_ID,
        .name = "Salvator Keymaster HAL",
        .author = "Renesas Electronics",
        .methods = &keymaster_module_methods,
        .dso = 0,
        .reserved = {}
    },
};
