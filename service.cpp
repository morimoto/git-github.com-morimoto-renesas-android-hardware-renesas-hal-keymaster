/*
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

#define LOG_TAG "KeymasterHAL"

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>

#include <hidl/HidlTransportSupport.h>
#include <hidl/LegacySupport.h>
#include <android-base/logging.h>

#include "optee_keymaster.h"

using ::android::hardware::configureRpcThreadpool;
using ::android::hardware::joinRpcThreadpool;
using ::android::hardware::keymaster::V3_0::IKeymasterDevice;
using ::android::hardware::keymaster::V3_0::renesas::OpteeKeymasterDevice;
using ::android::OK;
using ::android::sp;

int main() {
    ALOGI("Loading...");
    sp<IKeymasterDevice> keymaster = new (std::nothrow) OpteeKeymasterDevice;
    CHECK_EQ((keymaster != nullptr), true) <<
        "Failed to allocate OpteeKeymasterDevice instance.";

    configureRpcThreadpool(1, true);

    android::status_t status = keymaster->registerAsService();
    CHECK_EQ(status, android::OK) <<
        "Failed to register IKeymasterDevice interface.";

    joinRpcThreadpool();
}
