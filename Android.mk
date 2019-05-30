#
# Copyright (C) 2019 GlobalLogic
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Include only for Renesas ones.
ifneq (,$(filter $(TARGET_PRODUCT), salvator ulcb kingfisher))

LOCAL_PATH := $(call my-dir)
TA_KEYMASTER_SRC     := $(LOCAL_PATH)/ta
TA_KEYMASTER_UUID    := dba51a17-0563-11e7-93b16fa7b0071a51

################################################################################
# Build keymaster HAL                                                          #
################################################################################
include $(CLEAR_VARS)

LOCAL_MODULE                := android.hardware.keymaster@3.0-service.renesas
LOCAL_INIT_RC               := android.hardware.keymaster@3.0-service.renesas.rc
LOCAL_VINTF_FRAGMENTS       := android.hardware.keymaster@3.0-service.renesas.xml
LOCAL_MODULE_RELATIVE_PATH  := hw
LOCAL_MODULE_TAGS           := optional
LOCAL_PROPRIETARY_MODULE    := true
LOCAL_REQUIRED_MODULES      := $(TA_KEYMASTER_UUID)
LOCAL_CFLAGS                += -DANDROID_BUILD

LOCAL_SRC_FILES := \
    service.cpp \
    optee_keymaster.cpp \
    optee_keymaster_ipc.c

LOCAL_C_INCLUDES := \
    vendor/renesas/utils/optee-client/public \
    $(TA_KEYMASTER_SRC)/include

LOCAL_SHARED_LIBRARIES := \
    libteec \
    liblog \
    libbase \
    libhidlbase \
    libhidltransport \
    libhardware \
    libutils \
    libcutils \
    android.hardware.keymaster@3.0

include $(BUILD_EXECUTABLE)

################################################################################
# Build keymaster HAL TA                                                       #
################################################################################

# Please keep this variable consistent with TA_KEYMASTER_UUID define that
# defined in ta/include/common.h file
TA_KEYMASTER_OBJ            = $(PRODUCT_OUT)/obj/TA_OBJ/$(TA_KEYMASTER_UUID)
TA_KEYMASTER_OUT            = $(abspath $(TA_KEYMASTER_OBJ))
TA_KEYMASTER_BINARY         = $(TA_KEYMASTER_OBJ)/$(TA_KEYMASTER_UUID).ta
# OP-TEE Trusted OS is dependency for TA
OPTEE_BINARY                = $(PRODUCT_OUT)/obj/OPTEE_OBJ/core/tee.bin
OPTEE_TA_DEV_KIT_DIR        = $(abspath $(PRODUCT_OUT)/obj/OPTEE_OBJ/export-ta_arm64)

$(TA_KEYMASTER_BINARY): $(OPTEE_BINARY)
	mkdir -p $(TA_KEYMASTER_OUT)
	CROSS_COMPILE=$(BSP_GCC_CROSS_COMPILE) BINARY=$(TA_KEYMASTER_UUID) TA_DEV_KIT_DIR=$(OPTEE_TA_DEV_KIT_DIR) $(ANDROID_MAKE) -C $(TA_KEYMASTER_SRC) O=$(TA_KEYMASTER_OUT) clean
	CROSS_COMPILE=$(BSP_GCC_CROSS_COMPILE) BINARY=$(TA_KEYMASTER_UUID) TA_DEV_KIT_DIR=$(OPTEE_TA_DEV_KIT_DIR) $(ANDROID_MAKE) -C $(TA_KEYMASTER_SRC) O=$(TA_KEYMASTER_OUT) all

include $(CLEAR_VARS)
LOCAL_MODULE                := $(TA_KEYMASTER_UUID)
LOCAL_MODULE_STEM           := $(TA_KEYMASTER_UUID).ta
LOCAL_PREBUILT_MODULE_FILE  := $(TA_KEYMASTER_BINARY)
LOCAL_MODULE_PATH           := $(TARGET_OUT_VENDOR_SHARED_LIBRARIES)/optee_armtz/
LOCAL_MODULE_CLASS          := EXECUTABLES
include $(BUILD_PREBUILT)

$(LOCAL_BUILT_MODULE): $(TA_KEYMASTER_BINARY)

endif # Include only for Renesas ones.
