#
# Copyright (C) 2017 GlobalLogic
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
LOCAL_PATH:= $(call my-dir)

################################################################################
# Build keymaster HAL                                                          #
################################################################################
include $(CLEAR_VARS)

LOCAL_MODULE := android.hardware.keymaster@3.0-service.renesas
LOCAL_INIT_RC := android.hardware.keymaster@3.0-service.renesas.rc
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_MODULE_TAGS := optional
LOCAL_PROPRIETARY_MODULE := true
LOCAL_REQUIRED_MODULES := dba51a17-0563-11e7-93b16fa7b0071a51.ta
LOCAL_CFLAGS = -Wall -Werror
LOCAL_CFLAGS += -DANDROID_BUILD

LOCAL_SRC_FILES := \
	service.cpp \
	optee_keymaster.cpp \
	optee_keymaster_ipc.c

LOCAL_C_INCLUDES := \
	vendor/renesas/utils/optee-client/public \
	$(LOCAL_PATH)/ta/include

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
TA_KEYMASTER_UUID := dba51a17-0563-11e7-93b16fa7b0071a51
TA_KEYMASTER_SRC := $(LOCAL_PATH)/ta

TA_KEYMASTER_OUT := $(TA_OUT_INTERMEDIATES)/$(TA_KEYMASTER_UUID)_OBJ

TA_KEYMASTER_TARGET := $(TA_KEYMASTER_UUID)_ta

# OP-TEE Trusted OS is dependency for TA
.PHONY: TA_OUT_$(TA_KEYMASTER_UUID)
TA_OUT_$(TA_KEYMASTER_UUID): tee.bin
	mkdir -p $(TA_KEYMASTER_OUT)
	mkdir -p $(TARGET_OUT_VENDOR_SHARED_LIBRARIES)/optee_armtz

.PHONY: $(TA_KEYMASTER_TARGET)
$(TA_KEYMASTER_TARGET): TA_OUT_$(TA_KEYMASTER_UUID)
	CROSS_COMPILE=$(OPTEE_CROSS_COMPILE) BINARY=$(TA_KEYMASTER_UUID) TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) make -C $(TA_KEYMASTER_SRC) O=$(TA_KEYMASTER_OUT) clean
	CROSS_COMPILE=$(OPTEE_CROSS_COMPILE) BINARY=$(TA_KEYMASTER_UUID) TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) make -C $(TA_KEYMASTER_SRC) O=$(TA_KEYMASTER_OUT) all

.PHONY: $(TA_KEYMASTER_UUID).ta
$(TA_KEYMASTER_UUID).ta: $(TA_KEYMASTER_TARGET)
	cp $(TA_KEYMASTER_OUT)/$@ $(TARGET_OUT_VENDOR_SHARED_LIBRARIES)/optee_armtz/$@

endif # Include only for Renesas ones.
