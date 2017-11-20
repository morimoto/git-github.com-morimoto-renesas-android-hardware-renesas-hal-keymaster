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

LOCAL_MODULE := keystore.$(TARGET_PRODUCT)
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

LOCAL_CFLAGS = -Wall -Werror
LOCAL_CFLAGS += -DANDROID_BUILD

LOCAL_SRC_FILES := \
	module.cpp \
	optee_keymaster.cpp \
	optee_keymaster_ipc.c

LOCAL_C_INCLUDES := \
	hardware/renesas/optee-client/public \
	$(LOCAL_PATH)/ta/include

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libteec \
	liblog

include $(BUILD_SHARED_LIBRARY)

################################################################################
# Build keymaster HAL TA                                                       #
################################################################################

include $(TARGET_DEVICE_DIR)/build/ta_clear_vars.mk
# Please keep this variable consistent with TA_KEYMASTER_UUID define that
# defined in ta/include/common.h file
TA_UUID:=dba51a17-0563-11e7-93b16fa7b0071a51
TA_SRC:=$(LOCAL_PATH)/ta

include $(TARGET_DEVICE_DIR)/build/ta_build_executable.mk
endif # Include only for Renesas ones.
