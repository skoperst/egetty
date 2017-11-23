#egetty
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := egetty.c
LOCAL_SRC_FILES += skbuff.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/

LOCAL_MODULE:= egetty

include $(BUILD_EXECUTABLE)


#econsole
include $(CLEAR_VARS)

LOCAL_SRC_FILES := econsole.c
LOCAL_SRC_FILES += skbuff.c
LOCAL_SRC_FILES += jelopt.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/
LOCAL_MODULE:= econsole
include $(BUILD_EXECUTABLE)
