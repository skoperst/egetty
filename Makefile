LOCAL_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
LOCAL_DIR := $(LOCAL_DIR:%/=%)


ifndef TARGET_DIR
TARGET_DIR := $(LOCAL_DIR)/out
$(shell mkdir -p $(TARGET_DIR))
endif

OUTPUT_DIR := $(TARGET_DIR)

CC=gcc
CFLAGS+=-Os -Wall
LDFLAGS+=-static
LDLIBS+=-lutil

all:	econsole egetty


econsole: C_FILES := $(LOCAL_DIR)/econsole.c
econsole: C_FILES += $(LOCAL_DIR)/skbuff.c
econsole: C_FILES += $(LOCAL_DIR)/jelopt.c

econsole:
	$(CC) $(CFLAGS) $(LDFLAGS) $(C_FILES) $(C_INCLUDES) -o $(OUTPUT_DIR)/econsole $(LDLIBS)
	
	
egetty:	C_FILES := $(LOCAL_DIR)/egetty.c
egetty: C_FILES += $(LOCAL_DIR)/skbuff.c
egetty:
	$(CC) $(CFLAGS) $(LDFLAGS) $(C_FILES) $(C_INCLUDES) -o $(OUTPUT_DIR)/egetty $(LDLIBS)
	
clean:	
	rm -f *.o econsole egetty
