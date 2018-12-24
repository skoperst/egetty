LOCAL_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
LOCAL_DIR := $(LOCAL_DIR:%/=%)


ifndef TARGET_DIR
TARGET_DIR := $(LOCAL_DIR)/out
$(shell mkdir -p $(TARGET_DIR))
$(shell mkdir -p $(TARGET_DIR)/bin)
endif

OUTPUT_DIR := $(TARGET_DIR)

CC=gcc
CFLAGS+= -Wall 
LDLIBS+=-lutil

all:	econsole egetty


econsole: C_FILES := $(LOCAL_DIR)/econsole.c
econsole: C_FILES += $(LOCAL_DIR)/skbuff.c
econsole: C_FILES += $(LOCAL_DIR)/jelopt.c

econsole:
	$(CC) $(CFLAGS) $(LDFLAGS) $(C_FILES) $(C_INCLUDES) -o $(OUTPUT_DIR)/bin/econsole $(LDLIBS)
	
	
egetty:	C_FILES := $(LOCAL_DIR)/egetty.c
egetty: C_FILES += $(LOCAL_DIR)/skbuff.c
egetty:
	$(CC) $(CFLAGS) $(LDFLAGS) $(C_FILES) $(C_INCLUDES) -o $(OUTPUT_DIR)/bin/egetty $(LDLIBS)

test: C_FILES := $(LOCAL_DIR)/test.c
test:
	$(CC) $(CFLAGS) $(C_FILES) $(C_INCLUDES) -o $(OUTPUT_DIR)/bin/test 
	
clean:	
	rm -f *.o econsole egetty

.PHONY: install
install:
	install -m 0755 $(OUTPUT_DIR)/bin/econsole /usr/local/bin/
