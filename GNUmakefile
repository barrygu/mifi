LOC_TEST :=  true

CLI-SRCS := tcpClient.c tcpClient.h 
SVR-SRCS := tcpServer.c tcpServer.h
COMMON-SRCS := tcpComm.c tcpComm.h
LIB-SRCS := queue.c queue.h linenoise.c linenoise.h

CLI-OBJS := $(patsubst %.c,%.o,$(filter %.c,$(CLI-SRCS)))
SVR-OBJS := $(patsubst %.c,%.o,$(filter %.c,$(SVR-SRCS)))
COMMON-OBJS := $(patsubst %.c,%.o,$(filter %.c,$(COMMON-SRCS)))
LIB-OBJS := $(patsubst %.c,%.o,$(filter %.c,$(LIB-SRCS)))

LIB_NAME := mifi
EXE_EXT  :=

OST:=$(shell echo $$OSTYPE)
ifeq ($(OST),cygwin)
LIB_EXT := .dll
EXE_EXT := .exe
else
LIB_EXT := .so
endif

LIB_MIFI := lib$(LIB_NAME)
TARGET_SVR := svr$(EXE_EXT)
TARGET_CLI := cli$(EXE_EXT)

CC := gcc

all: $(LIB_MIFI) $(TARGET_SVR) $(TARGET_CLI)

ifeq ($(strip $(LOC_TEST)),true)
CFLAGS += -DLOCAL_TEST
endif

CFLAGS += -DDEBUG
CFLAGS += -Wall -g
ifeq ($(OST),linux-gnu)
CFLAGS += -fPIC
endif

LDFLAGS = -g -L. -pthread

.PHONY: test
test:
	@echo SVR-SRCS: $(SVR-SRCS) 
	@echo CLI-SRCS: $(CLI-SRCS) 
	@echo COMMON-SRCS: $(COMMON-SRCS)
	@echo OSTYPE: \"$(OST)\"
	@echo LIB: $(LIB_MIFI)$(LIB_EXT)

	@echo

	@echo SVR-OBJS: $(SVR-OBJS) 
	@echo CLI-OBJS: $(CLI-OBJS) 
	@echo COMMON-OBJS: $(COMMON-OBJS)

$(LIB_MIFI): $(LIB-OBJS)
	$(CC) -shared -Wl,-soname,$@$(LIB_EXT) -o $@$(LIB_EXT) $(LIB-OBJS)

$(TARGET_CLI): $(CLI-OBJS) $(COMMON-OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ -l$(LIB_NAME)

$(TARGET_SVR): $(SVR-OBJS) $(COMMON-OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ -l$(LIB_NAME)

$(CLI-OBJS): %.o: %.c $(filter %.h,$(CLI-SRCS) $(COMMON-SRCS))
$(SVR-OBJS): %.o: %.c $(filter %.h,$(SVR-SRCS) $(COMMON-SRCS))
$(COMM-OBJS): %.o: %.c $(filter %.h,$(COMMON-SRCS))
$(LIB-OBJS): %.o: %.c $(filter %.h,$(LIB-SRCS))
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	-rm -f $(TARGET_SVR) $(TARGET_CLI) *.o *~ *$(LIB_EXT)
