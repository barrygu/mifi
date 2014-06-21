LOC_TEST :=  true

CLI-SRCS := tcpClient.c tcpClient.h
SVR-SRCS := tcpServer.c tcpServer.h
COMMON-SRCS := tcpComm.c tcpComm.h linenoise.c linenoise.h queue.c queue.h

#SRCS := $(SVR-SRCS) $(CLI-SRCS) $(COMMON-SRCS)

#过滤出所有的.c文件，并将.c替换为.o
CLI-OBJS := $(patsubst %.c,%.o,$(filter %.c,$(CLI-SRCS)))
SVR-OBJS := $(patsubst %.c,%.o,$(filter %.c,$(SVR-SRCS)))
COMMON-OBJS := $(patsubst %.c,%.o,$(filter %.c,$(COMMON-SRCS)))

#OBJS := $(SVR-OBJS) $(CLI-OBJS) $(COMMON-OBJS)

CC := gcc

all: svr cli

ifeq ($(strip $(LOC_TEST)),true)
CFLAGS += -DLOCAL_TEST
endif

CFLAGS += -DDEBUG
CFLAGS += -Wall -g
LDFLAGS = -Wall -g -pthread

.PHONY: test
test:
	@echo SVR-SRCS: $(SVR-SRCS) 
	@echo CLI-SRCS: $(CLI-SRCS) 
	@echo COMMON-SRCS: $(COMMON-SRCS)
#	@echo SRCS: $(SRCS)

	@echo

	@echo SVR-OBJS: $(SVR-OBJS) 
	@echo CLI-OBJS: $(CLI-OBJS) 
	@echo COMMON-OBJS: $(COMMON-OBJS)
#	@echo OBJS: $(OBJS) 

cli: $(CLI-OBJS) $(COMMON-OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

svr: $(SVR-OBJS) $(COMMON-OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

#$(OBJS): %.o: %.c tcpComm.h
#$(OBJS): %.o: %.c $(filter %.h,$(COMMON-SRCS))
#	$(CC) $(CFLAGS) -c -o $@ $<

$(CLI-OBJS): %.o: %.c $(filter %.h,$(CLI-SRCS) $(COMMON-SRCS))
$(SVR-OBJS): %.o: %.c $(filter %.h,$(SVR-SRCS) $(COMMON-SRCS))
$(COMM-OBJS): %.o: %.c $(filter %.h,$(COMMON-SRCS))
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	-rm -f svr cli *.o *~
