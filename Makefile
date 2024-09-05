CC=gcc

SOURCE_FILES = exploit.c util.c perf.c stage1.c stage2.c stage3.c race_util.c
OBJ_FILES = $(patsubst %.c,%.o,$(SOURCE_FILES))

CFLAGS = -static -pthread
COBJFLAGS = $(CFLAGS) -c
LDFLAGS = 
EXEC_NAME = exploit

%.o: %.c
	$(CC) $^ $(COBJFLAGS) -o $@

$(EXEC_NAME): $(OBJ_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

run: $(EXEC_NAME)
	cp $(EXEC_NAME) ./basic_linux_env/host/exploit
	cd ./basic_linux_env && ./run_qemu.sh

clean:
	rm ./*.o
	rm $(EXEC_NAME)