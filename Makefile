EXEC_NAME = mitm
OBJ_FILES = main.o
 
INCLUDES = -I.
LIBS = -lpthread -lm -lrt -losdep
LIBS_DIR = -L. -Losdep/
CC = gcc
CFLAGS = -Wall -O2
 
all : $(EXEC_NAME)

install: $(EXEC_NAME)
	@cp mitm /usr/sbin/
	@cp man/mitm.1.gz /usr/share/man/man1/
 
clean :
	@rm $(EXEC_NAME) $(OBJ_FILES) *~
	@echo "Cleaning OK"

$(EXEC_NAME) : $(OBJ_FILES) osdep/libosdep.a
	@$(CC) -O3 -o $(EXEC_NAME) $(OBJ_FILES) $(LIBS_DIR) $(INCLUDES) $(LIBS)
	@strip $(EXEC_NAME)
	@echo "Compiled"

osdep/libosdep.a: 
	@make -C osdep
 
%.o: %.cpp
	@g++ $(CFLAGS) $(LIBS_DIR) $(INCLUDES) -o $@ -c $<
	@echo "Compiling $<..."
