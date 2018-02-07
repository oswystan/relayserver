#######################################################################
##                     Copyright (C) 2017 wystan
##
##       filename: makefile
##    description:
##        created: 2017-07-06 11:42:13
##         author: wystan
##
#######################################################################
.PHONY: all clean

bin := main
src := $(wildcard *.c *.cpp)
obj := $(src:.c=.o)
obj := $(obj:.cpp=.o)
ld_flags := -static

all: $(bin)

$(bin): $(obj)
	@gcc $^ -o $(bin) $(ld_flags)
	@strip $@
	@echo "[gen] "$@
%.o:%.c
	@echo "[ cc] "$@
	@gcc -c $< -o $@
%.o:%.cpp
	@echo "[cpp] "$@
	@g++ -c $< -o $@

clean:
	@echo "cleaning..."
	@rm -f *.o $(bin)
	@echo "done."
key:
	@./genkey

#######################################################################
