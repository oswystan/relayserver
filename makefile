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

prog_dtls := dtls
prog_main := a.out
bin       := $(prog_dtls) $(prog_main)
cert      := cacert.pem cakey.pem
ld_flags  := -lssl -lcrypto -ldl

all: $(bin) $(cert)

$(prog_main): main.o
	@gcc $^ -o $@ $(ld_flags)
	@echo "[gen] "$@
$(prog_dtls): dtls.o
	@gcc $^ -o $@ $(ld_flags)
	@echo "[gen] "$@
%.o:%.c
	@echo "[ cc] "$@
	@gcc -c -g $< -o $@
%.o:%.cpp
	@echo "[cpp] "$@
	@g++ -c $< -o $@
$(cert):
	@openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout $(word 2,$(cert)) -out $(word 1,$(cert)) \
		-subj /C=CN/ST=BJ/L=Beijing/O=TAL/OU=LiveCloud/CN=wystan/emailAddress=wystan@china.com \
		> /dev/null 2>&1
	@echo "[gen]" $(cert)

clean:
	@echo "cleaning..."
	@rm -f *.o $(bin) $(cert)
	@echo "done."

#######################################################################
