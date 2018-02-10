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
prog_srtp := srtp
bin       := $(prog_dtls) $(prog_main) $(prog_srtp)
cert      := cacert.pem cakey.pem
cflags 	  := -I./thirdparty/srtp/include
ld_flags  := -L./thirdparty/srtp/lib -lssl -lcrypto -ldl -lsrtp2
h         := $(if $(filter 1,$V),,@)

all: $(bin) $(cert)

$(prog_main): main.o
	$(h) gcc $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
$(prog_dtls): dtls.o
	$(h) gcc $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
$(prog_srtp): srtp.o
	$(h) gcc $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
%.o:%.c
	$(h) gcc -c -g $(cflags) $< -o $@
	@ echo "[ cc] "$@
%.o:%.cpp
	$(h) g++ -c $< -o $@
	@ echo "[cpp] "$@
$(cert):
	$(h) openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout $(word 2,$(cert)) -out $(word 1,$(cert)) \
		-subj /C=CN/ST=BJ/L=Beijing/O=TAL/OU=LiveCloud/CN=wystan/emailAddress=wystan@china.com \
		> /dev/null 2>&1
	@ echo "[gen]" $(cert)

clean:
	@echo "cleaning..."
	$(h) rm -f *.o $(bin) $(cert)
	@echo "done."

#######################################################################
