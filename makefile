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
prog_stun := stunsrv
prog_x509 := x509
bin       := $(prog_dtls) $(prog_main) $(prog_srtp) $(prog_stun) $(prog_x509)
cert      := cacert.pem cakey.pem
cflags 	  := -I./thirdparty/srtp/include
ld_flags  := -L./thirdparty/srtp/lib -lssl -lcrypto -ldl -lsrtp2 -lz
h         := $(if $(filter 1,$V),,@)

all: $(bin) $(cert)

$(prog_main): main.o stun.o bio.o
	$(h) g++ $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
$(prog_dtls): dtls.o bio.o
	$(h) g++ $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
$(prog_srtp): srtp.o
	$(h) g++ $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
$(prog_stun): stunsrv.o stun.o
	$(h) g++ $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
$(prog_x509): x509.c
	$(h) gcc $^ -o $@ $(ld_flags)
	@ echo "[gen] "$@
%.o:%.c
	$(h) g++ -c -g $(cflags) $< -o $@
	@ echo "[ cc] "$@
%.o:%.cpp
	$(h) g++ -c -g $(cflags) $< -o $@
	@ echo "[cpp] "$@
$(cert):
	$(h) openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout $(word 2,$(cert)) -out $(word 1,$(cert)) \
		-subj /C=CN/ST=BJ/L=Beijing/O=TAL/OU=LiveCloud/CN=wystan/emailAddress=wystan@china.com \
		> /dev/null 2>&1
	@ echo "[gen]" $(cert)

clean:
	@echo "cleaning..."
	$(h) rm -f *.o $(bin) 
	@echo "done."

#######################################################################
