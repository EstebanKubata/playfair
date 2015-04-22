UNAME := $(shell uname -s)
ifeq ($(UNAME),Linux)
   LIBS=-ldns_sd -L/opt/vc/src/hello_pi/libs/ilclient -L/opt/vc/lib/ -lbcm_host -lvcos -lvchiq_arm -lilclient -lopenmaxil
   CFLAGS+="-DHAVE_OPENMAX -DSTANDALONE -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -DTARGET_POSIX -D_LINUX -fPIC -DPIC -D_REENTRANT -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -Wall -g -DHAVE_LIBOPENMAX=2 -DOMX -DOMX_SKIP64BIT -ftree-vectorize -pipe -DUSE_EXTERNAL_OMX -DHAVE_LIBBCM_HOST -DUSE_EXTERNAL_LIBBCM_HOST -DUSE_VCHIQ_ARM -Wno-psabi"
endif


%.o:		%.c
		gcc $(CFLAGS) -std=c99 -fgnu89-inline -Wno-deprecated-declarations -I/opt/vc/include -I/opt/vc/include/interface/vcos/pthreads -I/opt/vc/include/interface/vmcs_host/linux -I/opt/vc/src/hello_pi/libs/ilclient -I/opt/local/include -c $< -o $@

playfair:	modified_md5.o bplist.o sap_hash.o hand_garble.o mirror_http.o omghax.o
		gcc -std=c99 -Wno-deprecated-declarations $^ -o playfair -lcrypto -lpthread -lm $(LIBS)

testing:	modified_md5.o bplist.o sap_hash.o hand_garble.o playfair.o omghax.o
		gcc -std=c99 -Wno-deprecated-declarations $^ -o testing -lcrypto -lpthread -lm $(LIBS)

clean:
		rm -f *.o
		rm -f playfair
		rm -f testing
