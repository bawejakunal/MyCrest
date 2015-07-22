top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
libdir = -L ${exec_prefix}/lib
INCLUDE = -I ${prefix}/include/pbc

LDFLAGS = -lgmp -lpbc -lm -lcrypto
CC = gcc
CFLAGS =  -O3 -Wunused-result -Wall
SOURCES= mainbgw.c bgw.c base64.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE= mainbgw


all : $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	      $(CC)  $(CFlAGS) $(INCLUDES) -o $@ $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC)  $(CFlAGS)  $(INCLUDE) $(libdir) $(LDFLAGS) -c $< -o $@


clean :
	 $(RM) *~  *.o mainbgw bgw 