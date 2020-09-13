CC	= gcc
CFLAGS	= -Wall -O2
LFLAGS	= -Wall
TARGETS = testhttp_raw

all: $(TARGETS) 

testhttp_raw.o: testhttp_raw.c

testhttp_raw: testhttp_raw.o

clean:
	rm -f *.o *~ $(TARGETS) 
