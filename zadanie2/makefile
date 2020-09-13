CC	 = g++
CXXFLAGS = -Wall -O2 -Wextra
TARGETS  = radio-proxy

all: $(TARGETS) 

radio-proxy.o: radio-proxy.cpp

radio-proxy: radio-proxy.o
	$(CC) $(CFLAGS) $^ -lpthread -o $@

.PHONY: clean
clean:
	rm -f *.o *~ $(TARGETS) 
