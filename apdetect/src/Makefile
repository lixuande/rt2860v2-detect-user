OBJECTS = apdetect                                                                                                                       
 
all : $(OBJECTS)
 
PKG_NAME=docs
 
apdetect: main.o 
	$(CC) $(LDFLAGS) -std=c99 $^ -o $@
 
main.o:main.c
	$(CC) $(CFLAGS) -std=c99  -c $<
 
.PHONY:clean
clean:
	@-rm *.o apdetect 
