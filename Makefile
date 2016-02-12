
CC = gcc
CFLAGS = -Wall -Os
LDLIBS = -ljpeg -lpthread
OBJECTS = main.o picture.o ve.o vejpeg.o
TARGET = jepocx

$(TARGET): $(OBJECTS)
	gcc -o $@ $^ $(LDLIBS)

clean:
	rm $(TARGET) $(OBJECTS)

