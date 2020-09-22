FLAGS = -Wall -std=c++11
CXX = g++
SRC = Hash-Attack.cpp
OBJ = $(SRC:.cpp = .o)
LIBS = -I/usr/local/Cellar/openssl@1.1/1.1.1g/include -L/usr/local/Cellar/openssl@1.1/1.1.1g/lib/ -lssl -lcrypto

Hash-Attack: $(OBJ)         
	$(CXX) $(FLAGS) -o Hash-Attack $(OBJ) $(LIBS)
	
clean:
	rm -f core *.o Hash-Attack
