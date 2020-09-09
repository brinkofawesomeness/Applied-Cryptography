FLAGS = -Wall -std=c++11
CXX = g++
SRC = AES-Worker.cpp AES.cpp Tests/AES-Unit-Tests.cpp
OBJ = $(SRC:.cpp = .o)

AES-Worker: $(OBJ)         
	$(CXX) $(FLAGS) -o AES-Worker $(OBJ) 
	
clean:
	rm -f core *.o AES-Worker