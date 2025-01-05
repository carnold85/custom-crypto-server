CXX = g++
CPPFLAGS = -O3 -Wall -Wextra -Werror \
		   -Wunused-parameter \
		   -Wformat-y2k -Wcast-align \
		   -Wconversion -Wformat-security \
		   -Wmissing-declarations \
		   -Wstrict-overflow \
		   -Wtrampolines \
		   -fmessage-length=0 \
		   -fno-common \
		   -fno-omit-frame-pointer \
		   -fstack-check \
		   -fstack-protector-all \
		   -mfunction-return=thunk \
		   -mindirect-branch=thunk \
		   -Wl,-z,nodlopen \
		   -Wl,-z,nodump \
		   -Wl,-z,noexecstack \
		   -Wl,-z,relro \
		   -Wl,-z,now \
		   -fPIC -fPIE \
		   -std=gnu++17 \
		   -g
CC = $(CXX)
CFLAGS = $(CPPFLAGS)
LDLIBS = -lgcrypt -lpthread -lb64 -lgpg-error

TARGET = custom-cryptd

CPP_SRCS = \
src/crypt/crypto.cpp \
src/network/Protocol.cpp \
src/network/ProtocolCrypto.cpp \
src/network/Socket.cpp \
src/custom-cryptd.cpp

OBJS = $(CPP_SRCS:%.cpp=%.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CPPFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

%.o : %.cpp
	$(CXX) $(CPPFLAGS) -D BUILD_OPTIONS='"$(CXX) $(CPPFLAGS)"' -c "$<" -o "$@"

.PHONY: clean

clean:
	$(RM) $(TARGET) $(OBJS)
