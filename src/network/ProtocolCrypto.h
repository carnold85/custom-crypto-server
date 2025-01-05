#ifndef THORSANVIL_SOCKET_PROTOCOL_CRYPPTO_H
#define THORSANVIL_SOCKET_PROTOCOL_CRYPTO_H

#include "Protocol.h"
#include "../crypt/crypto.h"

namespace ThorsAnvil {
namespace Socket {

class ProtocolCrypto: public Protocol {
public:
	using Protocol::Protocol;
	bool cryptoGreeting(void);
	void processRequests(crypto& Server);
	//ProtocolCrypto();
	ProtocolCrypto();

	std::string getClientName(void) const {
		return clientName;
	}

private:
	void sendMessage(std::string const& message) override;
	void recvMessage(std::string& message) override;
	void recvMessageUntilNewline(std::string& message);
	void recvMessageUntilDotNewline(std::string& message);
	std::string clientName;
};

}
}

#endif
