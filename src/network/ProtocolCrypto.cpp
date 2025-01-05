#include "ProtocolCrypto.h"
#include "Socket.h"
#include <iostream>
#include <syslog.h>

using namespace ThorsAnvil::Socket;

void ProtocolCrypto::sendMessage(std::string const& message) {
	socket.putMessageData(message.c_str(), message.size());
}

void ProtocolCrypto::recvMessage(std::string& message) {
	std::size_t dataRead = 0;
	message.resize(256);
	std::fill(message.begin(),message.end(), '\0');

	while (true) {
		std::size_t const dataMax = message.capacity() - 1;
		char* buffer = &message[0];

		std::size_t got = socket.getMessageData(buffer + dataRead,
				dataMax - dataRead, [](std::size_t) {return false;});
		dataRead += got;
		if (got == 0) {
			break;
		}
	}
}

void ProtocolCrypto::recvMessageUntilNewline(std::string& message) {
	std::size_t dataRead = 0;
	std::fill(message.begin(),message.end(), '\0');
	message.resize(256);
	char* buffer = &message[0];
	std::size_t getBytes = socket.getMessageData(buffer, message.size(),
			[buffer](std::size_t bytesReadSoFar) {
				std::string tmp(buffer);
				if(tmp.find("\n")!=std::string::npos) {
					return true;
				} else if(tmp.find("\r\n")!=std::string::npos) {
					return true;
				}
				if(bytesReadSoFar >0) {
					//nothing
				}
				return false;
			});
	dataRead += getBytes;
}

void ProtocolCrypto::recvMessageUntilDotNewline(std::string& message) {
	std::size_t dataRead = 0;
	std::fill(message.begin(),message.end(), '\0');
	message.resize(10240);
	bool dotFound = false;

	while (!dotFound) {
		message.resize(message.capacity());
		char* buffer = &message[0];
		std::size_t getBytes = socket.getMessageData(buffer + dataRead, message.size() - dataRead, [buffer, &message, &dotFound, &dataRead](std::size_t bytesReadSoFar) {
							std::string tmp(buffer);
							if(tmp.find("\r\n.\r\n")!=std::string::npos) {
								dotFound = true;
								return true;
							} else if(tmp.find("\n.\n")!=std::string::npos) {
								dotFound = true;
								return true;
							}
							if(bytesReadSoFar >0) {
								//nothing
							}
							return false;
						});
		dataRead += getBytes;
		if (getBytes == 0) {
			break;
		}
		if (!dotFound && dataRead == message.size()) {
			message.resize(message.size() * 2);
		}
	}
}

bool ProtocolCrypto::cryptoGreeting() {
	std::string greeting;
	try {
		// Greeting has to met CSP (Crypto Server Protocol)
		sendMessage("220 CSP/1.0 Custom Crypto Server\r\n");
		recvMessageUntilNewline(greeting);
		if (greeting.find("EHLO CSP/1.0 ") == 0) {
			size_t pos = 0;
			if ((pos = greeting.find("\r\n")) != std::string::npos) {
				greeting.replace(pos, greeting.length(), "");
			}
			clientName = greeting.substr(13);
			sendMessage("250 OK\r\n");
			return true;
		} else if (greeting.find("EHLO CSP/1.0") == 0) {
			sendMessage("501 Missing argument to HELO command\r\n");
			socket.putMessageClose();
			return false;
		} else if (greeting.find("EHLO ") == 0) {
			sendMessage("554 Unable to speak your dialect\r\n");
			socket.putMessageClose();
			return false;
		} else if (greeting.find("EHLO") == 0) {
			sendMessage("501 Missing argument to EHLO command\r\n");
			socket.putMessageClose();
			return false;
		} else {
			sendMessage("421 What the hell is wrong with you? Speak my language!\r\n");
			socket.putMessageClose();
			return false;
		}
	} catch (const std::runtime_error& error) {
		syslog(LOG_ERR, std::string(clientName + ": Newtowrk error: %s").c_str(), error.what());
		return false;
	} catch (const std::exception& error) {
		return false;
	}
	return false;
}

void ProtocolCrypto::processRequests(crypto& cryoptServer) {
	std::string command;
	std::string data;
	std::string cryptoOutput;
	size_t pos = 0;
	try {
		while (true) {
			recvMessageUntilNewline(command);
			if (command.find("ENCRYPT ") == 0) {
				sendMessage("501 Too many arguments\r\n");
			} else if (command.find("DECRYPT ") == 0) {
				sendMessage("501 Too many arguments\r\n");
			} else if (command.find("ENCRYPT") == 0) {
				sendMessage("354 Send data.\r\n");
				recvMessageUntilDotNewline(data);
				pos = 0;
				syslog(LOG_NOTICE, "%s", std::string(clientName + ": Starting encryption").c_str());
				if ((pos = data.find("\r\n.\r\n")) != std::string::npos) {
					data.replace(pos, data.length(), "");
				} else if ((pos = data.find("\n.\n")) != std::string::npos) {
					data.replace(pos, data.length(), "");
				}
				if (!cryoptServer.encryptData(data, cryptoOutput, clientName)) {
					syslog(LOG_ERR, "%s", std::string(clientName + ": Encrypt failed").c_str());
					sendMessage("501 Illegal ciphertext.\r\n");
					std::fill(cryptoOutput.begin(),cryptoOutput.end(), 0);
					std::fill(data.begin(),data.end(), 0);
				} else {
					if ((pos = cryptoOutput.rfind("\n")) != std::string::npos) {
						cryptoOutput.replace(pos, cryptoOutput.length(), "");
					}
					syslog(LOG_NOTICE, "%s", std::string(clientName + ": Encrypt successful").c_str());
					sendMessage("537 OK, data follows\r\n");
					sendMessage(cryptoOutput);
					sendMessage("\r\n.\r\n");
					std::fill(cryptoOutput.begin(),cryptoOutput.end(), 0);
					std::fill(data.begin(),data.end(), 0);
				}
			} else if (command.find("DECRYPT") == 0) {
				sendMessage("354 Send data.\r\n");
				recvMessageUntilDotNewline(data);
				pos = 0;
				syslog(LOG_NOTICE, "%s", std::string(clientName + ": Starting decryption").c_str());
				if ((pos = data.find("\r\n.\r\n")) != std::string::npos) {
					data.replace(pos, data.length(), "");
				} else if ((pos = data.find("\n.\n")) != std::string::npos) {
					data.replace(pos, data.length(), "");
				}
				if (!cryoptServer.decryptData(data, cryptoOutput, clientName)) {
					syslog(LOG_ERR, "%s", std::string(clientName + ": Decrypt failed").c_str());
					sendMessage("501 Illegal ciphertext.\r\n");
					std::fill(cryptoOutput.begin(),cryptoOutput.end(), 0);
					std::fill(data.begin(),data.end(), 0);
				} else {
					syslog(LOG_NOTICE, "%s", std::string(clientName + ": Decrypt successful").c_str());
					sendMessage("537 OK, data follows\r\n");
					sendMessage(cryptoOutput);
					sendMessage("\r\n.\r\n");
					std::fill(cryptoOutput.begin(),cryptoOutput.end(), 0);
					std::fill(data.begin(),data.end(), 0);
				}
			} else if (command.find("STATS") == 0) {
				cryoptServer.printStats(cryptoOutput);
				sendMessage(cryptoOutput);
			} else if (command.find("QUIT") == 0) {
				sendMessage("421 Have a nice day\r\n");
				socket.putMessageClose();
				return;
			} else if (command.find("quit") == 0) {
				sendMessage("421 Have a nice day\r\n");
				socket.putMessageClose();
				return;
			} else if (command[0] == '\0') {
				return;
			} else if (command.find("\r\n") == 0 || command.find("\n") == 0) {
				socket.putMessageClose();
				return;
			} else {
				syslog(LOG_ERR, "%s", std::string(clientName + ": Wrong/unkown command").c_str());
				sendMessage("500 Command not recognized\r\n");
			}
		}
	} catch (const std::runtime_error& error) {
		syslog(LOG_ERR, std::string(clientName + ": Newtowrk error: %s").c_str(), error.what());
		return;
	} catch (const std::exception& error) {
		syslog(LOG_ERR, std::string(clientName + ": Exception error: %s").c_str(), error.what());
		return;
	}
	return;
}
