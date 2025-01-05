#ifndef CRYPTO_H_
#define CRYPTO_H_

#define CRYPTO_CIPHER GCRY_CIPHER_AES256
#define CRYPTO_CIPHERMODE GCRY_CIPHER_MODE_GCM
#define CRYPTO_HASH GCRY_MD_SHA512
#define CRYPTO_KEY_ID_LEN 8
#define CRYPTO_SALT_LEN 32
#define CRYPTO_KDF_DERIVE_METHOD GCRY_KDF_SCRYPT
#define CRYPTO_KDF_SUBALGO 65536 //In case of scrypt CPU/memory cost parameter N
#define CRYPTO_KDF_ITERATIONS 16 // In case of scrypt parallelization parameter p
#define CRYPTO_VERSION_IDENTIFIER "$1"
#define GCRYPT_NO_DEPRECATED

#define PROGRAM_NAME "custom-cryptd"
#define PROGRAM_VERSION "1.0"
#define PRGRAM_COPYRIGHT "(C) Copyright 2019, https://github.com/carnold85"

#include <gcrypt.h>
#include <string>
#include <vector>
#include <ctime>
#include <cstdint>

class crypto {
private:
	size_t keyLength, blkLength, hashLenght;
	std::vector<uint8_t> dataBuffer;
	std::string generateKeyIdFromData(std::vector<uint8_t>& data);
	bool withoutKeyFiles;
	std::vector<uint8_t*> keyHolder;
	std::vector<std::string> keyIdHolder;
	std::vector<uint64_t> encryptSuccess;
	std::vector<uint64_t> encryptFailure;
	std::vector<uint64_t> decryptSuccess;
	std::vector<uint64_t> decryptFailure;
	uint64_t numberOfConnections;
	uint64_t numberOfActiveConnections;
	uint64_t otherError;
	std::time_t startTime;
	std::string error;

	void setError(std::string errorPrefix, std::string scopeName, std::string functionName, std::string errorString, gcry_error_t gcryptError = 0, bool isFatal = false, bool logToSyslog = false);

public:
	crypto();
	bool initializeAES(void);
	bool generateAESKey(void);
	bool generateIv(std::vector<uint8_t>& randIv);
	bool encryptData(std::string& plainData, std::string& encryptedData, std::string clientName = "", bool keyDerivation = false, bool retry = false);
	bool decryptData(std::string& encryptedData, std::string& plainData, std::string clientName = "", bool keyDerivation = false);
	bool saveAESKeyToFile(std::string& filename, bool alwaysGenerateNewsKey = true);
	bool loadAESKeyFromFile(std::string filename);
	bool deriveKey(std::vector<uint8_t>& salt, std::vector<uint8_t>& key);
	bool addAESKeyToTruststore(std::vector<uint8_t>& data);
	std::string convertToHex(unsigned char *data, size_t len);
	void printStats(std::string& message);
	virtual ~crypto();

	uint64_t getNumberOfConnections(void) const {
		return numberOfConnections;
	}

	void incrementNumberOfConnections(void) {
		numberOfConnections++;
	}

	uint64_t getNumberOfActiveConnections(void) const {
		return numberOfActiveConnections;
	}

	void incrementNumberOfActiveConnections() {
		numberOfActiveConnections++;
	}

	void decrementNumberOfActiveConnections() {
		numberOfActiveConnections--;
	}

	const char* getLastError(void) {
		if(!error.empty()) {
			return (char*) error.c_str();
		} else {
			return "";
		}
	}

};

#endif /* CRYPTO_H_ */
