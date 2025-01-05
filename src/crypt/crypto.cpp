#include "crypto.h"
#include <b64/encode.h>
#include <b64/decode.h>
#include <sstream>
#include <vector>
#include <fstream>
#include <termios.h>
#include <unistd.h>
#include <algorithm>
#include <syslog.h>
#include <chrono>
#include <ctime>
#include <thread>
#include <mutex>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

crypto::crypto() {
	keyLength = 0;
	blkLength = 0;
	hashLenght = 0;
	withoutKeyFiles = true;
	numberOfConnections = 0;
	numberOfActiveConnections = 0;
	otherError = 0;
	startTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	gcry_error_t err;

	if (!gcry_check_version(GCRYPT_VERSION)) {
		setError("", "GCRYPT", __func__, "Version mismatch", 0, true, true);
		std::cerr << getLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	err = gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);
	if (err != GPG_ERR_NO_ERROR) {
		setError("", "GCRYPT", __func__, "Cannot set control param GCRYCTL_USE_SECURE_RNDPOOL", err, true, true);
		std::cerr << getLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	/* We don’t want to see any warnings, e.g. because we have not yet
	 parsed program options which might be used to suppress such
	 warnings. */
	err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	if (err != GPG_ERR_NO_ERROR) {
		setError("", "GCRYPT", __func__, "Cannot set control param GCRYCTL_SUSPEND_SECMEM_WARN", err, true, true);
		std::cerr << getLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	/* ... If required, other initialization goes here.  Note that the
	 process might still be running with increased privileges and that
	 the secure memory has not been initialized.  */

	/* Allocate a pool of 64MB secure memory.  This makes the secure memory
	 available and also drops privileges where needed.  Note that by
	 using functions like gcry_xmalloc_secure and gcry_mpi_snew Libgcrypt
	 may expand the secure memory pool with memory which lacks the
	 property of not being swapped out to disk.   */
	err = gcry_control(GCRYCTL_INIT_SECMEM, 67108864, 0);
	if (err != GPG_ERR_NO_ERROR) {
		setError("", "GCRYPT", __func__, "Cannot set control param GCRYCTL_INIT_SECMEM", err, true, true);
		std::cerr << getLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	/* It is now okay to let Libgcrypt complain when there was/is
	 a problem with the secure memory. */
	err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	if (err != GPG_ERR_NO_ERROR) {
		setError("", "GCRYPT", __func__, "Cannot set control param GCRYCTL_RESUME_SECMEM_WARN", err, true, true);
		std::cerr << getLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	/* ... If required, other initialization goes here.  */
	/* Tell Libgcrypt that initialization has completed. */
	err =gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (err != GPG_ERR_NO_ERROR) {
		setError("", "GCRYPT", __func__, "Cannot set control param GCRYCTL_INITIALIZATION_FINISHED", err, true, true);
		std::cerr << getLastError() << std::endl;
		exit(EXIT_FAILURE);
	}
}

bool crypto::initializeAES(void) {
	keyLength = gcry_cipher_get_algo_keylen(CRYPTO_CIPHER);
	if(keyLength == 0) {
		setError("", "GCRYPT", __func__, "Cannot getgcry_cipher_get_algo_keylen", 0, true, true);
		return false;
	}
	blkLength = gcry_cipher_get_algo_blklen(CRYPTO_CIPHER);
	if(blkLength == 0) {
		setError("", "GCRYPT", __func__, "Cannot gcry_cipher_get_algo_blklen", 0, true, true);
		return false;
	}
	hashLenght = gcry_md_get_algo_dlen(CRYPTO_HASH);
	if(hashLenght == 0) {
		setError("", "GCRYPT", __func__, "Cannot gcry_md_get_algo_dlen", 0, true, true);
		return false;
	}

	return true;
}

bool crypto::generateAESKey(void) {
	if (withoutKeyFiles) {
		uint8_t* pointer = (uint8_t*) gcry_random_bytes_secure(keyLength, GCRY_VERY_STRONG_RANDOM);
		if (pointer == NULL) {
			setError("", "GCRYPT", __func__, "Cannot generate secure random bytes", 0, true, true);
			return false;
		}
		keyHolder.push_back(pointer);
		std::vector<uint8_t> data(pointer, pointer+keyLength);
		keyIdHolder.push_back(generateKeyIdFromData(data));
		data.clear();
		encryptSuccess.push_back(0);
		encryptFailure.push_back(0);
		decryptSuccess.push_back(0);
		decryptFailure.push_back(0);
		return true;
	} else {
		//we have already keys
		return true;
	}
}

bool crypto::generateIv(std::vector<uint8_t>& randIv) {
	//Overide exsisting data
	randIv.resize(blkLength, '\0');
	std::fill(randIv.begin(),randIv.end(), '\0');

	//Create random bytes (not from entropy, but secure enough for IV)
	gcry_create_nonce(randIv.data(), randIv.size());

	//Check if IV was generated
	if(randIv[0] == '\0' && randIv[blkLength-1] == '\0') {
		setError("", "GCRYPT", __func__, "Generation of IV failed - Retry", 0, true, true);
		//Retry:
		gcry_create_nonce(randIv.data(), randIv.size());
		if(randIv[0] == '\0') {
			setError("", "GCRYPT", __func__, "Generation of IV failed - Retry", 0, true, true);
			return false;
		} else {
			return true;
		}
	}

	return true;
}

std::string crypto::generateKeyIdFromData(std::vector<uint8_t>& data) {
	std::vector<uint8_t> keyId(hashLenght, 0);
	gcry_md_hash_buffer(CRYPTO_HASH, keyId.data(), data.data(), data.size());
	return convertToHex(keyId.data(), keyId.size()).substr(0, CRYPTO_KEY_ID_LEN);
}

bool crypto::encryptData(std::string& plainData, std::string& encryptedData, std::string clientName, bool keyDerivation, bool retry) {
	gcry_error_t err;
	gcry_cipher_hd_t cryptHandleLocal;
	err = gcry_cipher_open(&cryptHandleLocal, CRYPTO_CIPHER, CRYPTO_CIPHERMODE, GCRY_CIPHER_SECURE);
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", 0, true, true);
		return false;
	}
	if(plainData.empty()) {
		setError(clientName, "GCRYPT", __func__, "plainData is empty", 0, true, true);
		return false;
	}
	std::vector<uint8_t> salt(CRYPTO_SALT_LEN, '\0');
	std::vector<uint8_t> key(keyLength, '\0');
	std::string version = CRYPTO_VERSION_IDENTIFIER;
	std::vector<uint8_t> randIv(blkLength, '\0');

	if (keyDerivation) {
		gcry_create_nonce(salt.data(), salt.size());
		if (deriveKey(salt, key) == false) {
			setError(clientName, "GCRYPT", __func__, "Key derivation failed", 0, true, true);
			otherError++;
			std::fill(plainData.begin(),plainData.end(), 0);
			plainData.clear();
			std::fill(salt.begin(),salt.end(), 0);
			std::fill(key.begin(),key.end(), 0);
			return false;
		}
	} else {
		salt.clear();
		key.clear();
	}

	if (!generateIv(randIv)) {
		encryptFailure.back()++;
		std::fill(plainData.begin(),plainData.end(), 0);
		plainData.clear();
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(key.begin(),key.end(), 0);
		return false;
	}

	if (keyDerivation) {
		err = gcry_cipher_setkey(cryptHandleLocal, key.data(), key.size());
		std::fill(key.begin(),key.end(), 0);
		if (err != GPG_ERR_NO_ERROR) {
			setError(clientName, "GCRYPT", __func__, "", err, true, true);
			otherError++;
			std::fill(plainData.begin(),plainData.end(), 0);
			plainData.clear();
			std::fill(salt.begin(),salt.end(), 0);
			std::fill(key.begin(),key.end(), 0);
			return false;
		}
	} else {
		err = gcry_cipher_setkey(cryptHandleLocal, keyHolder.back(), keyLength);
		if (err != GPG_ERR_NO_ERROR) {
			setError(clientName, "GCRYPT", __func__, "", err, true, true);
			encryptFailure.back()++;
			std::fill(plainData.begin(),plainData.end(), 0);
			plainData.clear();
			std::fill(salt.begin(),salt.end(), 0);
			std::fill(key.begin(),key.end(), 0);
			return false;
		}
	}

	err = gcry_cipher_setiv(cryptHandleLocal, randIv.data(), randIv.size());
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		encryptFailure.back()++;
		std::fill(plainData.begin(),plainData.end(), 0);
		plainData.clear();
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(key.begin(),key.end(), 0);
		std::fill(randIv.begin(),randIv.end(), 0);
		return false;
	}

	dataBuffer.clear();
	if(!plainData.empty()) {
		dataBuffer.resize(plainData.length(), '\0');
	} else {
		setError(clientName, "GCRYPT", __func__, "plainData is empty", 0, true, true);
		return false;
	}

	err = gcry_cipher_final(cryptHandleLocal);
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		std::fill(plainData.begin(),plainData.end(), 0);
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(key.begin(),key.end(), 0);
		std::fill(randIv.begin(),randIv.end(), 0);
		std::fill(dataBuffer.begin(),dataBuffer.end(), 0);
		dataBuffer.clear();
		encryptFailure.back()++;
		return false;
	}
	err = gcry_cipher_encrypt(cryptHandleLocal, dataBuffer.data(), dataBuffer.size(), plainData.c_str(), plainData.length());
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		std::fill(plainData.begin(),plainData.end(), 0);
		plainData.clear();
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(key.begin(),key.end(), 0);
		std::fill(randIv.begin(),randIv.end(), 0);
		std::fill(dataBuffer.begin(),dataBuffer.end(), 0);
		dataBuffer.clear();
		encryptFailure.back()++;
		return false;
	}
	std::vector<uint8_t> tag(blkLength, '\0');
	err = gcry_cipher_gettag(cryptHandleLocal, tag.data(), tag.size());
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		encryptFailure.back()++;
		std::fill(plainData.begin(),plainData.end(), 0);
		plainData.clear();
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(key.begin(),key.end(), 0);
		std::fill(randIv.begin(),randIv.end(), 0);
		std::fill(dataBuffer.begin(),dataBuffer.end(), 0);
		std::fill(tag.begin(),tag.end(), 0);
		return false;
	}

	base64::encoder base64Encoder;
	std::ostringstream os;
	std::istringstream is(std::string(reinterpret_cast<const char*>(salt.data()), salt.size())
						+ std::string(reinterpret_cast<const char*>(randIv.data()), randIv.size())
						+ std::string(reinterpret_cast<const char*>(tag.data()), tag.size())
						+ std::string(reinterpret_cast<const char*>(dataBuffer.data()), dataBuffer.size())
	);

	base64Encoder.encode(is, os);
	encryptedData = version + keyIdHolder.back() + os.str() + '\0';
	std::fill(salt.begin(),salt.end(), 0);
	std::fill(randIv.begin(),randIv.end(), 0);
	std::fill(tag.begin(),tag.end(), 0);
	std::fill(key.begin(),key.end(), 0);
	std::fill(dataBuffer.begin(),dataBuffer.end(), 0);
	is.clear();
	os.clear();
	dataBuffer.clear();

	err = gcry_cipher_reset(cryptHandleLocal);
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		encryptFailure.back()++;
		return false;
	}

	//Verify Data:
	if(!keyDerivation) {
		if(!retry) {
			std::string tmppPlain;
			std::string tmppEnc = encryptedData;
			if (decryptData(tmppEnc, tmppPlain, clientName)) {
				setError(clientName, "GCRYPT", __func__, "Verify encrypted data can be decrypted ... OK!", 0, false, true);
				std::fill(tmppEnc.begin(),tmppEnc.end(), 0);
				tmppEnc.clear();
				std::fill(tmppPlain.begin(),tmppPlain.end(), 0);
				tmppPlain.clear();
			} else {
				setError(clientName, "GCRYPT", __func__, "Verify encrypted data can be decrypted ... FAILED!", 0, true, true);
				bool retrySuccess = false;
				for(int counter=0; counter < 2; counter++) {
					std::fill(encryptedData.begin(),encryptedData.end(), 0);
					encryptedData.clear();
					if (encryptData(plainData, encryptedData, clientName, keyDerivation, true)) {
						setError(clientName, "GCRYPT", __func__, "Retry" + std::to_string(counter) + " encrypt try ... SUCCESSFUL!", 0, false, true);
						retrySuccess = true;
						break;
					} else {
						setError(clientName, "GCRYPT", __func__, "Retry" + std::to_string(counter) + " encrypt try ... FAILED!", 0, true, true);
						if(plainData.empty()) {
							return false;
						}
					}
				}
				if(!retrySuccess) {
					encryptFailure.back()++;
					std::fill(plainData.begin(),plainData.end(), 0);
					plainData.clear();
					return false;
				}
			}
		} else {
			std::string tmppPlain;
			std::string tmppEnc = encryptedData;
			if (decryptData(tmppEnc, tmppPlain, clientName)) {
				std::fill(tmppEnc.begin(),tmppEnc.end(), 0);
				tmppEnc.clear();
				std::fill(tmppPlain.begin(),tmppPlain.end(), 0);
				tmppPlain.clear();
			} else {
				std::fill(tmppEnc.begin(),tmppEnc.end(), 0);
				tmppEnc.clear();
				std::fill(tmppPlain.begin(),tmppPlain.end(), 0);
				tmppPlain.clear();
				return false;
			}
		}
	}
	std::fill(plainData.begin(),plainData.end(), 0);
	plainData.clear();

	encryptSuccess.back()++;
	gcry_cipher_close(cryptHandleLocal);
	return true;
}

bool crypto::decryptData(std::string& encryptedData, std::string& plainData, std::string clientName, bool keyDerivation) {
	gcry_error_t err;
	gcry_cipher_hd_t cryptHandleLocal;
	err = gcry_cipher_open(&cryptHandleLocal, CRYPTO_CIPHER, CRYPTO_CIPHERMODE, GCRY_CIPHER_SECURE);
	if(encryptedData.empty()) {
		setError(clientName, "GCRYPT", __func__, "encryptedData is empty", 0, true, true);
		return false;
	}
	std::string salt(CRYPTO_SALT_LEN, '\0');
	std::string iv(blkLength, '\0');
	std::string tagData(blkLength, '\0');
	std::string b64DecodeDEncryptedData;
	std::vector<uint8_t> key(keyLength, '\0');
	std::string version = CRYPTO_VERSION_IDENTIFIER;
	long int keyPosition = 0;

	std::string encryptedVersion = encryptedData.substr(0, version.length());
	if (version != encryptedVersion) {
		setError(clientName, "GCRYPT", __func__, "Decrypt: Wrong crypt version: " + encryptedVersion, 0, true, true);
		otherError++;
		std::fill(encryptedData.begin(),encryptedData.end(), 0);
		encryptedData.clear();
		return false;
	}

	std::string dataKeyId = encryptedData.substr(version.length(), CRYPTO_KEY_ID_LEN);

	base64::decoder base64Dencoder;
	std::ostringstream os;
	std::istringstream is(encryptedData.substr(version.length() + CRYPTO_KEY_ID_LEN));
	//std::fill(encryptedData.begin(),encryptedData.end(), 0);
	base64Dencoder.decode(is, os);
	std::string b64DecodeData = os.str();
	if (keyDerivation) {
		salt = b64DecodeData.substr(0, CRYPTO_SALT_LEN);
		iv = b64DecodeData.substr(CRYPTO_SALT_LEN, blkLength);
		tagData = b64DecodeData.substr(CRYPTO_SALT_LEN + blkLength, blkLength);
		b64DecodeDEncryptedData = b64DecodeData.substr(CRYPTO_SALT_LEN + blkLength + blkLength);
	} else {
		salt.clear();
		iv = b64DecodeData.substr(0, blkLength);
		tagData = b64DecodeData.substr(blkLength, blkLength);
		b64DecodeDEncryptedData = b64DecodeData.substr(blkLength + blkLength);
	}
	std::fill(b64DecodeData.begin(),b64DecodeData.end(), 0);
	is.clear();
	os.clear();

	if(b64DecodeDEncryptedData.empty()) {
		setError(clientName, "GCRYPT", __func__, "encryptedDate in Base64Block is empty", 0, true, true);
		return false;
	}

	if (keyDerivation) {
		std::vector<uint8_t> saltVec(salt.begin(), salt.end());
		if (deriveKey(saltVec, key) == false) {
			setError(clientName, "GCRYPT", __func__, "Key derivation failed", 0, true, true);
			otherError++;
			std::fill(salt.begin(),salt.end(), 0);
			std::fill(iv.begin(),iv.end(), 0);
			std::fill(tagData.begin(),tagData.end(), 0);
			std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
			return false;
		} else {
			//woho
		}
	}

	if (!keyDerivation) {
		std::vector<std::string>::iterator it;
		it = std::find(keyIdHolder.begin(), keyIdHolder.end(), dataKeyId);
		if (it == keyIdHolder.end()) {
			setError(clientName, "GCRYPT", __func__, "Decrypt: No key found for" + dataKeyId, 0, true, true);
			otherError++;
			std::fill(salt.begin(),salt.end(), 0);
			std::fill(iv.begin(),iv.end(), 0);
			std::fill(tagData.begin(),tagData.end(), 0);
			std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
			return false;
		} else {
			keyPosition = it - keyIdHolder.begin();
		}

		err = gcry_cipher_setkey(cryptHandleLocal, keyHolder.at(keyPosition),
				keyLength);
		if (err != GPG_ERR_NO_ERROR) {
			setError(clientName, "GCRYPT", __func__, "", err, true, true);
			decryptFailure.at(keyPosition)++;
			std::fill(salt.begin(),salt.end(), 0);
			std::fill(iv.begin(),iv.end(), 0);
			std::fill(tagData.begin(),tagData.end(), 0);
			std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
			return false;
		}
	} else {
		err = gcry_cipher_setkey(cryptHandleLocal, key.data(), key.size());
		if (err != GPG_ERR_NO_ERROR) {
			setError(clientName, "GCRYPT", __func__, "", err, true, true);
			otherError++;
			std::fill(salt.begin(),salt.end(), 0);
			std::fill(iv.begin(),iv.end(), 0);
			std::fill(tagData.begin(),tagData.end(), 0);
			std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
			return false;
		}
	}

	err = gcry_cipher_setiv(cryptHandleLocal, iv.c_str(), iv.length());
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		if (keyDerivation) {
			otherError++;
		} else {
			decryptFailure.at(keyPosition)++;
		}
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(iv.begin(),iv.end(), 0);
		std::fill(tagData.begin(),tagData.end(), 0);
		std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
		return false;
	}
	std::fill(iv.begin(),iv.end(), 0);
	iv.clear();

	dataBuffer.clear();
	if(!b64DecodeDEncryptedData.empty()) {
		dataBuffer.resize(b64DecodeDEncryptedData.length(), '\0');
	} else {
		setError(clientName, "GCRYPT", __func__, "encryptedDate in Base64Block is empty", 0, true, true);
		return false;
	}

	err = gcry_cipher_final(cryptHandleLocal);
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		dataBuffer.clear();
		b64DecodeDEncryptedData.clear();
		tagData.clear();
		iv.clear();
		b64DecodeData.clear();
		if (keyDerivation) {
			otherError++;
		} else {
			decryptFailure.at(keyPosition)++;
		}
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(iv.begin(),iv.end(), 0);
		std::fill(tagData.begin(),tagData.end(), 0);
		std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
		std::fill(dataBuffer.begin(),dataBuffer.end(), 0);
		return false;
	}
	err = gcry_cipher_decrypt(cryptHandleLocal, dataBuffer.data(), dataBuffer.size(), b64DecodeDEncryptedData.c_str(), b64DecodeDEncryptedData.length());
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		dataBuffer.clear();
		b64DecodeDEncryptedData.clear();
		tagData.clear();
		iv.clear();
		b64DecodeData.clear();
		if (keyDerivation) {
			otherError++;
		} else {
			decryptFailure.at(keyPosition)++;
		}
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(iv.begin(),iv.end(), 0);
		std::fill(tagData.begin(),tagData.end(), 0);
		std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
		std::fill(dataBuffer.begin(),dataBuffer.end(), 0);
		return false;
	}

	err = gcry_cipher_checktag(cryptHandleLocal, tagData.c_str(), tagData.size());
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		dataBuffer.clear();
		if (keyDerivation) {
			otherError++;
		} else {
			decryptFailure.at(keyPosition)++;
		}
		std::fill(salt.begin(),salt.end(), 0);
		std::fill(iv.begin(),iv.end(), 0);
		std::fill(tagData.begin(),tagData.end(), 0);
		std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
		std::fill(dataBuffer.begin(),dataBuffer.end(), 0);
		return false;
	}

	plainData.clear();
	plainData.assign(dataBuffer.begin(), dataBuffer.end());

	std::fill(salt.begin(),salt.end(), 0);
	std::fill(iv.begin(),iv.end(), 0);
	std::fill(tagData.begin(),tagData.end(), 0);
	std::fill(b64DecodeDEncryptedData.begin(),b64DecodeDEncryptedData.end(), 0);
	std::fill(dataBuffer.begin(),dataBuffer.end(), 0);

	dataBuffer.clear();
	b64DecodeDEncryptedData.clear();
	tagData.clear();
	iv.clear();
	b64DecodeData.clear();

	err = gcry_cipher_reset(cryptHandleLocal);
	if (err != GPG_ERR_NO_ERROR) {
		setError(clientName, "GCRYPT", __func__, "", err, true, true);
		if (keyDerivation) {
			otherError++;
		} else {
			decryptFailure.at(keyPosition)++;
		}
		return false;
	}

	if (!keyDerivation) {
		decryptSuccess.at(keyPosition)++;
	}
	gcry_cipher_close(cryptHandleLocal);
	return true;
}

bool crypto::saveAESKeyToFile(std::string& filename, bool alwaysGenerateNewsKey) {
	int cryptoFile = 0;
	std::string dataEncrypted;
	if ((cryptoFile = open(filename.c_str(), O_WRONLY|O_EXCL|O_CREAT, 0600)) != -1) {
		if (keyHolder.size() == 0) {
			if (generateAESKey()) {
				setError("", "GCRYPT", __func__, "Generating new AESKey done!", 0, false, true);
				std::cout << getLastError() << std::endl;
			} else {
				setError("", "GCRYPT", __func__, "Could not create AESKey!", 0, true, true);
				std::cerr << getLastError() << std::endl;
				close(cryptoFile);
				return false;
			}
		} else {
			if (alwaysGenerateNewsKey) {
				if (generateAESKey()) {
					setError("", "GCRYPT", __func__, "Generating new AESKey done!", 0, false, true);
					std::cout << getLastError() << std::endl;
				} else {
					setError("", "GCRYPT", __func__, "Could not create AESKey!", 0, true, true);
					std::cerr << getLastError() << std::endl;
					close(cryptoFile);
					return false;
				}
			} else {
				setError("", "GCRYPT", __func__, "Used AESKey generated before!", 0, false, true);
				std::cout << getLastError() << std::endl;
			}
		}
		std::string data = std::string(reinterpret_cast<const char*>(keyHolder.back()), keyLength);
		if (encryptData(data, dataEncrypted, "", true)) {
			std::string version = CRYPTO_VERSION_IDENTIFIER;
			std::string dataKeyId = dataEncrypted.substr(version.length(), CRYPTO_KEY_ID_LEN);
			write(cryptoFile, dataEncrypted.data(), dataEncrypted.size());
			close(cryptoFile);
			setError("", "GCRYPT", __func__, "Key file with KeyID " + dataKeyId + " successfully generated!", 0, false, true);
			std::cout << getLastError() << std::endl;
			std::fill(data.begin(),data.end(), 0);
			std::fill(dataEncrypted.begin(),dataEncrypted.end(), 0);
			std::fill(version.begin(),version.end(), 0);
			std::fill(dataKeyId.begin(),dataKeyId.end(), 0);
			return true;
		} else {
			setError("", "GCRYPT", __func__, "Could not generate key file!", 0, true, true);
			std::cerr << getLastError() << std::endl;
			close(cryptoFile);
			std::fill(data.begin(),data.end(), 0);
			return false;
		}
	} else {
		setError("", "GCRYPT", __func__, "Cannot open file >" + filename + "> for writting!", 0, true, true);
		std::cerr << getLastError() << std::endl;
		return false;
	}
	return false;
}

bool crypto::loadAESKeyFromFile(std::string filename) {
	std::ifstream cryptoFile(filename);
	std::string data;
	if (cryptoFile.is_open()) {
		std::string dataEncrypted((std::istreambuf_iterator<char>(cryptoFile)), std::istreambuf_iterator<char>());
		std::string version = CRYPTO_VERSION_IDENTIFIER;
		std::string dataKeyId = dataEncrypted.substr(version.length(), CRYPTO_KEY_ID_LEN);
		setError("", "GCRYPT", __func__, "Found key file with KeyID " + dataKeyId, 0, false, true);
		std::cout << getLastError() << std::endl;
		if (decryptData(dataEncrypted, data, "", true)) {
			setError("", "GCRYPT", __func__, "Key file decrypted successful", 0, false, true);
			std::cout << getLastError() << std::endl;
			std::vector<uint8_t> key(data.begin(), data.end());
			addAESKeyToTruststore(key);
			keyIdHolder.push_back(dataKeyId);
			encryptSuccess.push_back(0);
			encryptFailure.push_back(0);
			decryptSuccess.push_back(0);
			decryptFailure.push_back(0);
			std::fill(dataEncrypted.begin(),dataEncrypted.end(), 0);
			std::fill(version.begin(),version.end(), 0);
			std::fill(dataKeyId.begin(),dataKeyId.end(), 0);
			std::fill(data.begin(),data.end(), 0);
			std::fill(key.begin(),key.end(), 0);
			key.clear();
			data.clear();
			cryptoFile.close();
			return true;
			setError("", "GCRYPT", __func__, "Cannot decrypt key file", 0, true, true);
			std::cerr << getLastError() << std::endl;
			cryptoFile.close();
			std::fill(dataEncrypted.begin(),dataEncrypted.end(), 0);
			std::fill(version.begin(),version.end(), 0);
			std::fill(dataKeyId.begin(),dataKeyId.end(), 0);
			std::fill(data.begin(),data.end(), 0);
			return false;
		}
	} else {
		setError("", "GCRYPT", __func__, "Cannot open file >" + filename + "> for reading!", 0, true, true);
		std::cerr << getLastError() << std::endl;
		return false;
	}
	return false;
}

std::string crypto::convertToHex(unsigned char *data, size_t len) {
	constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'A', 'B', 'C', 'D', 'E', 'F' };
	std::string s(len * 2, ' ');
	for (size_t i = 0; i < len; ++i) {
		s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

bool crypto::deriveKey(std::vector<uint8_t>& salt, std::vector<uint8_t>& key) {
	gcry_error_t err;
	std::string password;
	static struct termios old_terminal;
	static struct termios new_terminal;

	key.resize(keyLength, '\0');

	//get settings of the actual terminal
	tcgetattr(STDIN_FILENO, &old_terminal);
	// do not echo the characters
	new_terminal = old_terminal;
	new_terminal.c_lflag &= ~(ECHO);
	// set this as the new terminal options
	tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

	std::cout << "Please enter  passphrase: " << std::endl;
	std::getline(std::cin, password);

	// go back to the old settings
	tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);

	std::cout << "Password received - doing magic..." << std::endl;

	err = gcry_kdf_derive(password.c_str(), password.length(), CRYPTO_KDF_DERIVE_METHOD, CRYPTO_KDF_SUBALGO, salt.data(), salt.size(), CRYPTO_KDF_ITERATIONS, key.size(), key.data());
	std::fill(password.begin(),password.end(), 0);
	if (err != GPG_ERR_NO_ERROR) {
		setError("", "GCRYPT", __func__, "", err, true, true);
		return false;
	}

	return true;
}

bool crypto::addAESKeyToTruststore(std::vector<uint8_t>& data) {
	withoutKeyFiles = false;

	uint8_t* pointer = (uint8_t*) gcry_malloc_secure(keyLength);
	if (pointer == NULL) {
		setError("", "GCRYPT", __func__, "Cannot add key to storage", 0, true, true);
		return false;
	}
	std::copy(data.begin(), data.end(), pointer);
	keyHolder.push_back(pointer);
	return true;
}

void crypto::printStats(std::string& message) {
	message.clear();
	std::string datebuffer(100, 0);
	std::strftime((char*) datebuffer.c_str(), datebuffer.size(), "%a, %d %b %Y %H:%M:%S %z",
			std::localtime(&startTime));

	std::stringstream ss;
	ss << PROGRAM_NAME " running since:\t\t\t" + datebuffer << "\r\n";
	ss << "Overall connections:\t\t\t\t" << getNumberOfConnections() << "\r\n";
	ss << "Current active connections:\t\t\t" << getNumberOfActiveConnections()
			<< "\r\n";
	for (std::vector<std::string>::size_type i = 0; i != keyIdHolder.size(); i++) {
		ss << "Key ID <" << keyIdHolder[i] << "> encryption successes: \t"
				<< encryptSuccess[i] << "\r\n";
		ss << "Key ID <" << keyIdHolder[i] << "> encryption failures: \t\t"
				<< encryptFailure[i] << "\r\n";
		ss << "Key ID <" << keyIdHolder[i] << "> decryption successes: \t"
				<< decryptSuccess[i] << "\r\n";
		ss << "Key ID <" << keyIdHolder[i] << "> decryption failures: \t\t"
				<< decryptFailure[i] << "\r\n";
	}
	ss << "Other de-/encryption failures:\t\t\t" << otherError << "\r\n";
	ss << PROGRAM_NAME << " Version " << PROGRAM_VERSION << "\r\n"
			<< "Compiled on " << __DATE__ << " at " << __TIME__ << "\r\n";
	message = ss.str();
}

void crypto::setError(std::string errorPrefix, std::string scopeName, std::string functionName, std::string errorString, gcry_error_t gcryptError, bool isFatal, bool logToSyslog) {
	std::string errorMessage;
	try {
		std::string gcryptErrorText;
		if(gcryptError > 0) {
			gcryptErrorText.resize(1024);
			if(gpg_strerror_r(gcryptError, (char*) gcryptErrorText.c_str(), gcryptErrorText.size()) == 0) {
			} else {
				gcryptErrorText.clear();
			}
		} else {
			gcryptErrorText.clear();
		}

		if(isFatal && gcryptError > 0 && strlen(gcryptErrorText.c_str()) > 0) {
			try {
				errorMessage.append(errorPrefix.c_str());
				errorMessage.append(": ");
				errorMessage.append(scopeName.c_str());
				errorMessage.append(" ERROR at ");
				errorMessage.append(functionName.c_str());
				errorMessage.append("(): ");
				errorMessage.append(errorString.c_str());
				errorMessage.append(" (");
				errorMessage.append(gcryptErrorText.c_str());
				errorMessage.append(")");
			} catch (const std::exception& errorException) {
				std::cerr << errorException.what() << std::endl;
			}
		} else 	if(isFatal) {
			try {
				errorMessage.append(errorPrefix.c_str());
				errorMessage.append(" ");
				errorMessage.append(scopeName.c_str());
				errorMessage.append(" ERROR at ");
				errorMessage.append(functionName.c_str());
				errorMessage.append("(): ");
				errorMessage.append(errorString.c_str());
			} catch (const std::exception& errorException) {
				std::cerr << errorException.what() << std::endl;
			}
		} else {
			try {
				errorMessage.append(errorPrefix.c_str());
				errorMessage.append(" ");
				errorMessage.append(scopeName.c_str());
				errorMessage.append(" INFO at ");
				errorMessage.append(functionName.c_str());
				errorMessage.append("(): ");
				errorMessage.append(errorString.c_str());
			} catch (const std::exception& errorException) {
				std::cerr << errorException.what() << std::endl;
			}
		}

		if(logToSyslog) {
			if(!errorMessage.empty()) {
				if(isFatal) {
					syslog(LOG_ERR, "%s", errorMessage.c_str());
				} else {
					syslog(LOG_NOTICE, "%s", errorMessage.c_str());
				}
			}
		}

		error = errorMessage;

	} catch (const std::exception& errorException) {
		std::cerr << errorException.what() << std::endl;
	}
}

crypto::~crypto() {
	gcry_error_t err;
	err = gcry_control(GCRYCTL_TERM_SECMEM);
	if (err != GPG_ERR_NO_ERROR) {
		//cannot do anything
	}
}
