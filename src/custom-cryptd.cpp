#include "crypt/crypto.h"
#include "network/Socket.h"
#include "network/ProtocolCrypto.h"
namespace Sock = ThorsAnvil::Socket;

#include <iostream>
#include <string>
#include <thread>
#include <csignal>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <syslog.h>

bool fileExists(const char* file);
void handleConnection(crypto* cryptoCryptProtocol, int socket);
void handle_signal(int sig);
void daemonizeMe(const char *pidfile);
void showhelp(std::string name);
void showVersionAndBuild(void);

bool exitdaemon = false;
int pidFilehandle;
Sock::ServerSocket* serverGlobal;

bool fileExists(const char* file) {
	struct stat buf;
	return (stat(file, &buf) == 0);
}

void handleConnection(crypto* cryptoCryptProtocol, int socket) {
	cryptoCryptProtocol->incrementNumberOfConnections();
	cryptoCryptProtocol->incrementNumberOfActiveConnections();
	Sock::DataSocket* acceptSocketCrypto = NULL;
	Sock::ProtocolCrypto* cryptoNetworkProtocol = NULL;
	//syslog(LOG_NOTICE, "Thread started!");
	try {
		acceptSocketCrypto = new Sock::DataSocket(socket);
		cryptoNetworkProtocol = new Sock::ProtocolCrypto(*acceptSocketCrypto);

		if (cryptoNetworkProtocol->cryptoGreeting()) {
			//syslog(LOG_NOTICE, "Server greeting sucessful");
			cryptoNetworkProtocol->processRequests(*cryptoCryptProtocol);
		}
	} catch (const std::runtime_error& error) {
		std::cerr << "Cannot create socket: " << error.what() << std::endl;
		syslog(LOG_ERR, "Newtowrk error: %s", error.what());
	} catch (const std::exception& error) {
		std::cerr << "Exception: " << error.what() << std::endl;
		syslog(LOG_ERR, "Exception error: %s", error.what());
	}
	if(cryptoNetworkProtocol != NULL) {
		delete cryptoNetworkProtocol;
	}
	if(acceptSocketCrypto != NULL) {
		delete acceptSocketCrypto;
	}
	close(socket);
	cryptoCryptProtocol->decrementNumberOfActiveConnections();
}

void handle_signal(int sig) {
	switch (sig) {
	case SIGHUP:
	case SIGINT:
	case SIGTERM:
		syslog(LOG_NOTICE, "Daemon exiting..");
		if (pidFilehandle != -1) {
			lockf(pidFilehandle, F_ULOCK, 0);
			close(pidFilehandle);
		}
		signal(SIGINT, SIG_DFL);
		exitdaemon = true;
		try {
			serverGlobal->close();
		} catch (const std::exception& error) {
			//woho
		}
		//exit(EXIT_SUCCESS);
		break;
	default:
		break;
	}
}

void daemonizeMe(const char *pidfile) {
	syslog(LOG_NOTICE, "Daemonizing program..");
	pid_t pid = 0;
	long int fd;

	/* Fork off the parent process */
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		syslog(LOG_ERR, "First fork failed!");
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		syslog(LOG_NOTICE, "First fork succeeded, pid: %d", pid);
		exit(EXIT_SUCCESS);
	}

	/* On success: The child process becomes session leader */
	if (setsid() < 0) {
		syslog(LOG_ERR, "Cannot set SID!");
		exit(EXIT_FAILURE);
	}

	/* Ignore signal sent from child to parent process */
	syslog(LOG_NOTICE, "Ignore signal sent from child");
	signal(SIGCHLD, SIG_IGN);

	/* Fork off for the second time*/
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		syslog(LOG_ERR, "Second fork failed!");
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		syslog(LOG_NOTICE, "Second fork succeeded, pid: %d", pid);
		exit(EXIT_SUCCESS);
	}

	/* Set new file permissions */
	syslog(LOG_NOTICE, "Setting umask..");
	umask(177); //allow read and write permission for the file's owner, but prohibit read, write, and execute permission for everyone else

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	syslog(LOG_NOTICE, "Setting chdir..");
	chdir("/");

	/* Close all open file descriptors */
	syslog(LOG_NOTICE, "Close file descriptors..");
	for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--) {
		close((int)fd);
	}

	/* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
	syslog(LOG_NOTICE, "Remove std*..");
	stdin = fopen("/dev/null", "r");
	stdout = fopen("/dev/null", "w+");
	stderr = fopen("/dev/null", "w+");

	/* Ensure only one copy */
	pidFilehandle = open(pidfile, O_RDWR | O_CREAT, 0600);

	if (pidFilehandle == -1) {
		/* Couldn't open lock file */
		syslog(LOG_ERR, "Could not open PID lock file %s, exiting", pidfile);
		exit(EXIT_FAILURE);
	}

	/* Try to lock file */
	if (lockf(pidFilehandle, F_TLOCK, 0) == -1) {
		/* Couldn't get lock on lock file */
		syslog(LOG_ERR, "Could not lock PID lock file %s, exiting", pidfile);
		exit(EXIT_FAILURE);
	}

	struct rlimit limit;
	limit.rlim_cur = 65535;
	limit.rlim_max = 65535;


	if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
		syslog(LOG_ERR, "setrlimit() failed with errno=%d", errno);
		exit(EXIT_FAILURE);
	}

	if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
		syslog(LOG_ERR, "getrlimit() failed with errno=%d", errno);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_NOTICE, "The soft limit nofile is %lu", limit.rlim_cur);
	syslog(LOG_NOTICE, "The hard limit nofile is %lu", limit.rlim_max);

	struct rlimit corelim;
	//corelim.rlim_cur = RLIM_INFINITY;
	//corelim.rlim_max = RLIM_INFINITY;
	corelim.rlim_cur = 0;
	corelim.rlim_max = 0;

	if (setrlimit(RLIMIT_CORE, &corelim) != 0) {
		syslog(LOG_ERR, "setrlimit() failed with errno=%d", errno);
		exit(EXIT_FAILURE);
	}

	/* Get max number of files. */
	if (getrlimit(RLIMIT_CORE, &corelim) != 0) {
		syslog(LOG_ERR, "getrlimit() failed with errno=%d", errno);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_NOTICE, "The soft limit core is %lu", corelim.rlim_cur);
	syslog(LOG_NOTICE, "The hard limit core is %lu", corelim.rlim_max);

	struct rlimit aslim;
	if (getrlimit(RLIMIT_AS, &aslim) != 0) {
		syslog(LOG_ERR, "getrlimit() failed with errno=%d", errno);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_NOTICE, "The soft limit as is %lu", aslim.rlim_cur);
	syslog(LOG_NOTICE, "The hard limit as is %lu", aslim.rlim_max);

	/* Get and format PID */
	std::string s = std::to_string(getpid());

	/* write pid to lockfile */
	write(pidFilehandle, s.data(), s.size());
}

void showhelp(std::string name) {
	std::cout << "Usage: " << name
			<< " [-p port] [-P pidfile] [-d] [-l] [-S] cryptoFile [...]"
			<< std::endl << "OR: " << "\t-g cryptoFile" << std::endl
			<< "\t-S" << std::endl
			<< "\t-? or -h" << std::endl
			<< "\t-V" << std::endl
			<<  std::endl
			<< "Switches:" <<  std::endl
			<< "-p:\t\tPort number for incoming connection (default 10000)"  <<  std::endl
			<< "-l:\t\tListen only on localhost ip address"  <<  std::endl
			<< "-d:\t\tStart in Daemon mode"  <<  std::endl
			<< "-P:\t\tPath and filename for PID file (default /var/run/custom-cryptd.pid)"  <<  std::endl
			<< "-S:\t\tStandalone Key mode - generate and use key without saving it. CAUTION: don't use for reusable de/encryption!" <<  std::endl
			<< "-g:\t\tGenerate Key and save in securely in file" <<  std::endl
			<< "-? or -h:\tShow this help" <<  std::endl
			<< "-V:\t\tShow version and build information" <<  std::endl
			<< "cryptoFile(s):\t Use key(s) from file(s) - generated before with -g switch - WARNING - Only last key in list is used for ALL encryptions!!!" <<  std::endl;
}

void showVersionAndBuild(void) {
	std::cout << PROGRAM_NAME << " Version " << PROGRAM_VERSION << std::endl
			<< "Compiled on " << __DATE__ << " at " << __TIME__ << std::endl
			<< PRGRAM_COPYRIGHT << std::endl;
	#ifdef BUILD_OPTIONS
	std::cout << "Build with options " << BUILD_OPTIONS << std::endl;
	#endif
	std::cout << std::endl;
}

int main(int argc, char* argv[]) {
	int port = 10000;
	bool daemonize = false;
	bool onlyLocalhost = false;
	bool generateKey = false;
	std::string generateKeyFile = "/tmp/foo";
	std::string pidFile = "/var/run/custom-cryptd.pid";
	std::vector<std::string> cryptoFiles;

	setlogmask(LOG_UPTO(LOG_NOTICE));
	openlog(PROGRAM_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	syslog(LOG_NOTICE, "Program started by User %d", getuid());

	if (argc < 2) {
		showhelp(argv[0]);
		return EXIT_FAILURE;
	}

	for (int argumentsIndex = 1; argumentsIndex < argc; argumentsIndex++) {
		std::string argument = argv[argumentsIndex];
		if (argument == "-p") {
			if (argumentsIndex + 1 < argc) {
				argumentsIndex++;
				std::string str_int = argv[argumentsIndex];
				try {
					port = std::stoi (str_int,nullptr);
				} catch (const std::out_of_range& oor) {
					std::cerr << "No correct port number!" << std::endl;
					syslog(LOG_ERR, "No correct port number at command line");
					return EXIT_FAILURE;
				}
				if (port > 0 && port <= 65535) {
					//woho
				} else {
					std::cerr << "No correct port number!" << std::endl;
					syslog(LOG_ERR, "No correct port number at command line");
					return EXIT_FAILURE;
				}
			} else {
				std::cerr << "Wrong arguments count!" << std::endl;
				syslog(LOG_ERR, "Wrong arguments count at command line");
				return EXIT_FAILURE;
			}
		} else if (argument == "-P") {
			if (argumentsIndex + 1 < argc) {
				argumentsIndex++;
				pidFile = argv[argumentsIndex];
			} else {
				std::cerr << "Wrong arguments count!" << std::endl;
				syslog(LOG_ERR, "Wrong arguments count at command line");
				return EXIT_FAILURE;
			}
		} else if (argument == "-S") {
			std::cout << "!!!WARNING!!! STANDALONE KEY - NO KEY FILE !!!WARNING!!!" << std::endl;
			std::cout << "Please enter Y" << std::endl;
			char decision = 'N';
			decision = (char) getchar();
			if (decision == 'Y') {
				//OK
			} else {
				return EXIT_FAILURE;
			}
		} else if (argument == "-d") {
			daemonize = true;
		} else if (argument == "-g") {
			if (argumentsIndex + 1 < argc) {
				argumentsIndex++;
				if (fileExists(argv[argumentsIndex])) {
					std::cerr << "File exists, for security reasons aborting"
							<< std::endl;
					syslog(LOG_ERR, "Key file exists, aborting");
					return EXIT_FAILURE;
				} else {
					generateKey = true;
					generateKeyFile = argv[argumentsIndex];
				}
			} else {
				std::cerr << "Wrong arguments count!" << std::endl;
				syslog(LOG_ERR, "Wrong arguments count at command line");
				return EXIT_FAILURE;
			}
		} else if (argument == "-l") {
			onlyLocalhost = true;
		} else if (argument == "-V") {
			showVersionAndBuild();
			return EXIT_SUCCESS;
		} else if (argument == "-?" || argument == "-h") {
			showhelp(argv[0]);
			return EXIT_SUCCESS;
		} else if (argument.find("-") != std::string::npos) {
			std::cerr << "Wrong switch!" << std::endl;
			syslog(LOG_ERR, "Wrong switch at command line");
			return EXIT_FAILURE;
		} else {
			//should be the cryptoFile
			if (fileExists(argv[argumentsIndex])) {
				cryptoFiles.push_back(argv[argumentsIndex]);
			} else {
				std::cerr << "No valid file: " << argv[argumentsIndex]
						<< std::endl;
				syslog(LOG_ERR, "Cannot open key file");
				return EXIT_FAILURE;
			}
		}
	}

	crypto* cryptoCryptProtocol = new crypto();

	if (!cryptoCryptProtocol->initializeAES()) {
		std::cout << "Initializing of AES was not successful!\n" << std::endl;
		syslog(LOG_ERR, "Initializing of AES was not successful");
		delete (cryptoCryptProtocol);
		return EXIT_FAILURE;
	}

	if (generateKey) {
		std::cout << argv[0] << " trying to generate KeyFile: " << generateKeyFile << std::endl;
		if (cryptoCryptProtocol->saveAESKeyToFile(generateKeyFile, true)) {
			delete (cryptoCryptProtocol);
			return EXIT_SUCCESS;
		} else {
			syslog(LOG_ERR, "Cannot save key file");
			delete (cryptoCryptProtocol);
			return EXIT_FAILURE;
		}
	}

	for (std::vector<std::string>::const_iterator i = cryptoFiles.begin();
			i != cryptoFiles.end(); ++i) {
		std::cout << argv[0] << " trying to load KeyFile: " << *i << std::endl;
		if (cryptoCryptProtocol->loadAESKeyFromFile(*i)) {
			syslog(LOG_NOTICE, "AES Key was successfully loaded");
		} else {
			syslog(LOG_ERR, "Cannot load key file");
			delete (cryptoCryptProtocol);
			return EXIT_FAILURE;
		}
	}

	if (!cryptoCryptProtocol->generateAESKey()) {
		std::cout << "Generating of AES Key was not successful!\n";
		syslog(LOG_ERR, "Generating of AES Key was not successful");
		delete (cryptoCryptProtocol);
		return EXIT_FAILURE;
	}

	if (daemonize) {
		daemonizeMe(pidFile.c_str());
	}
	signal(SIGHUP, handle_signal);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGPIPE, SIG_IGN);

	Sock::ServerSocket* server;
	try {
		server = new Sock::ServerSocket(port, onlyLocalhost);
		serverGlobal = server;
	} catch (const std::runtime_error& error) {
		std::cerr << "Cannot create socket: " << error.what() << std::endl;
		syslog(LOG_ERR, "Cannot create socket: %s", error.what());
		delete (server);
		delete (cryptoCryptProtocol);
		return EXIT_FAILURE;
	}

	while (!exitdaemon) {
		//syslog(LOG_NOTICE, "Waiting for connections...");
		int socket = 0;
		if(socket) {

		}
		try {
			socket = server->accept();
		} catch (const std::runtime_error& error) {
			syslog(LOG_ERR, "Exception error on accept: %s", error.what());
			exitdaemon = true;
			break;
		} catch (const std::exception& error) {
			syslog(LOG_ERR, "Exception error on accept: %s", error.what());
			exitdaemon = true;
			break;
		}
		//syslog(LOG_NOTICE, "New connection, starting thread");
		std::thread (handleConnection,cryptoCryptProtocol, socket).detach();
	}

	syslog(LOG_NOTICE, "Exit program");
	closelog();
	delete (server);
	delete (cryptoCryptProtocol);
	return EXIT_SUCCESS;
}
