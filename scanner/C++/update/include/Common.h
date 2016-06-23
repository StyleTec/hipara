#ifndef __COMMON__
#define __COMMON__

#define VERBOSE 1
#define ERRORLOG 1
#define DEBUG 0
#define LOG(M, ...) {if(M==ERRORLOG)printf(__VA_ARGS__); \
								else if(M==DEBUG && VERBOSE == 1)printf(__VA_ARGS__);}

typedef struct
{
	char* md5;
	char* sha1;
	char* sha256;
}Checksum;

typedef struct
{
	int fileCount;
	int id;
	int malwareId;
	char* assetIdentifier;
	char* extension;
	bool deploy;
	bool runIfMatch;
	Checksum checksum;
	char* url;
}FileDetails;

#endif /* __COMMON__*/