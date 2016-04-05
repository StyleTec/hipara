#ifndef __MYCURL__
#define __MYCURL__

#include "curl\curl.h"
#include <string>

using namespace std;

enum HTTP_METHOD
{
	GET,
	POST,
	PUT
};

typedef struct
{
	char *response;
	size_t size;
}MemoryStruct;

class MyCurl
{
	CURL* mpCurlHandle;
	MemoryStruct mResponse;
	string mFileDownloadPath;
	FILE* mpFPtr;

public:
	MyCurl();
	~MyCurl();

	static size_t curlCallback(void* ptr, size_t size, size_t nmemb, void* userData);
	static size_t curlHttpHeaderCallback(void *ptr, size_t size, size_t nmemb, void* userData);
	static size_t curlFileDownloadCallback(void* ptr, size_t size, size_t nmemb, void* userData);

	int sendRequest( const char *url,
					 HTTP_METHOD httpMethod,
					 const char *postData,
					 const char *header,
					 char **response,
					 int *respLength );

	int fileDownloadRequest(const char* url, char* header, char** response, int* respLen, const char* fileName);
	
};

#endif /* __MYCURL__ */