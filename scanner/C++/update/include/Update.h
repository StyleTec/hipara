#ifndef __UPDATE__
#define __UPDATE__

#include "MyCurl.h"
#include <string>
#include "RequestingURL.h"
#include "Common.h"

#define	SIGNATURE_FILE			"signatures.yar"

using namespace std;

class Update : public MyCurl
{
	char* mSignatureDownloadPath;
	char* mSignatureServerUrl;
	FileDetails* mFileDetails;
	char* mAccessToken;
	int mAccessTokenLen;
	char* mEmail;
	char* mPassword;

public:
	Update(const char* signatureDownloadPath, const char* signatureServerUrl);
	Update();
	~Update();

	int updateSignature(const char* email, const char* password);
	int parseJsonResponse(char* response);
};

#endif /* __UPDATE__ */