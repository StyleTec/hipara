#ifndef __UPDATE__
#define __UPDATE__

#include "MyCurl.h"
#include <string>
#include "RequestingURL.h"
#include "Common.h"

#define	SIGNATURE_FILE			"signatures.yar"

typedef enum ALERT_TYPE
{
	ALERT_FILE,
	ALERT_CMD
};

typedef struct
{
	char* hostName;
	char* fileName;
	char* alertMessage;
	char* timeStamp;
	char* command;
	ALERT_TYPE alertType;
	long parentProcessId;
}AlertMessage;

using namespace std;

class Update 
{
	char* mSignatureDownloadPath;
	char* mSignatureServerUrl;
	char* mAccessToken;
	int mAccessTokenLen;
	char* mEmail;
	char* mPassword;
	bool mbInitialized;

	int createEventsAndThreads();
	int addToQueue(AlertMessage* alert);

public:
	Update(const char* signatureDownloadPath, const char* signatureServerUrl);
	Update();
	~Update();

	int init();

	char* getSignatureServerUrl()
	{
		return mSignatureServerUrl;
	}
	char* getAccessToken()
	{
		return mAccessToken;
	}
	AlertMessage* popAlertMessage();
	int login(const char* email, const char* password);
	int updateSignature();
	int logout();
	int parseJsonResponse(char* response);
	int alert(AlertMessage*);
};

#endif /* __UPDATE__ */