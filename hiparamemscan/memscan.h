
#include<ntddk.h>

#define	MAX_PATH						260
#define	HIPARA_DEVICE_NAME				L"\\Device\\HIPARAMEMSCAN"
#define	HIPARA_SYMBOLIC_LINK_NAME		L"\\DosDevices\\HiparaMemScan"

#define	HIPARA_MEMORY_TAG				'csmh'

#define ARRAY_SIZE(X)					(sizeof(X) / sizeof(X[0]))

//	IOCTL definition.
#define SIOCTL_TYPE 40000
#define IOCTL_HELLO\
	CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_GET_LENGTH\
	CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_PROC_INFO\
	CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//	Device extension structure.
//	This is driver defined structure.
typedef struct _DEVICE_EXTENSION
{
	WCHAR wszSymbolicName[MAX_PATH];

}	DEVICE_EXTENSION, *P_DEVICE_EXTENSION;

//	System information class enum.
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS, *P_SYSTEM_INFORMATION_CLASS;

//
//	System process information structure.
//
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	LARGE_INTEGER			Reserved6[6];

}	SYSTEM_PROCESS_INFORMATION, *P_SYSTEM_PROCESS_INFORMATION;

//	Driver entry function.
DRIVER_INITIALIZE DriverEntry;

//	Driver unload function.
DRIVER_UNLOAD	DriverUnload;

//	IRP_MJ_CREATE handler function.
NTSTATUS
HiparaCreateHandler(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);

//	Device IOCTL handler function.
NTSTATUS
HiparaDeviceIOCTLHandler(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);

//	Undocumented function declaration.
NTSTATUS
ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


