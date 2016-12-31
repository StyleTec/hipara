#define	INITGUID

#include "memscan.h"
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

//
//	DriverEntry function.
//	Entry point function for driver.
//
NTSTATUS
DriverEntry(
IN PDRIVER_OBJECT pDriverObject,
IN PUNICODE_STRING pusUnicodeString
)
{
	NTSTATUS ntStatus;
	UNICODE_STRING usDeviceName;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING usSymbolicName;
	DEVICE_EXTENSION *pDeviceExtension;

	if (NULL == pDriverObject || NULL == pusUnicodeString)
	{
		DbgPrint("DriverEntry: Invalid Parameter.\n");
		return STATUS_INVALID_PARAMETER;
	}

	//
	//	Register dispatch handles for the driver.
	//
	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = HiparaCreateHandler;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HiparaDeviceIOCTLHandler;

	RtlInitUnicodeString(&usDeviceName, HIPARA_DEVICE_NAME);
	ntStatus = IoCreateDevice(
						pDriverObject,
						sizeof(DEVICE_EXTENSION),
						&usDeviceName,
						FILE_DEVICE_UNKNOWN,
						FILE_DEVICE_UNKNOWN,
						FALSE,
						&pDeviceObject
						);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("DriverEntry: IoCreateDevice failed(0x%08X)\n", ntStatus);
		return ntStatus;
	}

	RtlInitUnicodeString(&usSymbolicName, HIPARA_SYMBOLIC_LINK_NAME);
	ntStatus = IoCreateSymbolicLink(
						&usSymbolicName,
						&usDeviceName
						);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("DriverEntry: IoCreateSymbolicLink failed(0x%08X)\n", ntStatus);
		IoDeleteDevice(pDeviceObject);

		return ntStatus;
	}

	pDeviceExtension = (DEVICE_EXTENSION *)pDeviceObject->DeviceExtension;
	if (NULL != pDeviceExtension)
	{
		ntStatus = RtlStringCchCopyW(pDeviceExtension->wszSymbolicName, ARRAY_SIZE(pDeviceExtension->wszSymbolicName), HIPARA_SYMBOLIC_LINK_NAME);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("DriverEntry: RtlStringCchCopyW failed(0x%08X)\n", ntStatus);
			IoDeleteDevice(pDeviceObject);

			return ntStatus;
		}
	}

	return STATUS_SUCCESS;
}

VOID
DriverUnload(
IN PDRIVER_OBJECT pDriverObject
)
{
	NTSTATUS ntStatus;
	DEVICE_OBJECT *pDeviceObject;
	UNICODE_STRING usSymbolicName;
	DEVICE_EXTENSION *pDeviceExtension;

	DbgPrint("DriverUnload: Entry.\n");

	if (NULL == pDriverObject)
	{
		DbgPrint("DriverUnload: Invalid Parameter.\n");
		return;
	}
	
	pDeviceObject = pDriverObject->DeviceObject;
	if (NULL != pDeviceObject)
	{
		pDeviceExtension = (DEVICE_EXTENSION *)pDeviceObject->DeviceExtension;
		if (NULL != pDeviceExtension)
		{
			//	Delete symbolic link created in DriverEntry using IoCreateSymbolicLink
			RtlInitUnicodeString(&usSymbolicName, pDeviceExtension->wszSymbolicName);
			ntStatus = IoDeleteSymbolicLink(&usSymbolicName);
			if (!NT_SUCCESS(ntStatus))
			{
				DbgPrint("DriverUnload:IoDeleteSymbolicLink failed(0x%08X)\n", ntStatus);
			}
		}
		else
		{
			DbgPrint("DriverUnload: pDeviceExtension is NULL.\n");
		}

		//	Delete Device object create in DriverEntry using IoCreateDevice.
		IoDeleteDevice(pDeviceObject);
	}

	DbgPrint("DriverUnload: Exit.\n");
}

NTSTATUS
HiparaCreateHandler(
IN PDEVICE_OBJECT pDeviceObject,
IN PIRP pIrp
)
{
	PAGED_CODE();
	
	DbgPrint("HiparaCreateHandle: Entry.\n");

	if (NULL == pDeviceObject || NULL == pIrp)
	{
		DbgPrint("HiparaCreateHandle: Invalid parameter.\n");
		return STATUS_INVALID_PARAMETER;
	}

	UNREFERENCED_PARAMETER(pDeviceObject);

	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DbgPrint("HiparaCreateHandle: Exit\n");
	return STATUS_SUCCESS;
}

//	Device IOCTL handler function.
NTSTATUS
HiparaDeviceIOCTLHandler(
IN PDEVICE_OBJECT pDeviceObject,
IN PIRP pIrp
)
{
	NTSTATUS ntStatus;
	PVOID pInputBuffer;
	PVOID pOutputBuffer;
	ULONG ulInputBuffLen;
	ULONG ulOutputBuffLen;
	ULONG ulReturnedLength;
	PIO_STACK_LOCATION pIoStackLocation;
	SYSTEM_PROCESS_INFORMATION *pSystemProcInfo;

	DbgPrint("HiparaDeviceIOCTLHandler: Entry\n");

	if (NULL == pDeviceObject || NULL == pIrp)
	{
		DbgPrint("HiparaDeviceIOCTLHandler: Invalid parameter.\n");
		return STATUS_INVALID_PARAMETER;
	}

	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	if (NULL == pIoStackLocation)
	{
		DbgPrint("HiparaDeviceIOCTLHandler: IoGetCurrentIrpStackLocation returned NULL stack location.\n");

		return STATUS_INVALID_PARAMETER;
	}

	pSystemProcInfo = NULL;
	ntStatus = STATUS_SUCCESS;

	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_GET_LENGTH:

			DbgPrint("HiparaDeviceIOCTLHandler: IOCTL_GET_LENGTH.\n");

			pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;

			ntStatus = ZwQuerySystemInformation(SystemProcessInformation, pSystemProcInfo, 0, &ulReturnedLength);
			if (STATUS_INFO_LENGTH_MISMATCH != ntStatus)
			{
				//	We are actually expecting STATUS_INFO_LENGTH_MISMATCH, but we don't get so returning as 
				//	STATUS_UNSUCCESSFUL.
				DbgPrint("HiparaDeviceIOCTLHandler(IOCTL_GET_LENGTH): ZwQuerySystemInformation failed(0x%08X)\n", ntStatus);
				ntStatus = STATUS_UNSUCCESSFUL;
				pIrp->IoStatus.Information = 0;
				break;
			}
			DbgPrint("HiparaDeviceIOCTLHandler, IOCTL_GET_LENGTH: ZwQuerySystemInformation returned length (%u)\n", ulReturnedLength);

			RtlZeroMemory(pOutputBuffer, pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
			*(ULONG *)pOutputBuffer = ulReturnedLength;

			pIrp->IoStatus.Information = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

			ntStatus = STATUS_SUCCESS;
			break;

		case IOCTL_PROC_INFO:
			DbgPrint("HiparaDeviceIOCTLHandle: IOCTL_PROC_INFO.\n");

			//	InputBuffer will be length in bytes returned in call to IOCTL_GET_LENGTH.
			pInputBuffer = pIrp->AssociatedIrp.SystemBuffer;
			ulInputBuffLen = *(ULONG *)pInputBuffer;

			pSystemProcInfo = (SYSTEM_PROCESS_INFORMATION *)ExAllocatePoolWithTag(NonPagedPool, ulInputBuffLen, HIPARA_MEMORY_TAG);
			if (NULL == pSystemProcInfo)
			{
				DbgPrint("HiparaDeviceIOCTLHandler: Memory allocation failed.\n");
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				pIrp->IoStatus.Information = 0;
				break;
			}

			ntStatus = ZwQuerySystemInformation(SystemProcessInformation, pSystemProcInfo, ulInputBuffLen, &ulReturnedLength);
			if (!NT_SUCCESS(ntStatus))
			{
				DbgPrint("HiparaDeviceIOCTLHandler: ZwQuerySystemInformation failed(0x%08X)\n", ntStatus);
				ExFreePoolWithTag(pSystemProcInfo, HIPARA_MEMORY_TAG);
				pIrp->IoStatus.Information = 0;
				break;
			}

			pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;
			ulOutputBuffLen = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

			RtlZeroMemory(pOutputBuffer, ulOutputBuffLen);
			RtlCopyMemory(pOutputBuffer, pSystemProcInfo, ulReturnedLength);

			ntStatus = STATUS_SUCCESS;
			pIrp->IoStatus.Information = ulReturnedLength;

			ExFreePoolWithTag(pSystemProcInfo, HIPARA_MEMORY_TAG);

			break;

		default:
			DbgPrint("HiparaDeviceIOCTLHandler: Invalid device control request.\n");
			pIrp->IoStatus.Information = 0;
			ntStatus = STATUS_INVALID_DEVICE_REQUEST;
	}

	pIrp->IoStatus.Status = ntStatus;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DbgPrint("HiparaDeviceIOCTLHandler: Exit\n");
	return ntStatus;
}