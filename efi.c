/*
 * Copyright 2013 Red Hat, Inc <pjones@redhat.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <efi.h>
#include <efilib.h>

extern UINT8 *kek, *db, *pk;
extern UINTN kek_len, db_len, pk_len;

#define EFI_IMAGE_SECURITY_DATABASE_GUID { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f }}

EFI_STATUS efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS status = EFI_SUCCESS;
	UINT8 byte;
	UINTN size = sizeof(byte);
	EFI_GUID global = EfiGlobalVariable;
	EFI_GUID security = EFI_IMAGE_SECURITY_DATABASE_GUID;

	InitializeLib(image_handle, systab);

	status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &global,
				   NULL, &size, &byte);
	if (EFI_ERROR(status)) {
		Print(L"Could not get SetupMode: %d\n", status);
		uefi_call_wrapper(BS->Stall, 1, 2000000);
		return EFI_SUCCESS;
	}

	Print(L"Platform is in setup mode\n");
	Print(L"Creating db: ");
	status = uefi_call_wrapper(RT->SetVariable, 5, L"db", &security,
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
		db_len, db);
	if (EFI_ERROR(status)) {
		Print(L"Failed: %d\n", status);
		uefi_call_wrapper(BS->Stall, 1, 2000000);
		return EFI_SUCCESS;
	} else {
		Print(L"Success\n");
	}

	Print(L"Creating KEK: ");
	status = uefi_call_wrapper(RT->SetVariable, 5, L"KEK", &global,
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
		kek_len, kek);
	if (EFI_ERROR(status)) {
		Print(L"Failed: %d\n", status);
		uefi_call_wrapper(BS->Stall, 1, 2000000);
		return EFI_SUCCESS;
	} else {
		Print(L"Success\n");
	}

	Print(L"Creating PK: ");
	status = uefi_call_wrapper(RT->SetVariable, 5, L"PK", &global,
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
		pk_len, pk);
	if (EFI_ERROR(status)) {
		Print(L"Failed: %d\n", status);
		uefi_call_wrapper(BS->Stall, 1, 2000000);
		return EFI_SUCCESS;
	} else {
		Print(L"Success\n");
	}

	status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &global,
				   NULL, &size, &byte);
	if (EFI_ERROR(status)) {
		Print(L"Could not read SetupMode variable: %d\n", status);
		uefi_call_wrapper(BS->Stall, 1, 2000000);
		return EFI_SUCCESS;
	}
	Print(L"Platform is in %s Mode\n", byte ? L"Setup" : L"User");

	status = uefi_call_wrapper(RT->GetVariable, 5, L"SecureBoot", &global,
				   NULL, &size, &byte);
	if (EFI_ERROR(status)) {
		Print(L"Could not read SecureBoot variable: %d\n", status);
		uefi_call_wrapper(BS->Stall, 1, 2000000);
		return EFI_SUCCESS;
	}
	Print(L"Platform is %s set to boot securely\n", byte ? L"" : L"not");

	return status;
}
