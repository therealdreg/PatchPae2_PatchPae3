#include <ph.h>
#include <imagehlp.h>

#define ARG_OUTPUT 1
#define ARG_TYPE 2

#define TYPE_KERNEL 1
#define TYPE_LOADER 2
#define TYPE_HAL 3

typedef VOID (NTAPI *PPATCH_FUNCTION)(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    );

const PWSTR appver=L"0.0.0.39";

PPH_STRING ArgInput;
PPH_STRING ArgOutput;
PPH_STRING ArgType;

ULONG ArgTypeInteger;

VOID Fail(
    __in PWSTR Message,
    __in ULONG Win32Result
    )
{
    if (Win32Result == 0)
        wprintf(L"%s\n", Message);
    else
        wprintf(L"%s: %s\n", Message, PhGetWin32Message(Win32Result)->Buffer);

    RtlExitUserProcess(STATUS_UNSUCCESSFUL);
}

ULONG GetBuildNumber(
    __in PWSTR FileName
    )
{
    ULONG buildNumber = 0;
    PVOID versionInfo;
    VS_FIXEDFILEINFO *rootBlock;
    ULONG rootBlockLength;

    versionInfo = PhGetFileVersionInfo(FileName);

    if (!versionInfo)
        return 0;

    if (VerQueryValue(versionInfo, L"\\", &rootBlock, &rootBlockLength) && rootBlockLength != 0)
        buildNumber = rootBlock->dwFileVersionLS >> 16;

    PhFree(versionInfo);

    return buildNumber;
}

VOID Patch(
    __in PPH_STRING FileName,
    __in PPATCH_FUNCTION Action
    )
{
    BOOLEAN success;
    PPH_ANSI_STRING ansiFileName;
    LOADED_IMAGE loadedImage;

    ansiFileName = PhCreateAnsiStringFromUnicodeEx(FileName->Buffer, FileName->Length);

    if (!MapAndLoad(ansiFileName->Buffer, NULL, &loadedImage, FALSE, FALSE))
        Fail(L"Unable to map and load image", GetLastError());

    success = FALSE;
    Action(&loadedImage, &success);
    // This will unload the image and fix the checksum.
    UnMapAndLoad(&loadedImage);

    PhDereferenceObject(ansiFileName);

    if (success)
        wprintf(L"Patched.\n");
    else
        Fail(L"Failed.", 0);
}

VOID PatchKernel2600Part1_v1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // cmp ebx,ecx
        0x3B, 0xFB,
        // jnc 0005754EC
        0x73, 0xD9,
        // push 7
        0x6A, 0x07,
        // call ExVerifySuite
        0xE8 //0x**, 0x**, 0x**, 0x**
        // cmp *l,1
        // 0x**, 0x01
        // jnz * 
        // 0x75, 0x07
        // ...
    };
    ULONG movOffset = 13;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz 000575523 -> jz 000575523
            ptr[movOffset] = 0x74;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel2600Part1_v2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // cmp ebx,ecx
        0x3B, 0xD9,
        // jnc 0005754EC
        0x73, 0xDB,
        // push 7
        0x6A, 0x07,
        // call ExVerifySuite
        0xE8 //0x18, 0xC0, 0xEE, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz 000575523 
        // 0x75, 0x07
        // ...
    };
    ULONG movOffset = 13;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz 000575523 -> jz 000575523
            ptr[movOffset] = 0x74;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel2600Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // push 7
        0x6A, 0x07,
        // mov esi,eax
        0x8B, 0xF0,
        // mov [ebp][-4],ebx
        0x89, 0x5D, 0xFC,
        // mov [ebp][-8],edi
        0x89, 0x7D, 0xF8,
        // call ExVerifySuite
        0xE8 //0xE1, 0xFC, 0xE8, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz 0005D186E 
        // 0x75, 0x1B
        // ...
    };
    ULONG movOffset = 17;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jnz 0005D186E -> jz 0005D186E
            ptr[movOffset] = 0x74;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel2600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchKernel2600Part1_v1(LoadedImage, &success1);
	if (!success1)
	{
		PatchKernel2600Part1_v2(LoadedImage, &success1);
	}
    PatchKernel2600Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}

VOID PatchKernel3790Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : BF 00 00 00 02 6A 0A C7 45 FC 00 00 10 00
	// Replacepattern : ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? 00 10
{
    UCHAR target[] =
    {
        // mov edi, 02.00.00.00 -> mov edi, 10.00.00.00
        0xBF, 0x00, 0x00, 0x00, 0x02,
        // push 0A
        0x6A, 0x0A,
        // mov [ebp][-4], 00.10.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x10, 0x00
        // mov [ebp][-8],edi
        // 0x89, 0x7D, 0xF8,
        // call ExVerifySuite
        // 0xE8, 0xCC, 0xD3, 0xE6, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz ...
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  3] = 0x00;
            ptr[movOffset +  4] = 0x10;
            ptr[movOffset + 12] = 0x00;
            ptr[movOffset + 13] = 0x10;
			//wprintf(L"part1\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko (pattern fix by evgen_b)
	// Searchpattern  : 75 09 C7 45 FC 00 00 08 00 EB 69 6A 07 E8
	// Replacepattern : ?? ?? ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ??
{
    UCHAR target[] =
    {
        // jnz 000612D97
        0x75, 0x09,
        // mov [ebp][-4], 00.08.00.00 -> mov [	ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x08, 0x00,
        // jmps 000612E00
        0xEB, 0x69,
        // push 07
        0x6A, 0x07,
        // call ExVerifySuite
        0xE8 // 0xB8, 0xD3, 0xE6, 0xFF
        // cmp al,1
        // 0x3C, 0x01
        // jnz ...
    };
    ULONG movOffset = 7;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset]   = 0x00;
            ptr[movOffset+1] = 0x10;
			//wprintf(L"part2\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part3(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : C7 45 FC 00 00 00 01 74 33 B8 00 00 40 00
	// Replacepattern : ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? 00 10
{
    UCHAR target[] =
    {
        // mov [ebp][-4], 01.00.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x01,
        // jz 00612E00
        0x74, 0x33,
		// mov eax, 00.40.00.00 -> mov eax, 10.00.00.00
		0xB8, 0x00, 0x00, 0x40, 0x00
		// mov [ebp][-4],eax
		// 0x89, 0x45, 0xFC,
		// mov [ebp][-8],eax
		// 0x89, 0x45, 0xF8,
        // jmps 000612E00
        // 0xEB, 0x26
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  5] = 0x00;
            ptr[movOffset +  6] = 0x10;
            ptr[movOffset + 12] = 0x00;
            ptr[movOffset + 13] = 0x10;
			//wprintf(L"part3\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part4(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : C7 45 FC 00 00 10 00 74 10 C7 45 F8 00 00 40 00
	// Replacepattern : ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ?? ?? ?? 00 10
{
    UCHAR target[] =
    {
        // mov [ebp][-4], 00.10.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x10, 0x00,
        // jz 00612E00
        0x74, 0x10,
		// mov [ebp][-8], 00.40.00.00 -> mov [ebp][-8], 10.00.00.00
		0xC7, 0x45, 0xF8, 0x00, 0x00, 0x40, 0x00
		// jmps 00612E00
		// 0xEB, 0x07
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  5] = 0x00;
            ptr[movOffset +  6] = 0x10;
            ptr[movOffset + 14] = 0x00;
            ptr[movOffset + 15] = 0x10;
			//wprintf(L"part4\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790Part5(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// Yet another method by Oliver/Remko
	// Searchpattern  : C7 45 F8 00 00 10 00 33 F6 83 C3 08 8B 03
	// Replacepattern : ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ?? ?? ??
{
    UCHAR target[] =
    {
        // mov [ebp][-8], 00.10.00.00 -> mov [ebp][-4], 10.00.00.00
        0xC7, 0x45, 0xF8, 0x00, 0x00, 0x10, 0x00,
        // xor esi,esi
        0x33, 0xF6,
		// add ebx,8
		0x83, 0xC3, 0x08,
		// mov eax,[ebx]
		0x8B, 0x03
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset +  5] = 0x00;
            ptr[movOffset +  6] = 0x10;
			//wprintf(L"part5\n");

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchKernel3790(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;
    BOOLEAN success3 = FALSE;
    BOOLEAN success4 = FALSE;
    BOOLEAN success5 = FALSE;

    PatchKernel3790Part1(LoadedImage, &success1);
    PatchKernel3790Part2(LoadedImage, &success2);
    PatchKernel3790Part3(LoadedImage, &success3);
    PatchKernel3790Part4(LoadedImage, &success4);
    PatchKernel3790Part5(LoadedImage, &success5);
    *Success = success1 && success2 && success3 && success4 && success5;
}

VOID PatchKernel(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did ZwQueryLicenseValue succeed?
        0x85, 0xc0,
        // jl short loc_75644b ; if it didn't go to the default case
        0x7c, 0x11,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_75644b ; if it's zero, go to the default case
        0x74, 0x0a,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // 0xa3, 0x2c, 0x76, 0x53, 0x00
        // jmp short loc_756455 ; go to the next bit
        // 0xeb, 0x0a
        // loc_75644b: mov ds:_MiTotalPagesAllowed, 0x80000
        // 0xc7, 0x05, 0x2c, 0x76, 0x53, 0x00, 0x00, 0x00, 0x08, 0x00
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

VOID PatchKernel9200(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_914314 ; if it didn't go to the default case
        0x78, 0x4c,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_914314 ; if it's zero, go to the default case
        0x74, 0x45,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // ...
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

VOID PatchKernel9600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_923593 ; if it didn't go to the default case
        0x78, 0x50,
        // mov eax, [ebp+var_4] ; get the returned memory limit
        0x8b, 0x45, 0xfc,
        // test eax, eax ; is it non-zero?
        0x85, 0xc0,
        // jz short loc_923593 ; if it's zero, go to the default case
        0x74, 0x49,
        // shl eax, 8 ; multiply by 256
        0xc1, 0xe0, 0x08
        // mov ds:_MiTotalPagesAllowed, eax ; store in MiTotalPagesAllowed
        // ...
    };
    ULONG movOffset = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, k;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j] && j != 3 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov eax, [ebp+var_4] -> mov eax, 0x20000
            ptr[movOffset] = 0xb8;
            *(PULONG)&ptr[movOffset + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset + 5] = 0x90;
            ptr[movOffset + 6] = 0x90;

            // Do the same thing to the next mov eax, [ebp+var_4] 
            // occurence.
            for (k = 0; k < 100; k++)
            {
                if (
                    ptr[k] == 0x8b &&
                    ptr[k + 1] == 0x45 &&
                    ptr[k + 2] == 0xfc &&
                    ptr[k + 3] == 0x85 &&
                    ptr[k + 4] == 0xc0
                    )
                {
                    // mov eax, [ebp+var_4] -> mov eax, 0x20000
                    ptr[k] = 0xb8;
                    *(PULONG)&ptr[k + 1] = 0x20000;
                    // nop out the jz
                    ptr[k + 5] = 0x90;
                    ptr[k + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
            }

            break;
        }

        ptr++;
    }
}

VOID PatchKernel10240(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// 10240 - win10 RTM (evgen_b)
{
    // MxMemoryLicense

    // Basically, the portion of code we are going to patch 
    // queries the NT license value for the allowed memory.
    // If there is a limit, it sets MiTotalPagesAllowed to 
    // that limit times 256. If there is no specified limit, 
    // it sets MiTotalPagesAllowed to 0x80000 (2 GB).
    //
    // We will patch the limit to be 0x20000 << 8 pages (128 GB).

    UCHAR target1[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_009BCC3B ; if it didn't go to the default case
        0x78, 0x46,
        // mov esi, [ebp-4] ; get the returned memory limit
        0x8b, 0x75, 0xfc,
        // test esi, esi ; is it non-zero?
        0x85, 0xf6,
        // jz short loc_009BCC3B ; if it's zero, go to the default case
        0x74, 0x3f,
        // shl esi, 8 ; multiply by 256
        0xc1, 0xe6, 0x08
        // mov ds:_MiTotalPagesAllowed, esi ; store in MiTotalPagesAllowed
        // ...
    };

    UCHAR target2[] =
    {
        // test eax, eax ; did NtQueryLicenseValue succeed?
        0x85, 0xc0,
        // js short loc_009BCC32 ; if it didn't go to the default case
        0x78, 0x0d,
        // mov ecx, [ebp-4] ; get the returned memory limit
        0x8b, 0x4d, 0xfc,
        // test ecx, ecx ; is it non-zero?
        0x85, 0xc9,
        // jz short loc_009BCC32 ; if it's zero, go to the default case
        0x74, 0x06,
        // shl ecx, 8 ; multiply by 256
        0xc1, 0xe1, 0x08
        // mov ds:_MiTotalPagesAllowed, ecx ; store in MiTotalPagesAllowed
        // ...
    };

    ULONG movOffset1 = 4;
    ULONG movOffset2 = 4;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j, m, n;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target1); i++)
    {
        for (j = 0; j < sizeof(target1); j++)
        {
            if (ptr[j] != target1[j] && j != 3 && j != 10) // ignore jump offsets
                break;
        }

        if (j == sizeof(target1))
        {
            // Found it. Patch the code.

            // mov esi, [ebp+var_4] -> mov esi, 0x020000
            ptr[movOffset1] = 0xbe;
            *(PULONG)&ptr[movOffset1 + 1] = 0x20000;
            // nop out the jz
            ptr[movOffset1 + 5] = 0x90;
            ptr[movOffset1 + 6] = 0x90;

            // Do the same thing to the next mov ecx, [ebp+var_4] 
            // occurence.
            for (m = 0; m < 100; m++)
            {
				for (n = 0; n < sizeof(target2); n++)
				{
					if (ptr[n] != target2[n] && n != 3 && n != 10) // ignore jump offsets
						break;
				}

				if (n == sizeof(target2))
                {
                    // mov ecx, [ebp+var_4] -> mov ecx, 0x020000
                    ptr[movOffset2] = 0xb9;
                    *(PULONG)&ptr[movOffset2 + 1] = 0x20000;
                    // nop out the jz
                    ptr[movOffset2 + 5] = 0x90;
                    ptr[movOffset2 + 6] = 0x90;

                    *Success = TRUE;

                    break;
                }
				ptr++;
            }

            break;
        }

        ptr++;
    }
}

VOID PatchLoader(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadPEImageEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch BlImgLoadPEImageEx so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // sub esi, [ebx+4]
        0x2b, 0x73, 0x04,
        // push eax
        0x50,
        // add esi, [ebp+var_18]
        0x03, 0x75, 0xe8,
        // lea eax, [ebp+Source1]
        0x8d, 0x45, 0x8c,
        // push eax
        0x50,
        // push esi
        0x56,
        // mov eax, ebx
        0x8b, 0xc3
        // call _ImgpValidateImageHash@16
        // 0xe8, 0x59, 0x0b, 0x00, 0x00
        // mov ecx, eax ; copy return status into ecx
        // test ecx, ecx ; did ImgpValidateImageHash succeed?
        // mov [ebp+arg_0], ecx ; store the NT status into a variable
        // jge short loc_42109f ; if the function succeeded, go there
    };
    ULONG movOffset = 19;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov ecx, eax -> mov [ebp+arg_0], 0
            // 0x8b, 0xc8 -> 0xc7, 0x45, 0x08, 0x00, 0x00, 0x00, 0x00
            ptr[movOffset] = 0xc7;
            ptr[movOffset + 1] = 0x45;
            ptr[movOffset + 2] = 0x08;
            ptr[movOffset + 3] = 0x00;
            ptr[movOffset + 4] = 0x00;
            ptr[movOffset + 5] = 0x00;
            ptr[movOffset + 6] = 0x00;
            // jge short loc_42109f -> jmp short loc_42109f
            // 0x85, 0xc9 -> 0xeb, 0xc9
            ptr[movOffset + 7] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader7600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadPEImage

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch BlImgLoadPEImage so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // push eax
        0x50,
        // lea eax, [ebp+Source1]
        0x8d, 0x85, 0x94, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push [ebp+var_12c]
        0xff, 0xb5, 0xd4, 0xfe, 0xff, 0xff,
        // mov eax, [ebp+var_24]
        0x8b, 0x45, 0xdc,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // call _ImgpValidateImageHash@24
        // 0xe8, 0x63, 0x05, 0x00, 0x00
        // mov [ebp+var_8], eax ; copy return status into var_8
        // 0x89, 0x45, 0xf8
        // test eax, eax ; did ImgpValidateImageHash succeed?
        // 0x85, 0xc0
        // jge short loc_428ee5 ; if the function succeeded, go there
        // 0x7d, 0x2e
    };
    ULONG jgeOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that we don't need to update var_8 as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

            // jge short loc_428ee5 -> jmp short loc_428ee5
            // 0x7d, 0x2e -> 0xeb, 0x2e
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader7601_noKB(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage so that it doesn't care 
    // what the result of the function is.

    UCHAR target[] =
    {
        // push eax
        0x50,
        // lea eax, [ebp+Source1]
        0x8d, 0x85, 0x94, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push [ebp+var_12c]
        0xff, 0xb5, 0xd4, 0xfe, 0xff, 0xff,
        // mov eax, [ebp+var_24]
        0x8b, 0x45, 0xdc,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // call _ImgpValidateImageHash@24
        // 0xe8, 0x63, 0x05, 0x00, 0x00
        // mov [ebp+var_8], eax ; copy return status into var_8
        // 0x89, 0x45, 0xf8
        // test eax, eax ; did ImgpValidateImageHash succeed?
        // 0x85, 0xc0
        // jge short loc_428f57 ; if the function succeeded, go there
        // 0x7d, 0x2e
    };
    ULONG jgeOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that we don't need to update var_8 as it is 
            // a temporary status variable which will be overwritten 
            // very shortly.

            // jge short loc_428f57 -> jmp short loc_428f57
            // 0x7d, 0x2e -> 0xeb, 0x2e
            ptr[jgeOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader7601_KB3033929(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// fix for KB3033929 (evgen_b)
{
	// ImgpLoadPEImage

	// There is a function called ImgpValidateImageHash. We are 
	// going to patch ImgpLoadPEImage so that it doesn't care 
	// what the result of the function is.

	UCHAR target[] =
	{
		// push d,[ebp][-014]
		0xFF, 0x75, 0xEC,
		// lea eax,[ebp][-00000017C] ; [ebp+Source1]
		0x8D, 0x85, 0x84, 0xFE, 0xFF, 0xFF,
		// push eax
		0x50,
		// push d,[ebp][-028]
		0xFF, 0x75, 0xD8,
		// mov eax,[ebp][8]
		0x8B, 0x45, 0x08,
		// push d,[eax][00C]
		0xFF, 0x70, 0x0C,
		// lea eax,[ebp][-064]
		0x8D, 0x45, 0x9C,
		// call _ImgpValidateImageHash@24
		// E8, 5F, 05, 00, 00
		// mov [ebp][-8],eax ; copy return status into var_8
		// 0x89, 0x45, 0xf8
		// test eax, eax ; did ImgpValidateImageHash succeed?
		// 0x85, 0xc0
		// jge short 000428EDE ; if the function succeeded, go there
		// 0x7d, 0x2e -> EB, 2E
	};
	ULONG jgeOffset = 32;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j])
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.
			// Note that we don't need to update var_8 as it is 
			// a temporary status variable which will be overwritten 
			// very shortly.

			// jge short 000428EDE -> jmp short 000428EDE
			// 0x7d, 0x2e -> 0xeb, 0x2e
			ptr[jgeOffset] = 0xeb;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader7601(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
{
	// first, call normal patch, and if it fail, call fixed for KB3033929 patch (evgen_b)

	BOOLEAN success = FALSE;

	PatchLoader7601_noKB(LoadedImage, &success);
	if (!success)
	{
		PatchLoader7601_KB3033929(LoadedImage, &success);
	}
	*Success = success;
}

VOID PatchLoader9200Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    UCHAR target[] =
    {
        // push eax
        0x50,
        // push [ebp+var_14]
        0xff, 0x75, 0xec,
        // lea eax, [ebp+var_13c]
        0x8d, 0x85, 0xc4, 0xfe, 0xff, 0xff,
        // push eax
        0x50,
        // push ecx
        0x51,
        // push dword ptr [esi+0ch]
        0xff, 0x76, 0x0c,
        // lea eax, [ebp+var_74]
        0x8d, 0x45, 0x8c,
        // call _ImgpValidateImageHash@24
        // 0xe8, 0x4f, 0x06, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_43411d ; if the function succeeded, go there
        // 0x79, 0x2c
    };
    ULONG jnsOffset = 27;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short loc_43411d -> jmp short loc_43411d
            // 0x79, 0x2c -> 0xeb, 0x2c
            ptr[jnsOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9200Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgressEx

    UCHAR target[] =
    {
        // push 0
        0x6a, 0x00,
        // push [ebp+var_18]
        0xff, 0x75, 0xe8,
        // lea eax, [ebp+var_78]
        0x8d, 0x45, 0x88,
        // push eax
        0x50,
        // push [ebp+var_150]
        0xff, 0xb5, 0xb0, 0xfe, 0xff, 0xff,
        // xor eax, eax
        0x33, 0xc0,
        // push [ebp+arg_8]
        0xff, 0x75, 0x10
        // call _ImgpValidateImageHash@24
        // 0xe8, 0xe6, 0x13, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_433374 ; if the function succeeded, go there
        // 0x79, 0x1a
    };
    ULONG movOffset = 25;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov ebx, eax -> xor ebx, ebx
            // 0x8b, 0xd8 -> 0x33, 0xdb
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xdb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9200(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage and BlImgLoadImageWithProgressEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
    // so that they don't care what the result of the function is.

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchLoader9200Part1(LoadedImage, &success1);
    PatchLoader9200Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}

VOID PatchLoader9600Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage

    UCHAR target[] =
    {
        // push eax
        0x50,
        // push [ebp+var_78]
        0xff, 0x75, 0x88,
        // lea eax, [ebp+var_148]
        0x8d, 0x85, 0xb8, 0xfe, 0xff, 0xff,
        // push [ebp+var_14]
        0xff, 0x75, 0xec,
        // push eax
        0x50,
        // mov eax, [ebp+var_30]
        0x8b, 0x45, 0xd0,
        // push ecx
        0x51,
        // mov ecx, [eax+0ch]
        0x8b, 0x48, 0x0c,
        // call _ImgpValidateImageHash@32
        // 0xe8, 0x3a, 0x08, 0x00, 0x00
        // mov ebx, eax
        // 0x8b, 0xd8
        // test ebx, ebx ; did ImgpValidateImageHash succeed?
        // 0x85, 0xdb
        // jns short loc_434bc2 ; if the function succeeded, go there
        // 0x79, 0x2d
    };
    ULONG jnsOffset = 30;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.
            // Note that eax and ebx are not used later, so we can ignore them.

            // jns short loc_434bc2 -> jmp short loc_434bc2
            // 0x79, 0x2d -> 0xeb, 0x2d
            ptr[jnsOffset] = 0xeb;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9600Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // BlImgLoadImageWithProgress2

    UCHAR target[] =
    {
        // push 0
        0x6a, 0x00,
        // push 0
        0x6a, 0x00,
        // push [ebp+var_30]
        0xff, 0x75, 0xd0,
        // xor edx, edx
        0x33, 0xd2,
        // push [ebp+var_20]
        0xff, 0x75, 0xe0,
        // push eax
        0x50,
        // push [ebp+var_164]
        0xff, 0xb5, 0x9c, 0xfe, 0xff, 0xff,
        // call _ImgpValidateImageHash@32
        // 0xe8, 0x35, 0x17, 0x00, 0x00
        // mov esi, eax
        // 0x8b, 0xf0
        // test esi, esi ; did ImgpValidateImageHash succeed?
        // 0x85, 0xf6
        // jns short loc_433cec ; if the function succeeded, go there
        // 0x79, 0x52
    };
    ULONG movOffset = 24;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // mov esi, eax -> xor esi, esi
            // 0x8b, 0xf0 -> 0x33, 0xf6
            ptr[movOffset] = 0x33;
            ptr[movOffset + 1] = 0xf6;

            *Success = TRUE;

            break;
        }

        ptr++;
    }
}

VOID PatchLoader9600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{
    // ImgpLoadPEImage and BlImgLoadImageWithProgressEx

    // There is a function called ImgpValidateImageHash. We are 
    // going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
    // so that they don't care what the result of the function is.

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchLoader9600Part1(LoadedImage, &success1);
    PatchLoader9600Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}

VOID PatchLoader10240Part1(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 10240 - win10 RTM (evgen_b)
{
	// ImgpLoadPEImage
	UCHAR target[] =
	{
		// lea eax,[ebp][-018]
		0x8D, 0x45, 0xE8,
		// push eax
		0x50,
		// lea esi,[ebp][-0BC]
		0x8D, 0xB5, 0x44, 0xFF, 0xFF, 0xFF,
		// mov eax,800C
		0xB8, 0x0C, 0x80, 0x00, 0x00,
		// lea edi,[ebp][-104]
		0x8D, 0xBD, 0xFC, 0xFE, 0xFF, 0xFF,
		// mov edx,eax
		0x8B, 0xD0,
		// rep movsd
		0xF3, 0xA5,
		// push eax
		0x50,
		// lea ecx,[ebp][-0BC]
		0x8D, 0x8D, 0x44, 0xFF, 0xFF, 0xFF,
		// call _ImgpValidateImageHash@32
		// 0xE8, 0x__, 0x__, 0x__, 0x__
		// mov ebx, eax
		// 0x8b, 0xd8
		// test ebx, ebx ; did ImgpValidateImageHash succeed?
		// 0x85, 0xdb
		// jns short loc_... ; if the function succeeded, go there
		// 0x79, 0x24
	};
	ULONG jnsOffset = 41;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j])
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.
			// Note that eax and ebx are not used later, so we can ignore them.

			// jns short loc_... -> jmp short loc_...
			// 0x79, 0x24 -> 0xeb, 0x24
			ptr[jnsOffset] = 0xeb;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader10240Part2(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 10240 - win10 RTM (evgen_b)
{
	// BlImgLoadImageWithProgress2

	UCHAR target[] =
	{
		// push eax
		0x50,
		// push d,[ebp][-090]
		0xFF, 0xB5, 0x70, 0xFF, 0xFF, 0xFF,
		// lea eax,[ebp][-178]
		0x8D, 0x85, 0x88, 0xFE, 0xFF, 0xFF,
		// push d,[ebp][-010]
		0xFF, 0x75, 0xF0,
		// push eax
		0x50,
		// push ecx
		0x51,
		// lea eax,[ebp][-0BC]
		0x8D, 0x85, 0x44, 0xFF, 0xFF, 0xFF,
		// push eax
		0x50,
		// mov eax,[ebp][-030]
		0x8B, 0x45, 0xd0,
		// push esi
		0x56,
		// mov ecx,[eax][00C]
		0x8B, 0x48, 0x0C,
		// call _ImgpValidateImageHash@32
		// 0xE8, 0x__, 0x__, 0x__, 0x__
		// mov ebx,eax
		// 0x8B, 0xD8
		// test ebx,ebx ; did ImgpValidateImageHash succeed?
		// 0x85, 0xDB
		// js loc_... ; if the function succeeded, go there
		// 0x0F, 0x88, 0x9F, 0x00, 0x00, 0x00
	};
	ULONG movOffset = 37;
	PUCHAR ptr = LoadedImage->MappedAddress;
	ULONG i, j;

	for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
	{
		for (j = 0; j < sizeof(target); j++)
		{
			if (ptr[j] != target[j])
				break;
		}

		if (j == sizeof(target))
		{
			// Found it. Patch the code.

			// mov ebx,eax -> xor ebx,ebx
			// 0x8B, 0xD8 -> 0x31, 0xDB
			ptr[movOffset] = 0x31;
			ptr[movOffset + 1] = 0xDB;

			*Success = TRUE;

			break;
		}

		ptr++;
	}
}

VOID PatchLoader10240(
	__in PLOADED_IMAGE LoadedImage,
	__out PBOOLEAN Success
	)
	// 10240 - win10 RTM
{
	// ImgpLoadPEImage and BlImgLoadImageWithProgressEx

	// There is a function called ImgpValidateImageHash. We are 
	// going to patch ImgpLoadPEImage and BlImgLoadImageWithProgressEx
	// so that they don't care what the result of the function is.

	BOOLEAN success1 = FALSE;
	BOOLEAN success2 = FALSE;

	PatchLoader10240Part1(LoadedImage, &success1);
	PatchLoader10240Part2(LoadedImage, &success2);
	*Success = success1 && success2;
}

VOID PatchHAL2600Part1(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // mov cl,[edi][5]
        0x8A, 0x4F, 0x05,
        // test cl,cl
        0x84, 0xC9,
        // push ebx
        0x53,
        // jz 08002782C
        0x74, 0x17,
        // cmp b,[0800232B8],0
        0x80, 0x3D // 0xB8, 0x32, 0x02, 0x80, 0x00
        // ...
    };
    ULONG movOffset = 6;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            // jz 08002782C -> jmps 08002782C
            ptr[movOffset] = 0xEB;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchHAL2600Part2(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
	// reversing XP64G.EXE (evgen_b)
{
    // China patch

    UCHAR target[] =
    {
        // push 1
        0x6A, 0x01,
        // push 010                       --> push 030
        0x6A, 0x10,                    // --> 6A 30
        // push 001000000                 --> push -1
        0x68, 0x00, 0x00, 0x00, 0x01,  // --> 68 FF FF FF FF
        // push ebx
        0x53
        // mov d,[0800232C4],000000040    --> mov d,[0800232C4],000004000
        // 0xC7, 0x05, 0xC4, 0x32, 0x02, 0x80, 0x40, 0x00, 0x00, 0x00 -- > C7 05 C4 32 02 80 00 40 00 00
        // mov esi,00010000               --> mov esi,00030000
        // 0xBE, 0x00, 0x00, 0x01, 0x00   --> BE 00 00 03 00
        // call 08002D68E
        // 0xE8, 0x70, 0xF9, 0xFF, 0xFF
        // ...
    };
    ULONG movOffset = 0;
    PUCHAR ptr = LoadedImage->MappedAddress;
    ULONG i, j;

    for (i = 0; i < LoadedImage->SizeOfImage - sizeof(target); i++)
    {
        for (j = 0; j < sizeof(target); j++)
        {
            if (ptr[j] != target[j])
                break;
        }

        if (j == sizeof(target))
        {
            // Found it. Patch the code.

            ptr[movOffset+03] = 0x30;
            *(PULONG)&ptr[movOffset+05] = 0xFFFFFFFF;
            ptr[movOffset+16] = 0x00;
            ptr[movOffset+17] = 0x40;
            ptr[movOffset+23] = 0x03;

            *Success = TRUE;
            break;
        }

        ptr++;
    }
}

VOID PatchHAL2600(
    __in PLOADED_IMAGE LoadedImage,
    __out PBOOLEAN Success
    )
{

    BOOLEAN success1 = FALSE;
    BOOLEAN success2 = FALSE;

    PatchHAL2600Part1(LoadedImage, &success1);
    PatchHAL2600Part2(LoadedImage, &success2);
    *Success = success1 && success2;
}


VOID HelpType()
{
	wprintf(
	L"Usage: PatchPae -type kernel -o ntkrnlpx.exe ntkrnlpa.exe\n"
	L"       PatchPae -type loader -o winloadx.exe winload.exe\n"
	);
}

BOOLEAN CommandLineCallback(
    __in_opt PPH_COMMAND_LINE_OPTION Option,
    __in_opt PPH_STRING Value,
    __in_opt PVOID Context
    )
{
    if (Option)
    {
        switch (Option->Id)
        {
        case ARG_OUTPUT:
            PhSwapReference(&ArgOutput, Value);
            break;
        case ARG_TYPE:
            PhSwapReference(&ArgType, Value);
            break;
        }
    }
    else
    {
        if (!ArgInput)
            PhSwapReference(&ArgInput, Value);
    }

    return TRUE;
}

int __cdecl main(int argc, char *argv[])
{
    static PH_COMMAND_LINE_OPTION options[] =
    {
        { ARG_OUTPUT, L"o", MandatoryArgumentType },
        { ARG_TYPE, L"type", MandatoryArgumentType }
    };

    PH_STRINGREF commandLine;
    ULONG buildNumber;

    if (!NT_SUCCESS(PhInitializePhLibEx(0, 0, 0)))
        return 1;

    PhUnicodeStringToStringRef(&NtCurrentPeb()->ProcessParameters->CommandLine, &commandLine);
    PhParseCommandLine(&commandLine, options, sizeof(options) / sizeof(PH_COMMAND_LINE_OPTION), PH_COMMAND_LINE_IGNORE_FIRST_PART, CommandLineCallback, NULL);

	wprintf(L"\nPatchPae2 by wj32 (support for win vista, 7, 8, 8.1, serv 2008)\n"
	L"evgen_b MOD: added support for win xp, win 7 with KB3033929, win 10, serv 2003\n");
	wprintf(L"Version: %s\n\n", appver);

    if (argc == 1)
    {
		HelpType();	
		return 2;
    }

    ArgTypeInteger = TYPE_KERNEL;

    if (ArgType)
    {
        if (PhEqualString2(ArgType, L"kernel", TRUE))
            ArgTypeInteger = TYPE_KERNEL;
        else if (PhEqualString2(ArgType, L"loader", TRUE))
            ArgTypeInteger = TYPE_LOADER;
        else if (PhEqualString2(ArgType, L"hal", TRUE))
            ArgTypeInteger = TYPE_HAL;
        else
            Fail(L"Wrong type. Must be \"kernel\", \"hal\" or \"loader\".", 0);
    }

    if (PhIsNullOrEmptyString(ArgInput))
        Fail(L"Input file not specified!", 0);
    if (PhIsNullOrEmptyString(ArgOutput))
        Fail(L"Output file not specified!", 0);

    if (!CopyFile(ArgInput->Buffer, ArgOutput->Buffer, FALSE))
        Fail(L"Unable to copy file", GetLastError());

    if (!(buildNumber = GetBuildNumber(ArgOutput->Buffer)))
        Fail(L"Unable to get the build number of the file.", 0);

    if (ArgTypeInteger == TYPE_KERNEL)
    {
        if (buildNumber == 2600)
			// win xp
            Patch(ArgOutput, PatchKernel2600);
		else if ((buildNumber > 3700) && (buildNumber < 3800))
			// server 2003
			Patch(ArgOutput, PatchKernel3790);
        else if ((buildNumber >= 6000) && (buildNumber < 9200))
			// vista, server 2008, 7
            Patch(ArgOutput, PatchKernel);
        else if (buildNumber == 9200)
			// win 8
            Patch(ArgOutput, PatchKernel9200);
        else if (buildNumber == 9600)
			// win 8.1
            Patch(ArgOutput, PatchKernel9600);
		else if (buildNumber = 10240)
			// win 10 RTM 10240
			Patch(ArgOutput, PatchKernel10240);
		else
            Fail(L"Unsupported kernel version.", 0);
    }
	else if (ArgTypeInteger == TYPE_HAL)
	{
        if (buildNumber == 2600)
			Patch(ArgOutput, PatchHAL2600);
		else
            Fail(L"Unsupported HAL version.", 0);
	}
    else
    {
        if (buildNumber < 7600)
			// win Vista
            Patch(ArgOutput, PatchLoader);
        else if (buildNumber == 7600)
			// win 7 w/o SP
            Patch(ArgOutput, PatchLoader7600);
        else if (buildNumber == 7601)
			// win 7 SP1
            Patch(ArgOutput, PatchLoader7601);
        else if (buildNumber == 9200)
			// win 8
            Patch(ArgOutput, PatchLoader9200);
        else if (buildNumber == 9600)
			// win 8.1
            Patch(ArgOutput, PatchLoader9600);
		else if (buildNumber = 10240)
			// win 10 RTM 10240
			Patch(ArgOutput, PatchLoader10240);
		else
            Fail(L"Unsupported loader version.", 0);
    }

    return 0;
}
