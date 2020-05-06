#include <iostream>
#include <fstream>
#include <windows.h>

#define ALIGN_DOWN(x, align)  (x & ~(align-1))
#define ALIGN_UP(x, align)    ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)

class PEFile {
private:
    const char* fileName;
    size_t fileSize;
    char* data;
    _IMAGE_DOS_HEADER* pDosHeader = nullptr;
    _IMAGE_NT_HEADERS* pNtHeaders = nullptr; //TODO::тут
    WORD numberOfSections;
    DWORD sectionAligment;
    _IMAGE_SECTION_HEADER* pImageSectionHeader = nullptr;
    int defSection(DWORD rva) {
        for (int i = 0; i < numberOfSections; ++i)
        {
            DWORD start = pImageSectionHeader[i].VirtualAddress;
            DWORD end = start + ALIGN_UP(pImageSectionHeader[i].Misc.VirtualSize, sectionAligment);

            if (rva >= start && rva < end)
                return i;
        }
        return -1;
    }
    DWORD rvaToOff(DWORD rva)
    {
        int indexSection = defSection(rva);
        if (indexSection != -1)
            return rva - pImageSectionHeader[indexSection].VirtualAddress + pImageSectionHeader[indexSection].PointerToRawData;
        else
            return 0;
    }
public:
    PEFile(const char* filePath) {
        fileName = filePath;
        std::ifstream peFile;
        peFile.open(filePath, std::ios::in | std::ios::binary);
        if (!peFile.is_open())
        {
            std::cout << "Can't open file" << std::endl;
            exit(1);
        }

        // get the length of the file
        peFile.seekg(0, std::ios::end);
        fileSize = peFile.tellg();
        peFile.seekg(0, std::ios::beg);

        data = new char[fileSize];
        peFile.read(data, fileSize);
        peFile.close();
        pDosHeader = (_IMAGE_DOS_HEADER*)data;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cout << "Not Portable Executable file!";
            exit(1);
        }
        pNtHeaders = (_IMAGE_NT_HEADERS*)&data[pDosHeader->e_lfanew];  //TODO::тут
        numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
        sectionAligment = pNtHeaders->OptionalHeader.SectionAlignment;
        printf("File digit capacity:\t%s\n", pNtHeaders->OptionalHeader.Magic == 0x10b ? "x32" : "x");
        pImageSectionHeader = (_IMAGE_SECTION_HEADER*)&data[pDosHeader->e_lfanew + sizeof(_IMAGE_NT_HEADERS)]; //TODO::тут
    }
    void printSections() {
        printf("File sections:\n");
        for (int i = 0; i < numberOfSections; ++i) {
            printf("\t%s\n", pImageSectionHeader[i].Name);
        }
    }
    void printTableImports() {
        auto directoryEntryImport = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        DWORD importOffset = rvaToOff(directoryEntryImport.VirtualAddress);
        if (importOffset == 0) {
            printf("There's no table imports :(\n");
            return;
        }
        auto* imageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)&data[importOffset];
        printf("Table imports\n");
        for (int j = 0; imageImportDescriptor[j].Name != 0; ++j) {
            auto rvaName = imageImportDescriptor[j].Name;
            DWORD nameOffset = rvaToOff(rvaName);
            if (nameOffset == 0) {
                std::cout << "How is it possible?" << std::endl;
                exit(1);
            }
            printf("\t%d:\t%s\n", j + 1, &data[nameOffset]);

            auto originalThunkOffset = rvaToOff(imageImportDescriptor[j].OriginalFirstThunk);
            auto pImageOriginalThunkData = (IMAGE_THUNK_DATA32*)&data[originalThunkOffset]; //TODO::тут
            for (int h = 0; pImageOriginalThunkData[h].u1.AddressOfData != 0; ++h) {
                if (pImageOriginalThunkData[h].u1.AddressOfData > 0x80000000) {
                    printf("\t\t\tOrdinal: %x\n", (DWORD)pImageOriginalThunkData[h].u1.AddressOfData);
                }
                else {
                    auto addressOfDataOffset = rvaToOff(pImageOriginalThunkData[h].u1.AddressOfData);
                    auto importByName = (_IMAGE_IMPORT_BY_NAME*)&data[addressOfDataOffset];
                    printf("\t\t\t%s\n", importByName->Name);
                }
            }
        }
    }
    void printBoundImports() {
        auto directoryEntryBoundImport = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
//        DWORD importOffset = rvaToOff(directoryEntryBoundImport.VirtualAddress);
        DWORD importOffset = directoryEntryBoundImport.VirtualAddress;
        if (importOffset == 0) {
            printf("There's no bound imports :(\n");
            return;
        }
        auto *imageBoundImportDescriptor = (_IMAGE_BOUND_IMPORT_DESCRIPTOR*)&data[importOffset];
        printf("Bound imports:\n");
        for (int j = 0; imageBoundImportDescriptor[j].OffsetModuleName != 0; ++j) {
            DWORD nameOffset = imageBoundImportDescriptor[j].OffsetModuleName;
            if (nameOffset == 0) {
                std::cout << "How is it possible?" << std::endl;
                exit(1);
            }
            printf("\t%d:\t%s\n", j + 1, ((char *) imageBoundImportDescriptor) + nameOffset);
            //imageBoundImportDescriptor.
        }
    }

    void printDelayImports() {
        auto directoryEntryDelayImport = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        DWORD importOffset = rvaToOff(directoryEntryDelayImport.VirtualAddress);
        if (importOffset == 0) {
            printf("There's no delay imports :(\n");
            return;
        }
        auto* imageDelayImportDescriptor = (_IMAGE_DELAYLOAD_DESCRIPTOR*)&data[importOffset];
        printf("Delay imports:\n");
        for (int j = 0; imageDelayImportDescriptor[j].DllNameRVA != 0; ++j) {
            auto rvaName = imageDelayImportDescriptor[j].DllNameRVA;
            DWORD nameOffset = rvaToOff(rvaName);
            if (nameOffset == 0) {
                std::cout << "How is it possible?" << std::endl;
                exit(1);
            }
            printf("\t%d:\t%s\n", j + 1, &data[nameOffset]);
        }
    }
};

int main(int argc, const char* argv[]) {
    if (argc != 2) {
        std::cout << "The program argument must contain the path to the file" << std::endl;
        std::getchar();
        return 1;
    }
    PEFile file(argv[1]);
    file.printSections();
    file.printTableImports();
    file.printBoundImports();
    file.printDelayImports();
    return 0;
}

