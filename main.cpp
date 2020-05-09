#include <iostream>
#include <fstream>
#include <windows.h>

#define ALIGN_DOWN(x, align)  (x & ~(align-1))
#define ALIGN_UP(x, align)    ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)

template <class NtHeaders, class ImageThunkData>
class PEFile {
private:
    const char* fileName;
    size_t fileSize;
    char* data;
    _IMAGE_DOS_HEADER* pDosHeader = nullptr;
    NtHeaders* pNtHeaders = nullptr;
    WORD numberOfSections;
    DWORD sectionAligment;
    _IMAGE_SECTION_HEADER* pImageSectionHeader = nullptr;

    //Определение секции по виртуальному адресу
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
    //Конвертация виртуального адреса в оффсет
    DWORD rvaToOff(DWORD rva)
    {
        int indexSection = defSection(rva);
        if (indexSection != -1)
            return rva - pImageSectionHeader[indexSection].VirtualAddress + pImageSectionHeader[indexSection].PointerToRawData;
        else
            return 0;
    }
public:
    PEFile(const char *_fileName, size_t _fileSize, char *_data) {
        fileName = _fileName;
        fileSize = _fileSize;
        data = _data;

        //Проверяем файл на принадлежность к portable executable
        pDosHeader = (_IMAGE_DOS_HEADER*)data;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cout << "Not Portable Executable file!";
            exit(1);
        }
        //Считываем Nt-headers по адресу указанному в DOS-header
        pNtHeaders = (NtHeaders*) &data[pDosHeader->e_lfanew];
        //В Nt-header хранится заголовки и из них мы достаем нужные нам значения (количество секций, выравнивание секции)
        numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
        sectionAligment = pNtHeaders->OptionalHeader.SectionAlignment;
        //После Nt-header идут секции
        pImageSectionHeader = (_IMAGE_SECTION_HEADER*)&data[pDosHeader->e_lfanew + sizeof(NtHeaders)];
    }
    //Вывод имен секций
    void printSections() {
        printf("File sections:\n");
        for (int i = 0; i < numberOfSections; ++i) {
            printf("\t%s\n", pImageSectionHeader[i].Name);
        }
    }
    /**
    * В Optional headers хранятся массив из DataDirectory из которых мы можем обратиться к разным таблицам импорта (и не только) 
    * 3 метода ниже осуществляют вывод всех таблиц импорта (standard, bound, delay)
    */
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
            printf("\t%d:\t%s\n", j + 1, &data[nameOffset]);
            auto originalThunkOffset = rvaToOff(imageImportDescriptor[j].OriginalFirstThunk);
            auto pImageOriginalThunkData = (ImageThunkData*)&data[originalThunkOffset];
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
        DWORD importOffset = directoryEntryBoundImport.VirtualAddress;
        if (importOffset == 0) {
            printf("There's no bound imports :(\n");
            return;
        }
        auto *imageBoundImportDescriptor = (_IMAGE_BOUND_IMPORT_DESCRIPTOR*)&data[importOffset];
        printf("Bound imports:\n");
        for (int j = 0; imageBoundImportDescriptor[j].OffsetModuleName != 0; ++j) {
            DWORD nameOffset = imageBoundImportDescriptor[j].OffsetModuleName;
            printf("\t%d:\t%s\n", j + 1, ((char *) imageBoundImportDescriptor) + nameOffset);
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
            printf("\t%d:\t%s\n", j + 1, &data[nameOffset]);
        }
    }

    void printAllInfo() {
        printSections();
        printTableImports();
        printBoundImports();
        printDelayImports();
    }
};

int main(int argc, const char* argv[]) {
    if (argc != 2) {
        std::cout << "The program argument must contain the path to the file" << std::endl;
        std::getchar();
        return 1;
    }

    std::ifstream peFile;
    peFile.open(argv[1], std::ios::in | std::ios::binary);

    if (!peFile.is_open()) {
        std::cout << "Can't open file" << std::endl;
        exit(1);
    }
    //До того, как создать класс PEfile, нужно понять разрядность файла 
    //И в зависимости от разрядности воспользоваться в соответствующим шаблонным конструктором
    IMAGE_DOS_HEADER header;
    peFile.read((char *) &header, sizeof(IMAGE_DOS_HEADER));
    peFile.seekg(header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    WORD digitalCapacity;
    peFile.read((char *) &digitalCapacity, sizeof(WORD));

    peFile.seekg(0, std::ios::end);
    size_t fileSize = peFile.tellg();
    peFile.seekg(0, std::ios::beg);

    char *data = new char[fileSize];
    peFile.read(data, fileSize);
    peFile.close();

    printf("Magic: 0x%x\n", digitalCapacity);
    if (digitalCapacity == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("File digitalCapacity: x32\n");
        PEFile<IMAGE_NT_HEADERS32, IMAGE_THUNK_DATA32> file(argv[1], fileSize, data);
        file.printAllInfo();
    } else if (digitalCapacity == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("File digitalCapacity: x64\n");
        PEFile<IMAGE_NT_HEADERS64, IMAGE_THUNK_DATA64> file(argv[1], fileSize, data);
        file.printAllInfo();
    } else {
        printf("Can't determine digitalCapacity\n");
        exit(1);
    }

    return 0;
}

