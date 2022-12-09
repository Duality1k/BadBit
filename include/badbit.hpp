/*
    BadBit is a single header PE libray made from https://github.com/veil3 under MIT license
*/

#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>

// support for xor, if not included before this header then its going to use an empty xorstr_ macro
#ifndef xorstr_
#define xorstr_
#endif

#define SECTION_SIZE 0x28

namespace badbit
{
    class Binary
    {
    private:
        std::vector<byte> vBuffer;
        std::uintptr_t vbufBase = 0;

        bool bInitializedSections = false;
        std::vector<PIMAGE_SECTION_HEADER> vSections;

        // read the binary as a std::vector<byte>
        auto vecReadFile() -> bool
        {
            // open file as ios::binary, since it's an executable ofc
            std::ifstream file(this->FilePath, std::ios::binary);
            if (file.fail()) {
                throw std::runtime_error(xorstr_("invalid target file path"));
                return false;
            }

            if (!file.is_open()) {
                throw std::runtime_error(xorstr_("failed to open target file"));
                return false;
            }

            // skip leading whitespaces, only affects performance (in a good way)
            file.unsetf(std::ios::skipws);

            std::streampos fileSize;
            file.seekg(0, std::ios::end);
            fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            // write stream to buffer
            vBuffer.insert(vBuffer.begin(),
                std::istream_iterator<byte>(file),
                std::istream_iterator<byte>()
            );

            return true;
        }

    public:
        std::wstring FilePath;
        std::wstring FileName;

        PIMAGE_DOS_HEADER pDosHeader = nullptr;
        PIMAGE_NT_HEADERS pNtHeaders = nullptr;

        explicit Binary(const std::wstring filePath) : FilePath(filePath) {
            // get only the fileName (with extension) from the full path
            this->FileName = filePath.substr(filePath.find_last_of(xorstr_(L"/\\")) + 1);
            this->vecReadFile();
            this->vbufBase = reinterpret_cast<std::uintptr_t>(vBuffer.data());
        }

        // get the dos header from the binary's PE
        auto FindDosHeader() -> bool {
            if (!this->vbufBase) {
                throw std::runtime_error(xorstr_("failed to find DOS header, something went wrong"));
                return false;
            }

            // read the dos header from the buffer
            this->pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(this->vbufBase);
            // if e_magic matches IMAGE_DOS_SIGNATURE then dos header is correct
            return this->pDosHeader->e_magic == IMAGE_DOS_SIGNATURE;
        }

        // get the nt headers from the binary's PE
        auto FindNtHeaders() -> bool {
            if (!this->vbufBase || !this->pDosHeader) {
                throw std::runtime_error(xorstr_("failed to find NT headers, double check you're initializing the dos header"));
                return false;
            }

            // read the nt headers from the buffer
            this->pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(this->vbufBase + this->pDosHeader->e_lfanew);
            // if Signature matches IMAGE_NT_SIGNATURE then nt headers is correct
            return this->pNtHeaders->Signature == IMAGE_NT_SIGNATURE;
        }

        // get all image sections from the binary's PE, unless allowMultipleInit is set to true,
        // you won't be able to call this function twice to prevent mistakes
        auto FindSections(bool allowMultipleInit = false) -> bool
        {
            if (bInitializedSections && !allowMultipleInit) {
                throw std::runtime_error(xorstr_("could not initialize sections list twice, if this was intentional, use allowMultipleInit parameter"));
                return false;
            }

            if (!this->pNtHeaders) {
                throw std::runtime_error(xorstr_("failed to find NT headers, double check you're initializing the dos header"));
                return false;
            }

            // get the very first section
            auto pSectionHeader = IMAGE_FIRST_SECTION(this->pNtHeaders);

            // iterate sections, since the sections are PIMAGE_SECTION_HEADER (pointer), we can just increase ptr by 1 to get the next one
            for (int i = 0; i < this->pNtHeaders->FileHeader.NumberOfSections; i++)
            {
                // since some sections (like .textbss) might have 0x0 on some properties, the only "safe" thing
                // to check would be the section name, here, we check if
                // the byte pointer exists OR if the first char isn't a dot (which should be)
                if (!pSectionHeader->Name || pSectionHeader->Name[0] != '.') {
                    throw std::runtime_error(xorstr_("invalid section at index: ") + std::to_string(i));
                    return false;
                }

                // add the PIMAGE_SECTION_HEADER to the vSections vector
                vSections.push_back(pSectionHeader);
                // increase the section pointer to read the next one
                pSectionHeader++;
            }

            return true;
        }

        // Strips all debug information from the executable.
        auto ClearDebugDirectory() -> bool {

            // Get the debug directory from the PE header
            PIMAGE_DATA_DIRECTORY DataDebugDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

            if (DataDebugDir->Size == NULL || DataDebugDir->VirtualAddress == NULL)
            {
                // There is no debug directory, so it is OK to just return true.
                return true;
            }

            // Once data regarding the debug directory is known, it can be cleared in the PE header and
            // all data related to it.
            PIMAGE_DEBUG_DIRECTORY DebugDir = (PIMAGE_DEBUG_DIRECTORY)(vbufBase + Rva::RvaToOffset(pNtHeaders, DataDebugDir->VirtualAddress));

            // Clear the raw data
            uintptr_t RawData = vbufBase + DebugDir->PointerToRawData;
            memset((void*)RawData, 0, DebugDir->SizeOfData);

            // Clear the debug directory
            memset(DebugDir, 0, DataDebugDir->Size);

            // Set the Data directory values to both 0
            DataDebugDir->VirtualAddress = 0;
            DataDebugDir->Size = 0;

            // Done!
            return true;

        }

        template <typename T>
        auto ReadBuffer(std::uintptr_t address, T* value) -> bool {
            if (!IsBadWritePtr(address, sizeof * value)) {
                *value = *reinterpret_cast<T*>(address);
                return true;
            }
            else return false;
        }

        template <typename T>
        auto WriteBuffer(std::uintptr_t address, T value) -> void {
            if (!IsBadWritePtr(address, sizeof * value)) {
                *reinterpret_cast<T*>(address) = value;
                return true;
            }
            else return false;
        }

        auto DeleteSection(std::string sectionName) -> bool
        {
            int index = 0;
            IMAGE_SECTION_HEADER targetSection{};

            // iterate all sections, delete the target section from our buffer and save the index (used to calculate the actual header in the buf)
            for (int i = 0; i < vSections.size(); i++)
            {
                if (std::string((char*)this->vSections[i]->Name) == sectionName)
                {
                    targetSection = *this->vSections[i];
                    this->vSections.erase(this->vSections.begin() + i);
                    index = i;
                }
            }

            // since some sections (like .textbss) might have 0x0 on some properties, the only "safe" thing
            // to check would be the section name, here, we check if
            // the byte pointer exists OR if the first char isn't a dot (which should be)
            if (!targetSection.Name || targetSection.Name[0] != '.') {
                throw std::runtime_error("failed to delete \"" + sectionName + "\" section");
                return false;
            }

            // size of total sections, number of sections * size of IMAGE_SECTION_HEADER
            const auto sectionsBufferSize = this->vSections.size() * SECTION_SIZE;

            // start of section headers
            const auto sectionHeadersBufOffset = this->pDosHeader->e_lfanew + this->pNtHeaders->FileHeader.SizeOfOptionalHeader + 0x18;

            // fix sections addresses since we fucked em up
            for (auto section : this->vSections) {
                if (section->PointerToRawData > targetSection.PointerToRawData)
                    section->PointerToRawData -= targetSection.SizeOfRawData;
            }

            const auto targetSectionHeaderPadding = index * SECTION_SIZE;
            const auto targetSectionHeaderStart = sectionHeadersBufOffset + targetSectionHeaderPadding;
            const auto targetSectionHeaderEnd = sectionHeadersBufOffset + targetSectionHeaderPadding + SECTION_SIZE;

            this->vBuffer.erase(
                this->vBuffer.begin() + targetSectionHeaderStart,
                this->vBuffer.begin() + targetSectionHeaderEnd
            );

            // fix virtualsize of sections
            for (int i = 1; i < vSections.size(); i++) {
                if (vSections[i - 1]->VirtualAddress < targetSection.VirtualAddress)
                    vSections[i - 1]->Misc.VirtualSize = vSections[i]->VirtualAddress - vSections[i - 1]->VirtualAddress;
            }

            // decrease number of sections
            this->pNtHeaders->FileHeader.NumberOfSections--;

            /////////////////////////////////////////////////////////

            // delete section data (actual data, not the header)
            this->vBuffer.erase(vBuffer.begin() + targetSection.PointerToRawData, vBuffer.begin() + targetSection.SizeOfRawData);
        }

        auto GetSection(std::string sectionName) -> IMAGE_SECTION_HEADER {

            for (int i = 0; i < vSections.size(); i++)
                if (std::string((char*)this->vSections[i]->Name) == sectionName)
                    return *this->vSections[i];

            throw std::runtime_error("failed to get \"" + sectionName + "\" section");
            return IMAGE_SECTION_HEADER{};
        }

        // save modified buffer to a new file
        auto Save(std::wstring outputFilePath) -> bool {
            std::ofstream file;
            file.open(outputFilePath, std::ios::binary);
            if (file.fail()) {
                throw std::runtime_error(xorstr_("invalid output file path"));
                return false;
            }

            if (!file.is_open()) {
                throw std::runtime_error(xorstr_("failed to open output file"));
                return false;
            }

            file.write(reinterpret_cast<char*>(this->vBuffer.data()), this->vBuffer.size());
            file.close();

            return true;
        }

        ~Binary() {}
    };
}
