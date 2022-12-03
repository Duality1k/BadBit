# BadBit
BadBit is a lightweight single header library for PE binary parsing

## Example deleting a section from a PE header

for this example i also use "lightlog" library from my repositories (https://github.com/veil3/lightlog).
you can initialize it like this: 
```c++
	Log::InitStdOutHandle();
	Log::SetTitle("title");
```
Here's a fully working example:
### main.hpp
```c++
#include "includes/lightlog.hpp"
#include "includes/badbit.hpp"

using namespace badbit;

int main()
{
  // initialize std output handle (used for coloured output)
	Log::InitStdOutHandle();
  // change console title
	Log::SetTitle("BadBit");

	try
	{
    // initialize our "Binary" class from badbit library
		const auto binary = new Binary(L"C:\\BadBit\\test.exe");
		
    // use FindDosHeader to initialize DOS Header and check if its successful
		if (!binary->FindDosHeader())
			throw std::runtime_error("invalid DOS header");

    // you can access dos header from the binary class
		Log::Ok("Found DOS header");
		Log::Info("DOS e_magic: 0x%x", binary->pDosHeader->e_magic);

    // use FindDosHeader to initialize DOS Header and check if its successful
		if (!binary->FindNtHeaders())
			throw std::runtime_error("invalid NT headers");

    // you can access nt headers from the binary class
		Log::Ok("Found NT headers");
		Log::Info("NT Signature: 0x%x", binary->pNtHeaders->Signature);

    // use FindSections to initialize a std::vector of PIMAGE_SECTION_HEADER reading the binary's sections
    // sections are private and accessed only from class functions, to write raw bytes to the binary use WriteBuffer and ReadBuffer
		if (!binary->FindSections())
			throw std::runtime_error("failed to find sections");

		Log::Ok("Found sections");

    // use DeleteSection to delete a section, both headers and raw data, fixing the PE too
		const auto sectionToDelete = ".text";
		if (!binary->DeleteSection(sectionToDelete))
			throw std::runtime_error("failed to delete section");

		Log::Ok("Successfully deleted section: %s", sectionToDelete);

    // save the modified binary buffer to a new file
    const auto outputFileName = std::wstring(L"protected_").append(binary->FileName);
		if (!binary->Save(outputFileName))
			throw std::runtime_error("failed to write output file");

		Log::Ok("File written to disk!");
	}
	catch (std::exception ex)
	{
    // catch exceptions thrown from both main.cpp and badbit.hpp
		Log::Err("Error: %s", ex.what());
	}
}
```

Now, the file "test.exe" has been successfully modified, deleting the .text section, to a new file protected_test.exe in the output path
