// Shaders.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <map>
#include <string>
#include <vector>
#include <iostream>
#include <direct.h>
#include "DecompileHLSL.h"

using namespace std;

FILE *LogFile = NULL;
bool gLogDebug = false;

vector<string> enumerateFiles(string pathName, string filter = "") {
	vector<string> files;
	WIN32_FIND_DATAA FindFileData;
	HANDLE hFind;
	string sName = pathName;
	sName.append(filter);
	hFind = FindFirstFileA(sName.c_str(), &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE)	{
		string fName = pathName;
		fName.append(FindFileData.cFileName);
		files.push_back(fName);
		while (FindNextFileA(hFind, &FindFileData)) {
			fName = pathName;
			fName.append(FindFileData.cFileName);
			files.push_back(fName);
		}
		FindClose(hFind);
	}
	return files;
}

int _tmain(int argc, _TCHAR* argv[])
{
	fopen_s(&LogFile, "D3D_Shaders_log.txt", "wb");
	int shaderNo = 1;
	vector<string> gameNames;
	string pathName;
	vector<string> files;
	FILE* f;
	char cwd[MAX_PATH];
	char gamebuffer[10000];

	_getcwd(cwd, MAX_PATH);
	vector<string> lines;
	fopen_s(&f, "gamelist.txt", "rb");
	if (f) {
		int fr = ::fread(gamebuffer, 1, 10000, f);
		fclose(f);
		lines = stringToLines(gamebuffer, fr);
	}

	if (lines.size() > 0) {
		for (auto i = lines.begin(); i != lines.end(); i++) {
			gameNames.push_back(*i);
		}
	} else {
		gameNames.push_back(cwd);
	}
	for (DWORD i = 0; i < gameNames.size(); i++) {
		string gameName = gameNames[i];
		cout << gameName << ":" << endl;

		int progress = 0;
		pathName = gameName;
		pathName.append("\\ShaderCache\\");
		files = enumerateFiles(pathName, "????????????????-??.bin");
		if (files.size() > 0) {
			cout << "bin->asm: ";
			for (DWORD i = 0; i < files.size(); i++) {
				string fileName = files[i];

				auto ASM = disassembler(readFile(fileName));

				fileName.erase(fileName.size() - 3, 3);
				fileName.append("txt");
				FILE* f;
				fopen_s(&f, fileName.c_str(), "wb");
				fwrite(ASM.data(), 1, ASM.size(), f);
				fclose(f);
				
				int newProgress = 50.0 * i / files.size();
				if (newProgress > progress) {
					cout << ".";
					progress++;
				}
			}
		}
		cout << endl;

		progress = 0;
		pathName = gameName;
		pathName.append("\\ShaderCache\\");
		files = enumerateFiles(pathName, "????????????????-??.txt");
		if (files.size() > 0) {
			cout << "asm->cbo: ";
			for (DWORD i = 0; i < files.size(); i++) {
				string fileName = files[i];

				auto ASM = readFile(fileName);
				fileName.erase(fileName.size() - 3, 3);
				fileName.append("bin");
				auto BIN = readFile(fileName);
				
				auto CBO = assembler(ASM, BIN);

				fileName.erase(fileName.size() - 3, 3);
				fileName.append("cbo");
				FILE* f;
				fopen_s(&f, fileName.c_str(), "wb");
				fwrite(CBO.data(), 1, CBO.size(), f);
				fclose(f);

				int newProgress = 50.0 * i / files.size();
				if (newProgress > progress) {
					cout << ".";
					progress++;
				}
			}
		}
		cout << endl;

		progress = 0;
		pathName = gameNames[i];
		pathName.append("\\Mark\\");
		files = enumerateFiles(pathName, "*.bin");
		if (files.size() > 0) {
			cout << "bin->asm validate: ";
			for (DWORD i = 0; i < files.size(); i++) {
				string fileName = files[i];

				auto ASM = disassembler(readFile(fileName));

				fileName.erase(fileName.size() - 3, 3);
				fileName.append("txt");
				FILE* f;
				fopen_s(&f, fileName.c_str(), "wb");
				fwrite(ASM.data(), 1, ASM.size(), f);
				fclose(f);

				int newProgress = 50.0 * i / files.size();
				if (newProgress > progress) {
					cout << ".";
					progress++;
				}
			}
		}
		cout << endl;

		progress = 0;
		pathName = gameNames[i];
		pathName.append("\\Mark\\");
		files = enumerateFiles(pathName, "*.bin");
		if (files.size() > 0) {
			cout << "ValidHLSL: ";
			for (DWORD i = 0; i < files.size(); i++) {
				string fileName = files[i];
				auto BIN = readFile(fileName);
				fileName.erase(fileName.size() - 3, 3);
				fileName.append("txt");
				auto ASM = readFile(fileName);

				bool patched = false;
				string shaderModel;
				bool errorOccurred = false;

				// Set all to zero, so we only init the ones we are using here.
				ParseParameters p = {};

				p.bytecode = BIN.data();
				p.decompiled = (const char *)ASM.data();
				p.decompiledSize = ASM.size();
				const string decompiledCode = DecompileBinaryHLSL(p, patched, shaderModel, errorOccurred);

				if (errorOccurred) {
					fileName.erase(fileName.size() - 4, 4);
					fileName.append("_replace_bad.txt");
					FILE* f;
					fopen_s(&f, fileName.c_str(), "wb");
					fwrite(decompiledCode.data(), 1, decompiledCode.size(), f);
					fclose(f);
					continue;
				}

				fileName.erase(fileName.size() - 4, 4);
				fileName.append("_replace.txt");
				FILE* f;
				fopen_s(&f, fileName.c_str(), "wb");
				fwrite(decompiledCode.data(), 1, decompiledCode.size(), f);
				fclose(f);

				int newProgress = 50.0 * i / files.size();
				if (newProgress > progress) {
					cout << ".";
					progress++;
				}
			}
		}
		writeLUT();
		cout << endl;
	}
	return 0;
}