// stdafx.h 
#pragma once

#include <direct.h>
#include "d3d11.h"
#include "log.h"
#include <vector>
#include <set>
#include <unordered_map>

using namespace std;

vector<byte> assembler(vector<byte> asmFile, vector<byte> buffer);
vector<byte> readFile(string fileName);
string shaderModel(byte* buffer);
