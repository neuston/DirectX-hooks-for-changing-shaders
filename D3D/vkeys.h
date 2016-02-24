#pragma once

#include <string>

// http://msdn.microsoft.com/en-us/library/windows/desktop/dd375731(v=vs.85).aspx
struct VKMapping_t {
	char *name;
	int key;
};
static VKMapping_t VKMappings[] = {
	{"LBUTTON", 0x01},
	{"RBUTTON", 0x02},
	{"CANCEL", 0x03},
	{"MBUTTON", 0x04},
	{"XBUTTON1", 0x05},
	{"XBUTTON2", 0x06},
	{"BACK", 0x08}, {"BACKSPACE", 0x08}, {"BACK_SPACE", 0x08},
	{"TAB", 0x09},
	{"CLEAR", 0x0C},
	{"RETURN", 0x0D}, {"ENTER", 0x0D},
	{"SHIFT", 0x10},
	{"CONTROL", 0x11},
	{"MENU", 0x12}, {"ALT", 0x12},
	{"PAUSE", 0x13},
	{"CAPITAL", 0x14}, {"CAPS", 0x14}, {"CAPSLOCK", 0x14}, {"CAPS_LOCK", 0x14},
	{"KANA", 0x15},
	{"HANGUEL", 0x15},
	{"HANGUL", 0x15},
	{"JUNJA", 0x17},
	{"FINAL", 0x18},
	{"HANJA", 0x19},
	{"KANJI", 0x19},
	{"ESCAPE", 0x1B},
	{"CONVERT", 0x1C},
	{"NONCONVERT", 0x1D},
	{"ACCEPT", 0x1E},
	{"MODECHANGE", 0x1F},
	{"SPACE", 0x20},
	{"PRIOR", 0x21}, {"PGUP", 0x21}, {"PAGEUP", 0x21}, {"PAGE_UP", 0x21},
	{"NEXT", 0x22}, {"PGDN", 0x22}, {"PAGEDOWN", 0x22}, {"PAGE_DOWN", 0x22},
	{"END", 0x23},
	{"HOME", 0x24},
	{"LEFT", 0x25},
	{"UP", 0x26},
	{"RIGHT", 0x27},
	{"DOWN", 0x28},
	{"SELECT", 0x29},
	{"PRINT", 0x2A},
	{"EXECUTE", 0x2B},
	{"SNAPSHOT", 0x2C}, {"PRSCR", 0x2C}, {"PRINTSCREEN", 0x2C}, {"PRINT_SCREEN", 0x2C},
	{"INSERT", 0x2D},
	{"DELETE", 0x2E},
	{"HELP", 0x2F},
	/* 0-9 & upper case A-Z match ASCII and are checked programatically */
	{"LWIN", 0x5B}, {"LEFT_WIN", 0x5B}, {"LEFT_WINDOWS", 0x5B},
	{"RWIN", 0x5C}, {"RIGHT_WIN", 0x5C},{"RIGHT_WINDOWS", 0x5C},
	{"APPS", 0x5D},
	{"SLEEP", 0x5F},
	{"NUMPAD0", 0x60},
	{"NUMPAD1", 0x61},
	{"NUMPAD2", 0x62},
	{"NUMPAD3", 0x63},
	{"NUMPAD4", 0x64},
	{"NUMPAD5", 0x65},
	{"NUMPAD6", 0x66},
	{"NUMPAD7", 0x67},
	{"NUMPAD8", 0x68},
	{"NUMPAD9", 0x69},
	{"MULTIPLY", 0x6A},
	{"ADD", 0x6B},
	{"SEPARATOR", 0x6C},
	{"SUBTRACT", 0x6D},
	{"DECIMAL", 0x6E},
	{"DIVIDE", 0x6F},
	{"F1", 0x70},
	{"F2", 0x71},
	{"F3", 0x72},
	{"F4", 0x73},
	{"F5", 0x74},
	{"F6", 0x75},
	{"F7", 0x76},
	{"F8", 0x77},
	{"F9", 0x78},
	{"F10", 0x79},
	{"F11", 0x7A},
	{"F12", 0x7B},
	{"F13", 0x7C},
	{"F14", 0x7D},
	{"F15", 0x7E},
	{"F16", 0x7F},
	{"F17", 0x80},
	{"F18", 0x81},
	{"F19", 0x82},
	{"F20", 0x83},
	{"F21", 0x84},
	{"F22", 0x85},
	{"F23", 0x86},
	{"F24", 0x87},
	{"NUMLOCK", 0x90},
	{"SCROLL", 0x91},
	{"LSHIFT", 0xA0}, {"LEFT_SHIFT", 0xA0},
	{"RSHIFT", 0xA1}, {"RIGHT_SHIFT", 0xA1},
	{"LCONTROL", 0xA2}, {"LEFT_CONTROL", 0xA2},
	{"RCONTROL", 0xA3}, {"RIGHT_CONTROL", 0xA3},
	{"LMENU", 0xA4}, {"LEFT_MENU", 0xA4}, {"LALT", 0xA4}, {"LEFT_ALT", 0xA4},
	{"RMENU", 0xA5}, {"RIGHT_MENU", 0xA5}, {"RALT", 0xA5}, {"RIGHT_ALT", 0xA5},
	{"BROWSER_BACK", 0xA6},
	{"BROWSER_FORWARD", 0xA7},
	{"BROWSER_REFRESH", 0xA8},
	{"BROWSER_STOP", 0xA9},
	{"BROWSER_SEARCH", 0xAA},
	{"BROWSER_FAVORITES", 0xAB},
	{"BROWSER_HOME", 0xAC},
	{"VOLUME_MUTE", 0xAD},
	{"VOLUME_DOWN", 0xAE},
	{"VOLUME_UP", 0xAF},
	{"MEDIA_NEXT_TRACK", 0xB0},
	{"MEDIA_PREV_TRACK", 0xB1},
	{"MEDIA_STOP", 0xB2},
	{"MEDIA_PLAY_PAUSE", 0xB3},
	{"LAUNCH_MAIL", 0xB4},
	{"LAUNCH_MEDIA_SELECT", 0xB5},
	{"LAUNCH_APP1", 0xB6},
	{"LAUNCH_APP2", 0xB7},
	{"OEM_1", 0xBA}, {";", 0xBA}, {":", 0xBA}, {"COLON", 0xBA}, {"SEMICOLON", 0xBA}, {"SEMI_COLON", 0xBA},
	{"OEM_PLUS", 0xBB}, {"=", 0xBB}, {"PLUS", 0xBB}, {"EQUALS", 0xBB}, /* "+" alias already used for numpad + */
	{"OEM_COMMA", 0xBC}, {",", 0xBC}, {"<", 0xBC}, {"COMMA", 0xBC},
	{"OEM_MINUS", 0xBD}, {"MINUS", 0xBD}, {"UNDERSCORE", 0xBD}, {"_", 0xBD}, /* "-" alias already used for numpad - */
	{"OEM_PERIOD", 0xBE}, {".", 0xBE}, {">", 0xBE}, {"PERIOD", 0xBE},
	{"OEM_2", 0xBF}, {"/", 0xBF}, {"?", 0xBF}, {"SLASH", 0xBF}, {"FORWARD_SLASH", 0xBF}, {"QUESTION", 0xBF}, {"QUESTION_MARK", 0xBF},
	{"OEM_3", 0xC0}, {"`", 0xC0}, {"~", 0xC0}, {"TILDE", 0xC0}, {"GRAVE", 0xC0},
	{"OEM_4", 0xDB}, {"[", 0xDB}, {"{", 0xDB},
	{"OEM_5", 0xDC}, {"\\", 0xDC}, {"|", 0xDC}, {"BACKSLASH", 0xDC}, {"BACK_SLASH", 0xDC}, {"PIPE", 0xDC}, {"VERTICAL_BAR", 0xDC},
	{"OEM_6", 0xDD}, {"]", 0xDD}, {"}", 0xDD},
	{"OEM_7", 0xDE}, {"'", 0xDE}, {"\"", 0xDE}, {"QUOTE", 0xDE}, {"DOUBLE_QUOTE", 0xDE},
	{"OEM_8", 0xDF},
	{"OEM_102", 0xE2}, /* Either the angle bracket key or the backslash key on the RT 102-key keyboard */
	{"PROCESSKEY", 0xE5},
	/* {"PACKET", 0xE7}, Would need special handling for unicode characters */
	{"ATTN", 0xF6},
	{"CRSEL", 0xF7},
	{"EXSEL", 0xF8},
	{"EREOF", 0xF9},
	{"PLAY", 0xFA},
	{"ZOOM", 0xFB},
	{"NONAME", 0xFC},
	{"PA1", 0xFD},
	{"OEM_CLEAR", 0xFE},

	/*
	 * The following are to reduce the impact on existing users with an old
	 * d3dx.ini, provided they are using the default english key bindings
	 */
	{"Num 1", 0x61},
	{"Num 2", 0x62},
	{"Num 3", 0x63},
	{"Num 4", 0x64},
	{"Num 5", 0x65},
	{"Num 6", 0x66},
	{"Num 7", 0x67},
	{"Num 8", 0x68},
	{"Num 9", 0x69},
	{"*", 0x6A},
	{"Num /", 0x6F},
	{"-", 0x6D},
	{"+", 0x6B},
	{"Prnt Scrn", 0x2C},
};

static int ParseVKey(const char *name)
{
	int i;

	if (strlen(name) == 1) {
		wchar_t c = towupper(name[0]);
		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))
			return c;
	}

	if (!strncmp(name, "0x", 2)) {
		unsigned int vkey;
		scanf_s(name, "%x", &vkey);
		return vkey;
	}

	if (!_strnicmp(name, "VK_", 3))
		name += 3;

	for (i = 0; i < ARRAYSIZE(VKMappings); i++) {
		if (!_stricmp(name, VKMappings[i].name))
			return VKMappings[i].key;
	}

	return -1;
}

// Reverse lookup of key back to string name

static string GetKeyName(int key)
{
	for (int i = 0; i < ARRAYSIZE(VKMappings); i++) {
		if (VKMappings[i].key == key) {
			return (VKMappings[i].name);
		}
	}

	return ("missing");
}