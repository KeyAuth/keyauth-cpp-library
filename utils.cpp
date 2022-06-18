#include "utils.hpp"

#include <atlsecurity.h> 

std::string utils::get_hwid() {
	ATL::CAccessToken accessToken;
	ATL::CSid currentUserSid;
	if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) && accessToken.GetUser(&currentUserSid))
		return std::string(CT2A(currentUserSid.Sid()));
	else
	{
		MessageBoxA(0, "Couldn't Get HWID Indentifier, Contact Developer for help...", 0, 0);
		__fastfail(420);
	}
}

std::time_t utils::string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10);

	return (time_t)cv;
}

std::tm utils::timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
