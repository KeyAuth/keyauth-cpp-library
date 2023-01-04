#ifndef UNICODE
#define UNICODE
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <auth.hpp>
#include <strsafe.h> 
#include <windows.h>
#include <string>
#include <stdio.h>
#include <iostream>

#include <shellapi.h>

#include <sstream> 
#include <iomanip> 
#include "xorstr.hpp"
#include <fstream> 
#include <http.h>
#include <stdlib.h>
#include <atlstr.h>

#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "httpapi.lib")

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include <functional>
#include <vector>
#include <bitset>
#include <psapi.h>
#pragma comment( lib, "psapi.lib" )
#include <thread>
#include "hmac_sha256.h"

#include <cctype>
#include <algorithm>

#include "Security.hpp"

#define SHA256_HASH_SIZE 32

static std::string hexDecode(const std::string& hex);
std::string get_str_between_two_str(const std::string& s, const std::string& start_delim, const std::string& stop_delim);
std::string checksum();
void modify();
std::string signature;

void KeyAuth::api::init()
{
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)modify, 0, 0, 0);

	if (ownerid.length() != 10 || secret.length() != 64)
	{
		MessageBoxA(0, XorStr("Application Not Setup Correctly. Please Watch Video Linked in main.cpp").c_str(), NULL, MB_ICONERROR);
		exit(0);
	}

	UUID uuid = { 0 };
	std::string guid;
	::UuidCreate(&uuid);
	RPC_CSTR szUuid = NULL;
	if (::UuidToStringA(&uuid, &szUuid) == RPC_S_OK)
	{
		guid = (char*)szUuid;
		::RpcStringFreeA(&szUuid);
	}
	std::string sentKey;
	sentKey = guid.substr(0, 16);
	enckey = sentKey + "-" + secret;

	std::string hash = checksum();
	auto data =
		XorStr("type=init") +
		XorStr("&ver=") + version +
		XorStr("&hash=") + hash +
		XorStr("&enckey=") + sentKey +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;

	auto response = req(data, url);

	if (response == "KeyAuth_Invalid") {
		MessageBoxA(0, XorStr("Application not found. Please copy strings directly from dashboard.").c_str(), NULL, MB_ICONERROR);
		exit(0);
	}

	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(secret.data(), secret.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}
	if (ss_result.str().c_str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);

	if (json[("success")])
	{
		sessionid = json[("sessionid")];
		load_app_data(json[("appinfo")]);
	}
	else if (json[("message")] == "invalidver")
	{
		std::string dl = json[("download")];
		if (dl == "")
		{
			MessageBoxA(0, XorStr("Version in the loader does match the one on the dashboard, and the download link on dashboard is blank.\n\nTo fix this, either fix the loader so it matches the version on the dashboard. Or if you intended for it to have different versions, update the download link on dashboard so it will auto-update correctly.").c_str(), NULL, MB_ICONERROR);
		}
		else
		{
			ShellExecuteA(0, "open", dl.c_str(), 0, 0, SW_SHOWNORMAL);
		}
		exit(0);
	}
}

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

static size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata)
{
	// thanks to https://stackoverflow.com/q/28537837 and https://stackoverflow.com/a/66660987
	std::string temp = std::string(buffer);
	if (temp.substr(0, 9) == "signature") {
		std::string parsed = temp.erase(0, 11);; // remove "signature: "  from string 
		signature = parsed.substr(0, 64); // if I don't this, there's an extra line. so yeah.
	}
	std::string* headers = (std::string*)userdata;
	headers->append(buffer, nitems * size);
	return nitems * size;
}

void KeyAuth::api::login(std::string username, std::string password)
{
	std::string hwid = utils::get_hwid();
	auto data =
		XorStr("type=login") +
		XorStr("&username=") + username +
		XorStr("&pass=") + password +
		XorStr("&hwid=") + hwid +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
	if (json[("success")])
		load_user_data(json[("info")]);
}

void KeyAuth::api::web_login()
{

	// from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

	// Initialize the API.
	ULONG result = 0;
	HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
	result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);

	// Create server session.
	HTTP_SERVER_SESSION_ID serverSessionId;
	result = HttpCreateServerSession(version, &serverSessionId, 0);

	// Create URL group.
	HTTP_URL_GROUP_ID groupId;
	result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

	// Create request queue.
	HANDLE requestQueueHandle;
	result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

	// Attach request queue to URL group.
	HTTP_BINDING_INFO info;
	info.Flags.Present = 1;
	info.RequestQueueHandle = requestQueueHandle;
	result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

	// Add URLs to URL group.
	PCWSTR url = L"http://localhost:1337/handshake";
	result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

	// Announce that it is running.
	// wprintf(L"Listening. Please submit requests to: %s\n", url);

	// req to: http://localhost:1337/handshake?user=mak&token=2f3e9eccc22ee583cf7bad86c751d865
	bool going = true;
	while (going == true)
	{
		// Wait for a request.
		HTTP_REQUEST_ID requestId = 0;
		HTTP_SET_NULL_ID(&requestId);
		int bufferSize = 4096;
		int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
		BYTE* buffer = new BYTE[requestSize];
		PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer;
		RtlZeroMemory(buffer, requestSize);
		ULONG bytesReturned;
		result = HttpReceiveHttpRequest(
			requestQueueHandle,
			requestId,
			HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
			pRequest,
			requestSize,
			&bytesReturned,
			NULL
		);

		// Display some information about the request.
		// wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
		// wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
		// wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

		std::wstring ws(pRequest->CookedUrl.pQueryString);
		std::string myVarS = std::string(ws.begin(), ws.end());
		std::string user = get_str_between_two_str(myVarS, "?user=", "&");
		std::string token = get_str_between_two_str(myVarS, "&token=", "");

		// std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

		// break if preflight request from browser
		if (pRequest->Verb == HttpVerbOPTIONS)
		{
			// Respond to the request.
			HTTP_RESPONSE response;
			RtlZeroMemory(&response, sizeof(response));

			response.StatusCode = 200;
			response.pReason = "OK";
			response.ReasonLength = (USHORT)strlen(response.pReason);

			response.Headers.KnownHeaders[HttpHeaderServer].pRawValue = "Apache/2.4.48 nginx/1.12.2"; // confuse anyone looking at server header
			response.Headers.KnownHeaders[HttpHeaderServer].RawValueLength = 24;

			response.Headers.KnownHeaders[HttpHeaderVia].pRawValue = "hugzho's big brain";
			response.Headers.KnownHeaders[HttpHeaderVia].RawValueLength = 18;

			response.Headers.KnownHeaders[HttpHeaderRetryAfter].pRawValue = "never lmao";
			response.Headers.KnownHeaders[HttpHeaderRetryAfter].RawValueLength = 10;

			response.Headers.KnownHeaders[HttpHeaderLocation].pRawValue = "your kernel ;)";
			response.Headers.KnownHeaders[HttpHeaderLocation].RawValueLength = 14;

			// https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
			HTTP_UNKNOWN_HEADER  accessControlHeader;
			const char testCustomHeader[] = "Access-Control-Allow-Origin";
			const char testCustomHeaderVal[] = "*";
			accessControlHeader.pName = testCustomHeader;
			accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
			accessControlHeader.pRawValue = testCustomHeaderVal;
			accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
			response.Headers.pUnknownHeaders = &accessControlHeader;
			response.Headers.UnknownHeaderCount = 1;
			// Add an entity chunk to the response.
			// PSTR pEntityString = "Hello from C++";
			HTTP_DATA_CHUNK dataChunk;
			dataChunk.DataChunkType = HttpDataChunkFromMemory;

			result = HttpSendHttpResponse(
				requestQueueHandle,
				pRequest->RequestId,
				0,
				&response,
				NULL,
				NULL,   // &bytesSent (optional)
				NULL,
				0,
				NULL,
				NULL
			);

			delete[]buffer;
			continue;
		}

		going = false;

		// keyauth request
		std::string hwid = utils::get_hwid();
		auto data =
			XorStr("type=login") +
			XorStr("&username=") + user +
			XorStr("&token=") + token +
			XorStr("&hwid=") + hwid +
			XorStr("&sessionid=") + sessionid +
			XorStr("&name=") + name +
			XorStr("&ownerid=") + ownerid;
		auto resp = req(data, api::url);
		auto json = response_decoder.parse(resp);

		// from https://github.com/h5p9sl/hmac_sha256
		std::stringstream ss_result;

		// Allocate memory for the HMAC
		std::vector<uint8_t> out(SHA256_HASH_SIZE);

		// Call hmac-sha256 function
		hmac_sha256(enckey.data(), enckey.size(), resp.data(), resp.size(),
			out.data(), out.size());

		// Convert `out` to string with std::hex
		for (uint8_t x : out) {
			ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
		}

		if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
			abort();
		}

		// Respond to the request.
		HTTP_RESPONSE response;
		RtlZeroMemory(&response, sizeof(response));

		bool success = true;
		if (json[("success")])
		{
			load_user_data(json[("info")]);

			response.StatusCode = 420;
			response.pReason = "SHEESH";
			response.ReasonLength = (USHORT)strlen(response.pReason);
		}
		else
		{
			response.StatusCode = 200;
			response.pReason = std::string(json[("message")]).c_str();
			response.ReasonLength = (USHORT)strlen(response.pReason);
			success = false;
		}
		// end keyauth request

		response.Headers.KnownHeaders[HttpHeaderServer].pRawValue = "Apache/2.4.48 nginx/1.12.2"; // confuse anyone looking at server header
		response.Headers.KnownHeaders[HttpHeaderServer].RawValueLength = 24;

		response.Headers.KnownHeaders[HttpHeaderVia].pRawValue = "hugzho's big brain";
		response.Headers.KnownHeaders[HttpHeaderVia].RawValueLength = 18;

		response.Headers.KnownHeaders[HttpHeaderRetryAfter].pRawValue = "never lmao";
		response.Headers.KnownHeaders[HttpHeaderRetryAfter].RawValueLength = 10;

		response.Headers.KnownHeaders[HttpHeaderLocation].pRawValue = "your kernel ;)";
		response.Headers.KnownHeaders[HttpHeaderLocation].RawValueLength = 14;

		// https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
		HTTP_UNKNOWN_HEADER  accessControlHeader;
		const char testCustomHeader[] = "Access-Control-Allow-Origin";
		const char testCustomHeaderVal[] = "*";
		accessControlHeader.pName = testCustomHeader;
		accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
		accessControlHeader.pRawValue = testCustomHeaderVal;
		accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
		response.Headers.pUnknownHeaders = &accessControlHeader;
		response.Headers.UnknownHeaderCount = 1;
		// Add an entity chunk to the response.
		// PSTR pEntityString = "Hello from C++";
		HTTP_DATA_CHUNK dataChunk;
		dataChunk.DataChunkType = HttpDataChunkFromMemory;

		result = HttpSendHttpResponse(
			requestQueueHandle,
			pRequest->RequestId,
			0,
			&response,
			NULL,
			NULL,   // &bytesSent (optional)
			NULL,
			0,
			NULL,
			NULL
		);

		delete []buffer;

		if (!success)
			exit(0);
	}
}

void KeyAuth::api::button(std::string button)
{

	// from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

	// Initialize the API.
	ULONG result = 0;
	HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
	result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);

	// Create server session.
	HTTP_SERVER_SESSION_ID serverSessionId;
	result = HttpCreateServerSession(version, &serverSessionId, 0);

	// Create URL group.
	HTTP_URL_GROUP_ID groupId;
	result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

	// Create request queue.
	HANDLE requestQueueHandle;
	result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

	// Attach request queue to URL group.
	HTTP_BINDING_INFO info;
	info.Flags.Present = 1;
	info.RequestQueueHandle = requestQueueHandle;
	result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

	// Add URLs to URL group.
	std::wstring output;
	output = std::wstring(button.begin(), button.end());
	output = std::wstring(L"http://localhost:1337/") + output;
	PCWSTR url = output.c_str();
	result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

	// Announce that it is running.
	// wprintf(L"Listening. Please submit requests to: %s\n", url);

	// req to: http://localhost:1337/buttonvaluehere
	bool going = true;
	while (going == true)
	{
		// Wait for a request.
		HTTP_REQUEST_ID requestId = 0;
		HTTP_SET_NULL_ID(&requestId);
		int bufferSize = 4096;
		int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
		BYTE* buffer = new BYTE[requestSize];
		PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer;
		RtlZeroMemory(buffer, requestSize);
		ULONG bytesReturned;
		result = HttpReceiveHttpRequest(
			requestQueueHandle,
			requestId,
			HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
			pRequest,
			requestSize,
			&bytesReturned,
			NULL
		);

		going = false;

		// Display some information about the request.
		// wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
		// wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
		// wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

		// std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

		// Break from the loop if it's the poison pill (a DELETE request).
		// if (pRequest->Verb == HttpVerbDELETE)
		// {
		// 	wprintf(L"Asked to stop.\n");
		// 	break;
		// }

		// Respond to the request.
		HTTP_RESPONSE response;
		RtlZeroMemory(&response, sizeof(response));
		response.StatusCode = 420;
		response.pReason = "SHEESH";
		response.ReasonLength = (USHORT)strlen(response.pReason);

		response.Headers.KnownHeaders[HttpHeaderServer].pRawValue = "Apache/2.4.48 nginx/1.12.2"; // confuse anyone looking at server header
		response.Headers.KnownHeaders[HttpHeaderServer].RawValueLength = 24;

		response.Headers.KnownHeaders[HttpHeaderVia].pRawValue = "hugzho's big brain";
		response.Headers.KnownHeaders[HttpHeaderVia].RawValueLength = 18;

		response.Headers.KnownHeaders[HttpHeaderRetryAfter].pRawValue = "never lmao";
		response.Headers.KnownHeaders[HttpHeaderRetryAfter].RawValueLength = 10;

		response.Headers.KnownHeaders[HttpHeaderLocation].pRawValue = "your kernel ;)";
		response.Headers.KnownHeaders[HttpHeaderLocation].RawValueLength = 14;

		// https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
		HTTP_UNKNOWN_HEADER  accessControlHeader;
		const char testCustomHeader[] = "Access-Control-Allow-Origin";
		const char testCustomHeaderVal[] = "*";
		accessControlHeader.pName = testCustomHeader;
		accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
		accessControlHeader.pRawValue = testCustomHeaderVal;
		accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
		response.Headers.pUnknownHeaders = &accessControlHeader;
		response.Headers.UnknownHeaderCount = 1;
		// Add an entity chunk to the response.
		// PSTR pEntityString = "Hello from C++";
		HTTP_DATA_CHUNK dataChunk;
		dataChunk.DataChunkType = HttpDataChunkFromMemory;

		result = HttpSendHttpResponse(
			requestQueueHandle,
			pRequest->RequestId,
			0,
			&response,
			NULL,
			NULL,   // &bytesSent (optional)
			NULL,
			0,
			NULL,
			NULL
		);

		delete[]buffer;
	}
}

void KeyAuth::api::regstr(std::string username, std::string password, std::string key) {
	std::string hwid = utils::get_hwid();
	auto data =
		XorStr("type=register") +
		XorStr("&username=") + username +
		XorStr("&pass=") + password +
		XorStr("&key=") + key +
		XorStr("&hwid=") + hwid +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
	if (json[("success")])
		load_user_data(json[("info")]);
}

void KeyAuth::api::upgrade(std::string username, std::string key) {
	auto data =
		XorStr("type=upgrade") +
		XorStr("&username=") + username +
		XorStr("&key=") + key +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	json[("success")] = false;
	load_response_data(json);
}

void KeyAuth::api::license(std::string key) {
	std::string hwid = utils::get_hwid();
	auto data =
		XorStr("type=license") +
		XorStr("&key=") + key +
		XorStr("&hwid=") + hwid +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
	if (json[("success")])
		load_user_data(json[("info")]);
}

void KeyAuth::api::setvar(std::string var, std::string vardata) {
	auto data =
		XorStr("type=setvar") +
		XorStr("&var=") + var +
		XorStr("&data=") + vardata +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);
	load_response_data(json);
}

std::string KeyAuth::api::getvar(std::string var) {

	auto data =
		XorStr("type=getvar") +
		XorStr("&var=") + var +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
	return json[("response")];
}

void KeyAuth::api::ban(std::string reason) {

	auto data =
		XorStr("type=ban") +
		XorStr("&reason=") + reason +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
}

bool KeyAuth::api::checkblack() {
	std::string hwid = utils::get_hwid();
	auto data =
		XorStr("type=checkblacklist") +
		XorStr("&hwid=") + hwid +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	if (json[("success")])
	{
		return true;
	}
	else
	{
		return false;
	}
}

void KeyAuth::api::check() {
	auto data =
		XorStr("type=check") +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;

	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
}

std::string KeyAuth::api::var(std::string varid) {
	auto data =
		XorStr("type=var") +
		XorStr("&varid=") + varid +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;
	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
	return json[("message")];
}

void KeyAuth::api::log(std::string message) {

	char acUserName[100];
	DWORD nUserName = sizeof(acUserName);
	GetUserNameA(acUserName, &nUserName);
	std::string UsernamePC = acUserName;

	auto data =
		XorStr("type=log") +
		XorStr("&pcuser=") + UsernamePC +
		XorStr("&message=") + message +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;

	req(data, url);
}

std::vector<unsigned char> KeyAuth::api::download(std::string fileid) {
	auto to_uc_vector = [](std::string value) {
		return std::vector<unsigned char>(value.data(), value.data() + value.length() );
	};


	auto data =
		XorStr("type=file") +
		XorStr("&fileid=") + fileid +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=").c_str() + ownerid;

	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
	if (json[ XorStr( "success" ) ])
	{
		auto file = hexDecode(json[ XorStr( "contents" )]);
		return to_uc_vector(file);
	}
	return {};
}

std::string KeyAuth::api::webhook(std::string id, std::string params) {
	auto data =
		XorStr("type=webhook") +
		XorStr("&webid=") + id +
		XorStr("&params=") + params +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;

	auto response = req(data, url);
	auto json = response_decoder.parse(response);

	// from https://github.com/h5p9sl/hmac_sha256
	std::stringstream ss_result;

	// Allocate memory for the HMAC
	std::vector<uint8_t> out(SHA256_HASH_SIZE);

	// Call hmac-sha256 function
	hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
		out.data(), out.size());

	// Convert `out` to string with std::hex
	for (uint8_t x : out) {
		ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
	}

	if (ss_result.str() != signature) { // check response authenticity, if not authentic program crashes
		abort();
	}

	load_response_data(json);
	if (json[ XorStr( "success" ) ])
	{
		return json[( XorStr( "response" ) )];
	}
	return "";
}

void KeyAuth::api::chatget(std::string channel)
{
	auto data =
		XorStr("type=chatget") +
		XorStr("&channel=") + channel +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;

	auto response = req(data, url);
	auto json = response_decoder.parse(response);
	load_channel_data(json);
}

bool KeyAuth::api::chatsend(std::string message, std::string channel)
{
	auto data =
		XorStr("type=chatsend") +
		XorStr("&message=") + message +
		XorStr("&channel=") + channel +
		XorStr("&sessionid=") + sessionid +
		XorStr("&name=") + name +
		XorStr("&ownerid=") + ownerid;

	auto response = req(data, url);
	auto json = response_decoder.parse(response);
	load_response_data(json);
	if (json[("success")])
	{
		return true;
	}
	else
	{
		return false;
	}
}

static std::string hexDecode(const std::string& hex)
{
	int len = hex.length();
	std::string newString;
	for (int i = 0; i < len; i += 2)
	{
		std::string byte = hex.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
		newString.push_back(chr);
	}
	return newString;
}

std::string get_str_between_two_str(const std::string& s,
	const std::string& start_delim,
	const std::string& stop_delim)
{
	unsigned first_delim_pos = s.find(start_delim);
	unsigned end_pos_of_first_delim = first_delim_pos + start_delim.length();
	unsigned last_delim_pos = s.find(stop_delim);

	return s.substr(end_pos_of_first_delim,
		last_delim_pos - end_pos_of_first_delim);
}

std::string KeyAuth::api::req(std::string data, std::string url) {
	CURL* curl = curl_easy_init();
	if (!curl)
		return "null";

	std::string to_return;
	std::string headers;

	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);

	curl_easy_setopt(curl, CURLOPT_NOPROXY, XorStr( "keyauth.win" ) );

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &to_return);

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);

	auto code = curl_easy_perform(curl);

	if (code != CURLE_OK)
		MessageBoxA(0, curl_easy_strerror(code), 0, MB_ICONERROR);

	return to_return;
}

auto check_section_integrity( const char *section_name, bool fix = false ) -> bool
{
	const auto map_file = []( HMODULE hmodule ) -> std::tuple<std::uintptr_t, HANDLE>
	{
		wchar_t filename[ MAX_PATH ];
		GetModuleFileName( hmodule, filename, MAX_PATH );

		const auto file_handle = CreateFile( filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
		if ( !file_handle || file_handle == INVALID_HANDLE_VALUE )
		{
			return { 0ull, nullptr };
		}

		const auto file_mapping = CreateFileMapping( file_handle, 0, PAGE_READONLY, 0, 0, 0 );
		if ( !file_mapping )
		{
			CloseHandle( file_handle );
			return { 0ull, nullptr };
		}

		return { reinterpret_cast< std::uintptr_t >( MapViewOfFile( file_mapping, FILE_MAP_READ, 0, 0, 0 ) ), file_handle };
	};

	const auto hmodule = GetModuleHandle( 0 );
	if ( !hmodule ) return true;

	const auto base_0 = reinterpret_cast< std::uintptr_t >( hmodule );
	if ( !base_0 ) return true;

	const auto dos_0 = reinterpret_cast< IMAGE_DOS_HEADER * >( base_0 );
	if ( dos_0->e_magic != IMAGE_DOS_SIGNATURE ) return true;

	const auto nt_0 = reinterpret_cast< IMAGE_NT_HEADERS * >( base_0 + dos_0->e_lfanew );
	if ( nt_0->Signature != IMAGE_NT_SIGNATURE ) return true;

	auto section_0 = IMAGE_FIRST_SECTION( nt_0 );

	const auto [base_1, file_handle] = map_file( hmodule );
	if ( !base_1 || !file_handle || file_handle == INVALID_HANDLE_VALUE ) return true;

	const auto dos_1 = reinterpret_cast< IMAGE_DOS_HEADER * >( base_1 );
	if ( dos_1->e_magic != IMAGE_DOS_SIGNATURE )
	{
		UnmapViewOfFile( reinterpret_cast< void * >( base_1 ) );
		CloseHandle( file_handle );
		return true;
	}

	const auto nt_1 = reinterpret_cast< IMAGE_NT_HEADERS * >( base_1 + dos_1->e_lfanew );
	if ( nt_1->Signature != IMAGE_NT_SIGNATURE ||
		nt_1->FileHeader.TimeDateStamp != nt_0->FileHeader.TimeDateStamp ||
		nt_1->FileHeader.NumberOfSections != nt_0->FileHeader.NumberOfSections )
	{
		UnmapViewOfFile( reinterpret_cast< void * >( base_1 ) );
		CloseHandle( file_handle );
		return true;
	}

	auto section_1 = IMAGE_FIRST_SECTION( nt_1 );

	bool patched = false;
	for ( auto i = 0; i < nt_1->FileHeader.NumberOfSections; ++i, ++section_0, ++section_1 )
	{
		if ( strcmp( reinterpret_cast< char * >( section_0->Name ), section_name ) ||
			!( section_0->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) continue;

		for ( auto i = 0u; i < section_0->SizeOfRawData; ++i )
		{
			const auto old_value = *reinterpret_cast< BYTE * >( base_1 + section_1->PointerToRawData + i );

			if ( *reinterpret_cast< BYTE * >( base_0 + section_0->VirtualAddress + i ) == old_value )
			{
				continue;
			}

			if ( fix )
			{
				DWORD new_protect { PAGE_EXECUTE_READWRITE }, old_protect;
				VirtualProtect( ( void * )( base_0 + section_0->VirtualAddress + i ), sizeof( BYTE ), new_protect, &old_protect );
				*reinterpret_cast< BYTE * >( base_0 + section_0->VirtualAddress + i ) = old_value;
				VirtualProtect( ( void * )( base_0 + section_0->VirtualAddress + i ), sizeof( BYTE ), old_protect, &new_protect );
			}

			patched = true;
		}

		break;
	}

	UnmapViewOfFile( reinterpret_cast< void * >( base_1 ) );
	CloseHandle( file_handle );

	return patched;
}

std::string checksum()
{
	auto exec = [&](const char* cmd) -> std::string 
	{
		uint16_t line = -1;
		std::array<char, 128> buffer;
		std::string result;
		std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
		if (!pipe) {
			throw std::runtime_error("popen() failed!");
		}

		while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
				result = buffer.data();
		}
		return result;
	};

	char rawPathName[MAX_PATH];
	GetModuleFileNameA(NULL, rawPathName, MAX_PATH);

	return exec(("certutil -hashfile \"" + std::string(rawPathName) + XorStr( "\" MD5 | find /i /v \"md5\" | find /i /v \"certutil\"") ).c_str());
}

BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
	{
		if (*szMask == 'x' && *pData != *bMask)
			return FALSE;
	}
	return (*szMask) == NULL;
}
DWORD64 FindPattern(BYTE* bMask, const char* szMask)
{
	MODULEINFO mi{ };
	GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi));

	DWORD64 dwBaseAddress = DWORD64(mi.lpBaseOfDll);
	const auto dwModuleSize = mi.SizeOfImage;

	for (auto i = 0ul; i < dwModuleSize; i++)
	{
		if (bDataCompare(PBYTE(dwBaseAddress + i), bMask, szMask))
			return DWORD64(dwBaseAddress + i);
	}
	return NULL;
}

DWORD64 Function_Address;
void modify()
{
	check_section_integrity( XorStr( ".text" ).c_str( ), true );

	while (true)
	{
		if ( check_section_integrity( XorStr( ".text" ).c_str( ), false ) )
		{
			abort( );
		}
		if(!LockMemAccess())
		{
			abort( );
		}
		if (Function_Address == NULL) {
			Function_Address = FindPattern(PBYTE("\x48\x89\x74\x24\x00\x57\x48\x81\xec\x00\x00\x00\x00\x49\x8b\xf0"), "xxxx?xxxx????xxx") - 0x5;
		}
		BYTE Instruction = *(BYTE*)Function_Address;

		if ((DWORD64)Instruction == 0xE9) {
			abort();
		}
		Sleep(50);
	}
}
