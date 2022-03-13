#include <includes.hpp>

#pragma comment(lib, "libcurl.lib")

#define CURL_STATICLIB 

namespace KeyAuth {
	class api {
	public:

		std::string name, ownerid, secret, version, url, sslPin;

		api(std::string name, std::string ownerid, std::string secret, std::string version, std::string url, std::string sslPin) : name(name), ownerid(ownerid), secret(secret), version(version), url(url), sslPin(sslPin) {}

		void ban();
		void init();
		void check();
		void log(std::string msg);
		void license(std::string key);
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params);
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void web_login();
		void button(std::string value);
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password);
		std::vector<unsigned char> download(std::string fileid);
		void regstr(std::string username, std::string password, std::string key);

		class data_class {
		public:
			// app data
			std::string numUsers;
			std::string numOnlineUsers;
			std::string numKeys;
			std::string version;
			std::string customerPanelLink;
			// user data
			std::string username;
			std::string ip;
			std::string hwid;
			std::string createdate;
			std::string lastlogin;
			std::string subscription;
			std::string expiry;
			// response data
			bool success;
			std::string message;
		};
		data_class data;
	private:
		std::string sessionid, enckey;

		static std::string req(std::string data, std::string url, std::string sslPin);

		void load_user_data(nlohmann::json data) {
			api::data.username = data["username"];
			api::data.ip = data["ip"];
			api::data.hwid = data["hwid"];
			api::data.createdate = data["createdate"];
			api::data.lastlogin = data["lastlogin"];
			api::data.subscription = data["subscriptions"][0]["subscription"];
			api::data.expiry = data["subscriptions"][0]["expiry"];
		}

		void load_app_data(nlohmann::json data) {
			api::data.numUsers = data["numUsers"];
			api::data.numOnlineUsers = data["numOnlineUsers"];
			api::data.numKeys = data["numKeys"];
			api::data.version = data["version"];
			api::data.customerPanelLink = data["customerPanelLink"];
		}

		void load_response_data(nlohmann::json data) {
			api::data.success = data["success"];
			api::data.message = data["message"];
		}

		nlohmann::json response_decoder;

	};
}
