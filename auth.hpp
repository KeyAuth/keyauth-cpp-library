#include <includes.hpp>

#pragma comment(lib, "libcurl.lib")

#define CURL_STATICLIB 

struct channel_struct
{
	std::string author;
	std::string message;
	std::string timestamp;
};

namespace KeyAuth {
	class api {
	public:

		std::string name, ownerid, secret, version, url;

		api(std::string name, std::string ownerid, std::string secret, std::string version, std::string url) : name(name), ownerid(ownerid), secret(secret), version(version), url(url) {}

		void ban(std::string reason = "");
		void init();
		void check();
		void log(std::string msg);
		void license(std::string key);
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params, std::string body, std::string contenttype);
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void web_login();
		void button(std::string value);
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password);
		std::vector<unsigned char> download(std::string fileid);
		void regstr(std::string username, std::string password, std::string key);
		void chatget(std::string channel);
		bool chatsend(std::string message, std::string channel);

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
			std::vector<std::string> subscriptions;
			std::string expiry;
			// response data
			std::vector<channel_struct> channeldata;
			bool success;
			std::string message;
		};
		data_class data;
	private:
		std::string sessionid, enckey;

		static std::string req(std::string data, std::string url);

		void load_user_data(nlohmann::json data) {
			api::data.username = data["username"];
			api::data.ip = data["ip"];
			if (data["hwid"].is_null()) {
				api::data.hwid = "none";
			}
			else {
				api::data.hwid = data["hwid"];
			}
			api::data.createdate = data["createdate"];
			api::data.lastlogin = data["lastlogin"];
			for (auto sub : data["subscriptions"]) api::data.subscriptions.push_back(sub["subscription"]);
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

		void load_channel_data(nlohmann::json data) {
			api::data.success = data["success"];
			api::data.message = data["message"];
			for (auto sub : data["messages"])
			{
				std::string authoroutput = sub[("author")];
				std::string messageoutput = sub[("message")];
				std::string timestampoutput = sub[("timestamp")];
				authoroutput.erase(remove(authoroutput.begin(), authoroutput.end(), '"'), authoroutput.end());
				messageoutput.erase(remove(messageoutput.begin(), messageoutput.end(), '"'), messageoutput.end());
				timestampoutput.erase(remove(timestampoutput.begin(), timestampoutput.end(), '"'), timestampoutput.end());
				channel_struct output = { authoroutput , messageoutput, timestampoutput };
				api::data.channeldata.push_back(output);
			}
		}

		nlohmann::json response_decoder;

	};
}
