// Owner: M3 | Wires everything together
// Setup check: confirms the compiler and both third-party libraries work.
#include <iostream>
#include <thread>
#include "json.hpp"
#include "httplib.h"

int main() {
    std::cout << "CAN Guard backend starting..." << std::endl;

    nlohmann::json j = {{"project", "CAN Guard"}, {"libs_ok", true}};
    std::cout << "JSON works: " << j.dump() << std::endl;

    httplib::Server svr;
    svr.Get("/api/ping", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"status\":\"ok\"}", "application/json");
    });
    std::cout << "httplib works: server object created" << std::endl;
    std::cout << "Cores: " << std::thread::hardware_concurrency() << std::endl;
    return 0;
}