#include <iostream>
#include <future>

#include <WinHttpClient/win_http_client.h>
#include <WinHttpClient/win_crypt_cert_view.h>

#include <WinHttpClient/simple_http_client.h>

static void setup_utf8_console_window();

int main()
{
    setup_utf8_console_window();

    whc::simple::http_client agent("whc/0.01");

    // HTTP GET
    try
    {
        const char* url = R"(https://ttsuki.dev/)";
        std::cout << "GET " << url << "\n";
        auto response = agent.execute_http_request(url);

        std::cout << "http_status = " << response.http_status_code << "\n";
        std::cout << response.response_headers.to_http_header_string() << "\n";
        std::cout << whc::simple::read_out_response_body_as_string(response);
    }
    catch (const whc::http_exception& e)
    {
        std::cerr << "http_exception thrown " << e.what() << "\n";
    }

    // HTTP POST
    try
    {
        const char* url = R"(https://ttsuki.dev/some_json_api/)";
        std::cout << "POST " << url << "\n";
        auto response = agent.execute_http_request(
            url,
            whc::http_methods::HTTP_POST,
            whc::simple::make_request_message("application/json", R"--({"a":[1,2,3]})--")
        );

        std::cout << "http_status = " << response.http_status_code << "\n";
        std::cout << response.response_headers.to_http_header_string() << "\n";
        std::cout << whc::simple::read_out_response_body_as_string(response);
    }
    catch (const whc::http_exception& e)
    {
        std::cerr << "http_exception thrown " << e.what() << "\n";
    }

    // async download
    {
        std::cout << "Downloading file...\n";
        std::atomic<size_t> total = 0;
        auto future = std::async(
            std::launch::async,
            [&agent, &total]
            {
                auto response = agent.execute_http_request("https://ttsuki.dev/files/anther_wing_deep_white.mp3");
                for (std::vector<char> buffer(16384);
                     size_t bytes_count = response.read_response_body(buffer.data(), buffer.size());)
                {
                    //TODO: write to file
                    total += bytes_count;
                    std::this_thread::yield();
                }
                return total.load();
            });

        for (int i = 0; future.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready; ++i)
            std::cout << " " << ("|/-\\"[i % 4]) << " " << total << " bytes downloaded.\r";

        try
        {
            std::cout << "total: " << future.get() << " bytes downloaded.\n";
        }
        catch (const whc::http_exception& e)
        {
            std::cerr << "http_exception thrown " << e.what() << "\n";
        }
    }

    // show server certificate
    try
    {
        auto url = whc::uri("https://ttsuki.dev/");
        std::cout << "Showing server certificate of " << url.to_string() << "...\n";

        auto sess = whc::win_http::open_http_session("whc/0.01");
        auto conn = whc::win_http::open_http_connection(sess, url.hostname, url.port);
        auto requ = whc::win_http::open_http_request(conn, whc::http_methods::HTTP_HEAD, url);
        whc::win_http::send_http_request(requ);

        auto cert_view = whc::win_http::get_server_certificates(requ);
        for (auto&& chain : *cert_view)
        {
            std::cout << "  chain: trusted=" << (chain.can_trust() ? "yes" : "no") << "\n";
            for (auto&& certificate : chain)
            {
                std::wcout << L"    certificate:"
                    << L" CN=" << certificate.subject().common_name()
                    << L" O=" << certificate.subject().organization()
                    << L" OU=" << certificate.subject().organization_unit()
                    << L" not-before=" << certificate.not_before()
                    << L" not-after=" << certificate.not_after()
                    << L"\n";
            }
        }
    }
    catch (const whc::http_exception& e)
    {
        std::cerr << "http_exception thrown " << e.what() << "\n";
    }
}

// setup cout utf-8 console 
#include <Windows.h> // ::SetConsoleOutputCP(...)
static void setup_utf8_console_window() { ::SetConsoleOutputCP(CP_UTF8); }
