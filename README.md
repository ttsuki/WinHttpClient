# WinHttpClient

WinHttp HttpClient wrapper library.

## Features

```cpp
#include <iostream>

#include <WinHttpClient/simple_http_client.h>

int main()
{
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
}
```

## Build environment
  - MSVC 2022 (2017, 2019)
  - C++17

## License

MIT License (C) 2022 ttsuki
