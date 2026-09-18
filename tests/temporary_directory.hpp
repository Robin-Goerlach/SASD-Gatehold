#pragma once

#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>

namespace gatehold::test {

class TemporaryDirectory {
public:
    explicit TemporaryDirectory(
        std::string_view prefix = "gatehold-test") {
        std::string pattern = "/tmp/" + std::string{prefix} + "-XXXXXX";
        pattern.push_back('\0');
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            path_ = created;
        }
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

}  // namespace gatehold::test

