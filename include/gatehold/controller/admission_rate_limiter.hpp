#pragma once

#include <chrono>
#include <cstddef>
#include <vector>

namespace sasd::gatehold::controller {

struct AdmissionRateLimitConfig {
    std::size_t maximum_admissions{30U};
    std::chrono::milliseconds window{60000};
};

struct AdmissionRateDecision {
    bool admitted{false};
    std::chrono::milliseconds retry_after{0};
};

class AdmissionRateLimiter final {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr std::size_t maximum_admission_limit = 1024U;
    static constexpr std::chrono::milliseconds minimum_window{100};
    static constexpr std::chrono::milliseconds maximum_window{3600000};

    explicit AdmissionRateLimiter(AdmissionRateLimitConfig config);

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] AdmissionRateDecision try_admit(Clock::time_point now);
    void reset() noexcept;

private:
    AdmissionRateLimitConfig config_;
    std::vector<Clock::time_point> admissions_;
    Clock::time_point last_observation_{};
    bool has_observation_{false};
};

}  // namespace sasd::gatehold::controller
