#include "gatehold/controller/admission_rate_limiter.hpp"

#include <algorithm>

namespace sasd::gatehold::controller {

AdmissionRateLimiter::AdmissionRateLimiter(AdmissionRateLimitConfig config)
    : config_{config} {
    if (valid()) {
        admissions_.reserve(config_.maximum_admissions);
    }
}

bool AdmissionRateLimiter::valid() const noexcept {
    return config_.maximum_admissions > 0U &&
           config_.maximum_admissions <= maximum_admission_limit &&
           config_.window >= minimum_window &&
           config_.window <= maximum_window;
}

AdmissionRateDecision AdmissionRateLimiter::try_admit(Clock::time_point now) {
    if (!valid()) {
        return {.admitted = false, .retry_after = config_.window};
    }
    if (has_observation_ && now < last_observation_) {
        return {.admitted = false, .retry_after = config_.window};
    }
    last_observation_ = now;
    has_observation_ = true;

    const auto first_active = std::find_if(
        admissions_.begin(), admissions_.end(), [this, now](const auto admitted) {
            return now - admitted < config_.window;
        });
    admissions_.erase(admissions_.begin(), first_active);
    if (admissions_.size() >= config_.maximum_admissions) {
        const auto remaining = config_.window - (now - admissions_.front());
        auto retry_after =
            std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
        if (retry_after < remaining) {
            retry_after += std::chrono::milliseconds{1};
        }
        return {
            .admitted = false,
            .retry_after = retry_after};
    }

    admissions_.push_back(now);
    return {.admitted = true, .retry_after = std::chrono::milliseconds{0}};
}

void AdmissionRateLimiter::reset() noexcept {
    admissions_.clear();
    last_observation_ = Clock::time_point{};
    has_observation_ = false;
}

}  // namespace sasd::gatehold::controller
