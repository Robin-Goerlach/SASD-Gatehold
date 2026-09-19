#include "gatehold/controller/admission_rate_limiter.hpp"

#include "test_support.hpp"

#include <chrono>

namespace controller = sasd::gatehold::controller;

int main() {
    using namespace std::chrono_literals;
    using Clock = controller::AdmissionRateLimiter::Clock;

    gatehold::test::Context test;
    const auto origin = Clock::time_point{10s};

    controller::AdmissionRateLimiter zero_limit{
        {.maximum_admissions = 0U, .window = 1s}};
    controller::AdmissionRateLimiter excessive_limit{
        {.maximum_admissions =
             controller::AdmissionRateLimiter::maximum_admission_limit + 1U,
         .window = 1s}};
    controller::AdmissionRateLimiter short_window{
        {.maximum_admissions = 1U, .window = 99ms}};
    controller::AdmissionRateLimiter long_window{
        {.maximum_admissions = 1U, .window = 3600001ms}};
    test.check(
        !zero_limit.valid() && !excessive_limit.valid() &&
            !short_window.valid() && !long_window.valid(),
        "unsafe admission rate-limit configurations are rejected");
    test.check(
        !zero_limit.try_admit(origin).admitted,
        "invalid admission limiter fails closed");

    controller::AdmissionRateLimiter limiter{
        {.maximum_admissions = 3U, .window = 1s}};
    test.check(limiter.valid(), "bounded admission limiter is valid");
    test.check(
        limiter.try_admit(origin).admitted &&
            limiter.try_admit(origin + 100ms).admitted &&
            limiter.try_admit(origin + 200ms).admitted,
        "configured burst capacity is admitted");

    const auto denied = limiter.try_admit(origin + 250ms);
    test.check(
        !denied.admitted && denied.retry_after == 750ms,
        "excess admission is denied with a monotonic retry delay");
    const auto nearly_ready = limiter.try_admit(origin + 999ms);
    test.check(
        !nearly_ready.admitted && nearly_ready.retry_after == 1ms,
        "window remains closed through its final millisecond");
    test.check(
        limiter.try_admit(origin + 1s).admitted,
        "oldest admission expires exactly at the window boundary");
    test.check(
        limiter.try_admit(origin + 1100ms).admitted,
        "sliding window expires admissions independently");

    const auto backward = limiter.try_admit(origin + 1050ms);
    test.check(
        !backward.admitted && backward.retry_after == 1s,
        "monotonic clock regression fails closed without guessing");
    test.check(
        limiter.try_admit(origin + 1200ms).admitted,
        "clock regression does not corrupt retained admission state");

    limiter.reset();
    test.check(
        limiter.try_admit(origin).admitted,
        "explicit reset starts a fresh listener admission lifetime");

    return test.result();
}
