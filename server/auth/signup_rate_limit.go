package auth

import (
	"fmt"
	"math"
	"os"
	"strconv"
)

// Options configures the server authentication runtime. Hosted deployments
// supply LookupEnv; a nil lookup reads the process environment.
type Options struct {
	Session         SessionPolicy
	SignupRateLimit SignupRateLimitOptions
	LookupEnv       func(string) (*string, error)
}

// SignupRateLimitOptions holds declared signup limits. Nil fields use defaults.
type SignupRateLimitOptions struct {
	Signal        *string
	Max           *int
	WindowSeconds *int
}

type signupRateLimit struct {
	signal        string
	max           int32
	windowSeconds int
}

func resolveSignupRateLimit(input SignupRateLimitOptions, lookupEnv func(string) (*string, error)) (signupRateLimit, error) {
	if lookupEnv == nil {
		lookupEnv = func(name string) (*string, error) {
			if value, present := os.LookupEnv(name); present {
				return new(value), nil
			}
			return nil, nil
		}
	}
	read := func(name string) (*string, error) {
		value, err := lookupEnv(name)
		if err != nil {
			return nil, fmt.Errorf("%s could not be read", name)
		}
		return value, nil
	}
	signal := "email"
	if input.Signal != nil {
		signal = *input.Signal
	}
	if !validSignupSignal(signal) {
		return signupRateLimit{}, fmt.Errorf("auth.rate_limits.signup.signal must be email, global, or off")
	}
	const signalName = "AUTH_RATE_LIMITS_SIGNUP_SIGNAL"
	value, err := read(signalName)
	if err != nil {
		return signupRateLimit{}, err
	}
	if value != nil {
		if !validSignupSignal(*value) {
			return signupRateLimit{}, fmt.Errorf("%s must be email, global, or off", signalName)
		}
		signal = *value
	}
	max, err := signupLimitInteger(input.Max, 10, math.MaxInt32,
		"auth.rate_limits.signup.max", "AUTH_RATE_LIMITS_SIGNUP_MAX", read)
	if err != nil {
		return signupRateLimit{}, err
	}
	window, err := signupLimitInteger(input.WindowSeconds, 900, 31_536_000,
		"auth.rate_limits.signup.window_seconds", "AUTH_RATE_LIMITS_SIGNUP_WINDOW_SECONDS", read)
	if err != nil {
		return signupRateLimit{}, err
	}
	return signupRateLimit{signal: signal, max: int32(max), windowSeconds: window}, nil
}

func validSignupSignal(value string) bool {
	return value == "email" || value == "global" || value == "off"
}

func signupLimitInteger(declared *int, fallback, maximum int, field, name string,
	lookupEnv func(string) (*string, error)) (int, error) {
	if declared != nil {
		if *declared < 1 || *declared > maximum {
			return 0, fmt.Errorf("%s must be an integer between 1 and %d", field, maximum)
		}
		fallback = *declared
	}
	raw, err := lookupEnv(name)
	if err != nil {
		return 0, err
	}
	if raw == nil {
		return fallback, nil
	}
	value, err := strconv.ParseUint(*raw, 10, 31)
	if err != nil || strconv.FormatUint(value, 10) != *raw || value < 1 || value > uint64(maximum) {
		return 0, fmt.Errorf("%s must be an integer between 1 and %d", name, maximum)
	}
	return int(value), nil
}

func (limit signupRateLimit) subject(email string) string {
	if limit.signal == "global" {
		return "signup:global"
	}
	return email
}
