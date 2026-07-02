package server

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Login rate limit: each IP gets a bucket of loginBurst attempts that
// refills one attempt per loginRefillEvery. Steady state is 6 attempts a
// minute: generous for a human retyping a password, useless for volume
// guessing (argon2 already makes each attempt slow; this caps how many an
// IP gets at all). Limits are per process and per IP; deployments behind a
// proxy that mixes clients into one IP should limit at the proxy instead
// (the README already takes that stance).
const (
	loginBurst        = 5
	loginRefillEvery  = 10 * time.Second
	limiterSweepEvery = 5 * time.Minute
)

// ipLimiter is an in-memory per-key token bucket. Buckets refill lazily on
// access; idle entries are swept opportunistically so the map doesn't grow
// with every IP that ever tried to log in.
type ipLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	burst       float64
	refillEvery time.Duration
	lastSweep   time.Time
	now         func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(burst int, refillEvery time.Duration, now func() time.Time) *ipLimiter {
	if now == nil {
		now = time.Now
	}
	return &ipLimiter{
		buckets:     make(map[string]*bucket),
		burst:       float64(burst),
		refillEvery: refillEvery,
		lastSweep:   now(),
		now:         now,
	}
}

// allow spends one token from key's bucket. When the bucket is empty it
// reports false and how long until the next token exists.
func (l *ipLimiter) allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		refilled := float64(now.Sub(b.last)) / float64(l.refillEvery)
		b.tokens = math.Min(l.burst, b.tokens+refilled)
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) * float64(l.refillEvery))
}

// sweep drops buckets that have been idle long enough to be full again,
// which makes them indistinguishable from fresh ones. Caller holds l.mu.
func (l *ipLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < limiterSweepEvery {
		return
	}
	l.lastSweep = now
	fullAfter := time.Duration(l.burst) * l.refillEvery
	for key, b := range l.buckets {
		if now.Sub(b.last) >= fullAfter {
			delete(l.buckets, key)
		}
	}
}

// withLoginRateLimit gates a handler behind the per-IP login limiter,
// answering 429 with a Retry-After when the bucket is empty.
func (s *Server) withLoginRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, retryAfter := s.loginLimiter.allow(clientIP(r))
		if !ok {
			secs := int(math.Ceil(retryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			s.writeError(w, http.StatusTooManyRequests, "too many login attempts, retry later")
			return
		}
		next(w, r)
	}
}

// clientIP keys the limiter by the TCP peer address. Deliberately not
// X-Forwarded-For: an unauthenticated attacker can put anything there and
// hop buckets freely. Behind a reverse proxy every client shares the
// proxy's IP; rate-limit at the proxy in that topology.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
