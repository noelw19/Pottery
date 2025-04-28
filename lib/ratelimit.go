package lib

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/noelw19/honeypot/db"
)

type RateLimiter struct {
	tokens         float64   // Current number of tokens
	maxTokens      float64   // Maximum tokens allowed
	refillRate     float64   // Tokens added per second
	lastRefillTime time.Time // Last time tokens were refilled
	mutex          sync.Mutex
}

func NewRateLimiter(maxTokens, refillRate float64) *RateLimiter {
	return &RateLimiter{
		tokens:         maxTokens,
		maxTokens:      maxTokens,
		refillRate:     refillRate,
		lastRefillTime: time.Now(),
	}
}

func (r *RateLimiter) refillTokens() {
	now := time.Now()
	duration := now.Sub(r.lastRefillTime).Seconds()
	tokensToAdd := duration * r.refillRate

	r.tokens += tokensToAdd
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
	r.lastRefillTime = now
}

func (r *RateLimiter) Allow() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.refillTokens()

	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

type IPRateLimiter struct {
	limiters map[string]*RateLimiter
	mutex    sync.Mutex
}

func NewIPRateLimiter() *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*RateLimiter),
	}
}

func (i *IPRateLimiter) GetLimiter(ip string) *RateLimiter {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	limiter, exists := i.limiters[ip]
	if !exists {
		// Allow 100 requests per minute
		limiter = NewRateLimiter(100, 0.05)
		i.limiters[ip] = limiter
	}

	return limiter
}

// middleware that implements both the ratelimiting and the ip blacklisting
func RateLimitMiddleware(ipRateLimiter *IPRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Invalid IP", http.StatusInternalServerError)
			return
		}

		db := &db.Db{
			Filename: "./honeypot.db",
		}
		limiter := ipRateLimiter.GetLimiter(ip)
		if limiter.Allow() {
			inBlacklist := db.CheckIP_blacklist(ip)
			if !inBlacklist {
				next(w, r)
			} else {
				log.Println(RedLog("Blacklisted IP made a request: " + ip))
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
		} else {
			log.Println(RedLog("requests from " + ip + " being rate limited"))
			inBlacklist := db.CheckIP_blacklist(ip)

			if !inBlacklist {
				// save to blacklist
				err := db.Set_Blacklist(ip)
				if err != nil {
					log.Println("Error saving ip to blacklist: ", err)
				}
			
				http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
		}
	}
}
