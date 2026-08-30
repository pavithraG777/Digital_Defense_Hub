package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders adds browser protections that are safe for this JSON API.
// TLS/HSTS is intentionally enforced at the reverse proxy, where the service
// can reliably know that the public connection is HTTPS.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}
