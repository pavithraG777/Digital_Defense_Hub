package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type passwordChangeRequirementReaderFunc func(context.Context, uuid.UUID, uuid.UUID) (bool, error)

func (f passwordChangeRequirementReaderFunc) RequiresPasswordChange(
	ctx context.Context,
	userID uuid.UUID,
	organizationID uuid.UUID,
) (bool, error) {
	return f(ctx, userID, organizationID)
}

func TestEnforcePasswordChange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	organizationID := uuid.New()

	reader := passwordChangeRequirementReaderFunc(func(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
		return true, nil
	})

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Set("organization_id", organizationID)
	})
	router.Use(EnforcePasswordChange(reader))
	router.GET("/api/v1/profile", noContent)
	router.POST("/api/v1/change-password", noContent)
	router.POST("/api/v1/auth/logout", noContent)
	router.POST("/api/v1/auth/logout-all", noContent)
	router.GET("/api/v1/dashboard", noContent)

	for _, test := range []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "profile", method: http.MethodGet, path: "/api/v1/profile", want: http.StatusNoContent},
		{name: "change password", method: http.MethodPost, path: "/api/v1/change-password", want: http.StatusNoContent},
		{name: "logout", method: http.MethodPost, path: "/api/v1/auth/logout", want: http.StatusNoContent},
		{name: "logout all", method: http.MethodPost, path: "/api/v1/auth/logout-all", want: http.StatusNoContent},
		{name: "blocked dashboard", method: http.MethodGet, path: "/api/v1/dashboard", want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, nil)
			router.ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestEnforcePasswordChangeAllowsUsersWithoutRequirement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	organizationID := uuid.New()

	reader := passwordChangeRequirementReaderFunc(func(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
		return false, nil
	})

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Set("organization_id", organizationID)
	})
	router.Use(EnforcePasswordChange(reader))
	router.GET("/api/v1/dashboard", noContent)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusNoContent, recorder.Body.String())
	}
}

func TestEnforcePasswordChangeDoesNotExposeReaderFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	reader := passwordChangeRequirementReaderFunc(func(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
		return false, errors.New("database connection details")
	})

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uuid.New())
		c.Set("organization_id", uuid.New())
	})
	router.Use(EnforcePasswordChange(reader))
	router.GET("/api/v1/dashboard", noContent)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	if recorder.Body.String() == "" || strings.Contains(recorder.Body.String(), "database connection details") {
		t.Fatalf("unexpected failure response: %s", recorder.Body.String())
	}
}

func noContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}
