package auth

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ForgotPasswordResponse struct {
	Message          string `json:"message"`
	ResetToken       string `json:"reset_token,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

type ResetPasswordRequest struct {
	ResetToken      string `json:"reset_token" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

type ResetPasswordResponse struct {
	PasswordReset      bool `json:"password_reset"`
	SessionsTerminated bool `json:"sessions_terminated"`
	LoginRequired      bool `json:"login_required"`
}
