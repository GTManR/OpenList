package handles

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/OpenListTeam/OpenList/v4/internal/abuse"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type LoginReq struct {
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password"`
	OtpCode        string `json:"otp_code"`
	TurnstileToken string `json:"turnstile_token"`
}

// Login Deprecated
func Login(c *gin.Context) {
	var req LoginReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	req.Password = model.StaticHash(req.Password)
	loginHash(c, &req)
}

// LoginHash login with password hashed by sha256
func LoginHash(c *gin.Context) {
	var req LoginReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	loginHash(c, &req)
}

func verifyTurnstile(c *gin.Context, req *LoginReq, ip string, count int) bool {
	if !common.TurnstileRequired() {
		return true
	}
	// Require a fresh Turnstile token on every login request, including the
	// 2FA second step (the frontend keeps the widget alive and issues a new
	// token for it). Returning a uniform 400 when the token is missing avoids
	// leaking which accounts have 2FA enabled, and always requiring the token
	// prevents bypassing Turnstile by simply sending an otp_code.
	if req.TurnstileToken == "" {
		common.ErrorStrResp(c, "请先完成验证码验证", 400)
		return false
	}
	if !common.VerifyTurnstileToken(req.TurnstileToken, abuse.IPFromGin(c)) {
		// Count failed verifications toward the per-IP limit so a flood of
		// bogus tokens eventually gets locked out instead of endlessly
		// triggering remote siteverify calls.
		model.LoginCache.Set(ip, count+1)
		abuse.Record(ip, abuse.BehaviorTurnstileFail)
		if count+1 >= model.DefaultMaxAuthRetries {
			abuse.OnAuthLockout(ip, "turnstile_login")
		}
		common.ErrorStrResp(c, "验证码验证失败", 400)
		return false
	}
	return true
}

func loginHash(c *gin.Context, req *LoginReq) {
	// check count of login first (cheap, local) so an already-locked-out IP
	// can't be used to flood the remote Turnstile siteverify API.
	ip := abuse.IPFromGin(c)
	count, ok := model.LoginCache.Get(ip)
	if ok && count >= model.DefaultMaxAuthRetries {
		abuse.OnAuthLockout(ip, "http_login")
		common.ErrorStrResp(c, model.TooManyAttempts, 429)
		model.LoginCache.Expire(ip, model.DefaultLockDuration)
		return
	}
	if !verifyTurnstile(c, req, ip, count) {
		return
	}
	// check username
	user, err := op.GetUserByName(req.Username)
	if err != nil {
		common.ErrorStrResp(c, model.InvalidUsernameOrPassword, 401)
		model.LoginCache.Set(ip, count+1)
		if count+1 >= model.DefaultMaxAuthRetries {
			abuse.OnAuthLockout(ip, "http_login")
		}
		return
	}
	// validate password hash
	if err := user.ValidatePwdStaticHash(req.Password); err != nil {
		common.ErrorStrResp(c, model.InvalidUsernameOrPassword, 401)
		model.LoginCache.Set(ip, count+1)
		if count+1 >= model.DefaultMaxAuthRetries {
			abuse.OnAuthLockout(ip, "http_login")
		}
		return
	}
	// check 2FA
	if user.OtpSecret != "" {
		if !totp.Validate(req.OtpCode, user.OtpSecret) {
			// 402 - need opt
			common.ErrorStrResp(c, model.Invalid2FACode, 402)
			model.LoginCache.Set(ip, count+1)
			if count+1 >= model.DefaultMaxAuthRetries {
				abuse.OnAuthLockout(ip, "http_login")
			}
			return
		}
	}
	// generate token
	token, err := common.GenerateToken(user)
	if err != nil {
		common.ErrorResp(c, err, 500, true)
		return
	}
	common.SuccessResp(c, gin.H{"token": token})
	model.LoginCache.Del(ip)
}

type UserResp struct {
	model.User
	Otp   bool `json:"otp"`
	Prefs struct {
		LastWatched map[string]string `json:"last_watched,omitempty"`
	} `json:"prefs"`
}

// CurrentUser get current user by token
// if token is empty, return guest user
func CurrentUser(c *gin.Context) {
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	userResp := UserResp{
		User: *user,
	}
	userResp.Password = ""
	if userResp.OtpSecret != "" {
		userResp.Otp = true
	}
	userResp.Prefs.LastWatched = user.LastWatchedMap()
	common.SuccessResp(c, userResp)
}

func UpdateCurrent(c *gin.Context) {
	var req model.User
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, model.GuestCannotUpdateProfile, 403)
		return
	}
	user.Username = req.Username
	if req.Password != "" {
		user.SetPassword(req.Password)
	}
	user.SsoID = req.SsoID
	if err := op.UpdateUser(user); err != nil {
		common.ErrorResp(c, err, 500)
	} else {
		common.SuccessResp(c)
	}
}

func Generate2FA(c *gin.Context) {
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, model.GuestCannotGenerate2FA, 403)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OpenList",
		AccountName: user.Username,
	})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	img, err := key.Image(400, 400)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	// to base64
	var buf bytes.Buffer
	png.Encode(&buf, img)
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	common.SuccessResp(c, gin.H{
		"qr":     "data:image/png;base64," + b64,
		"secret": key.Secret(),
	})
}

type Verify2FAReq struct {
	Code   string `json:"code" binding:"required"`
	Secret string `json:"secret" binding:"required"`
}

func Verify2FA(c *gin.Context) {
	var req Verify2FAReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, model.GuestCannotGenerate2FA, 403)
		return
	}
	if !totp.Validate(req.Code, req.Secret) {
		common.ErrorStrResp(c, model.Invalid2FACode, 400)
		return
	}
	user.OtpSecret = req.Secret
	if err := op.UpdateUser(user); err != nil {
		common.ErrorResp(c, err, 500)
	} else {
		common.SuccessResp(c)
	}
}

func LogOut(c *gin.Context) {
	err := common.InvalidateToken(c.GetHeader("Authorization"))
	if err != nil {
		common.ErrorResp(c, err, 500)
	} else {
		common.SuccessResp(c)
	}
}

type LastWatchedReq struct {
	Folder string `json:"folder" binding:"required"`
	File   string `json:"file" binding:"required"`
}

// UpdateLastWatched records the last watched file for a folder on the current user account.
func UpdateLastWatched(c *gin.Context) {
	var req LastWatchedReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if user.IsGuest() {
		common.ErrorStrResp(c, model.GuestCannotUpdatePrefs, 403)
		return
	}
	if err := user.SetLastWatched(req.Folder, req.File); err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	if err := op.UpdateUser(user); err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	common.SuccessResp(c, gin.H{
		"last_watched": user.LastWatchedMap(),
	})
}
