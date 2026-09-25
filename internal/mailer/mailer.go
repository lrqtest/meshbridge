// Package mailer sends verification emails over SMTP (implicit TLS on 465,
// STARTTLS otherwise) and manages 6-digit verification codes with per-address
// cooldown, global rate limits, hashed storage, and attempt throttling.
// The mechanism follows the prior MineAI project; hardened: codes come from
// crypto/rand, are stored hashed, and verification attempts are bounded.
package mailer

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/smtp"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "embed"
)

//go:embed templates/verification.txt
var verificationTemplate string

type Config struct {
	Host     string // smtp.qq.com
	Port     int    // 465 (implicit TLS) or 587 (STARTTLS)
	Username string
	Password string
	From     string // defaults to Username
}

func (c Config) FromAddr() string {
	if c.From != "" {
		return c.From
	}
	return c.Username
}

// Sender delivers a message. Injectable for tests.
type Sender func(cfg Config, to, subject, body string) error

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]{2,}$`)

func ValidEmail(email string) bool {
	return len(email) <= 254 && emailRe.MatchString(email)
}

// ---- verification codes ----

type Limits struct {
	CooldownSeconds int
	ExpireMinutes   int
	MinuteLimit     int
	DailyLimit      int
}

type Service struct {
	DB     *sql.DB
	Config func() Config // current SMTP config (from settings)
	Secret func() string // server secret for code hashing
	Limits func() Limits // rate-limit knobs (from settings)
	Send   Sender        // defaults to SendSMTP
	Now    func() time.Time
}

// SendSMTP delivers over implicit TLS (465) or STARTTLS (587/25).
func SendSMTP(cfg Config, to, subject, body string) error {
	if cfg.Host == "" || cfg.Port == 0 {
		return fmt.Errorf("smtp not configured")
	}
	addr := cfg.Host + ":" + strconv.Itoa(cfg.Port)
	from := cfg.FromAddr()
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	msg := buildMessage(from, to, subject, body)

	if cfg.Port == 465 {
		return sendImplicitTLS(cfg.Host, addr, auth, from, to, msg)
	}
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}

func sendImplicitTLS(host, addr string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer cl.Close()
	if err := cl.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := cl.Mail(from); err != nil {
		return err
	}
	if err := cl.Rcpt(to); err != nil {
		return err
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: MeshBridge <" + from + ">\r\n")
	b.WriteString("To: <" + to + ">\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func CodeHash(serverSecret, email, code string) string {
	h := sha256.Sum256([]byte(serverSecret + ":" + email + ":" + code))
	return hex.EncodeToString(h[:])
}

func (s *Service) sender() Sender {
	if s.Send != nil {
		return s.Send
	}
	return SendSMTP
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SendCode generates, stores (hashed), and emails a 6-digit code.
// Rate limits mirror the MineAI project: per-address cooldown + global
// per-minute and per-day caps.
func (s *Service) SendCode(email, purpose string) (cooldown int, err error) {
	if !ValidEmail(email) {
		return 0, fmt.Errorf("invalid email")
	}
	switch purpose {
	case "setup", "register", "reset":
	default:
		return 0, fmt.Errorf("bad purpose")
	}
	lim := s.Limits() // CooldownSeconds <= 0 disables the per-address cooldown (tests); prod default comes from settings
	now := s.now()

	// per-address cooldown
	var lastCreated int64
	qerr := s.DB.QueryRow(`SELECT created_at FROM email_verification_codes
		WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1`, email, purpose).Scan(&lastCreated)
	if qerr == nil && now.Unix()-lastCreated < int64(lim.CooldownSeconds) {
		rem := int64(lim.CooldownSeconds) - (now.Unix() - lastCreated)
		return int(rem), fmt.Errorf("please wait %ds before requesting another code", rem)
	}
	// global caps
	var cnt int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM email_verification_codes WHERE created_at > ?`,
		now.Add(-time.Minute).Unix()).Scan(&cnt)
	if lim.MinuteLimit > 0 && cnt >= lim.MinuteLimit {
		return 0, fmt.Errorf("system busy, try again shortly")
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM email_verification_codes WHERE created_at > ?`, dayStart).Scan(&cnt)
	if lim.DailyLimit > 0 && cnt >= lim.DailyLimit {
		return 0, fmt.Errorf("daily verification limit reached, try tomorrow")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return 0, err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	hash := CodeHash(s.Secret(), email, code)
	exp := now.Add(time.Duration(lim.ExpireMinutes) * time.Minute)
	res, err := s.DB.Exec(`INSERT INTO email_verification_codes(email,code_hash,purpose,created_at,expires_at)
		VALUES(?,?,?,?,?)`, email, hash, purpose, now.Unix(), exp.Unix())
	if err != nil {
		return 0, err
	}
	body := strings.NewReplacer("{{CODE}}", code, "{{MINUTES}}", strconv.Itoa(lim.ExpireMinutes)).Replace(verificationTemplate)
	if err := s.sender()(s.Config(), email, "[MeshBridge] 邮箱验证码", body); err != nil {
		// A failed delivery must not burn the user's cooldown: drop the row.
		if id, iderr := res.LastInsertId(); iderr == nil {
			_, _ = s.DB.Exec(`DELETE FROM email_verification_codes WHERE id=?`, id)
		}
		return 0, fmt.Errorf("send failed: %w", err)
	}
	return lim.CooldownSeconds, nil
}

// CheckCode verifies and consumes a code. Max 5 attempts per code.
func (s *Service) CheckCode(email, purpose, code string) bool {
	if len(code) != 6 {
		return false
	}
	now := s.now().Unix()
	var id int64
	var hash string
	var attempts int
	err := s.DB.QueryRow(`SELECT id, code_hash, attempts FROM email_verification_codes
		WHERE email=? AND purpose=? AND used=0 AND expires_at > ? ORDER BY id DESC LIMIT 1`,
		email, purpose, now).Scan(&id, &hash, &attempts)
	if err != nil || attempts >= 5 {
		return false
	}
	want, err := hex.DecodeString(hash)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256([]byte(s.Secret() + ":" + email + ":" + code))
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		_, _ = s.DB.Exec(`UPDATE email_verification_codes SET attempts=attempts+1 WHERE id=?`, id)
		return false
	}
	_, err = s.DB.Exec(`UPDATE email_verification_codes SET used=1 WHERE id=?`, id)
	return err == nil
}
