package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	_ "paircomm/server/internal/sqlitedrv"
)

type Server struct {
	db               *sql.DB
	spoolTTL         time.Duration
	supervisorWindow time.Duration
	pendingWindow    time.Duration
	pairingTokenTTL  time.Duration
}

type deviceRecord struct {
	ID     string
	PairID string
	Side   string
	APIKey string
}

type supervisorRecord struct {
	ID     string
	PairID string
	Side   string
	APIKey string
	Status string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	ctx := context.Background()

	dbPath := os.Getenv("PC_DB_PATH")
	if dbPath == "" {
		dbPath = "paircomm.db"
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("failed to ensure db dir: %v", err)
	}

	db, err := sql.Open("custom_sqlite", dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("ping db: %v", err)
	}

	absDBPath, err := filepath.Abs(dbPath)
	if err != nil {
		log.Printf("warn: resolving absolute db path: %v", err)
		absDBPath = dbPath
	}
	log.Printf("database initialized at %s", absDBPath)
	log.Printf("to inspect the database, run: sqlite3 %q 'SELECT * FROM pairs;'", absDBPath)

	server := &Server{
		db:               db,
		spoolTTL:         getEnvDuration("PC_SPOOL_TTL", 48*time.Hour),
		supervisorWindow: getEnvDuration("PC_SUPERVISOR_WINDOW", 30*24*time.Hour),
		pendingWindow:    getEnvDuration("PC_PENDING_WINDOW", 24*time.Hour),
		pairingTokenTTL:  5 * time.Minute,
	}

	if err := server.runMigrations(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	go server.startPendingWorker(ctx)
	go server.startPurgeWorker(ctx)

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(server.requestLogger)

	router.Get("/health", server.handleHealth)
	router.Post("/activate", server.handleActivate)
	router.Post("/pairing/start", server.withDeviceAuth(server.handlePairingStart))
	router.Get("/policy", server.withAnyAuth(server.handleGetPolicy))
	router.Get("/status", server.withAnyAuth(server.handleStatus))
	router.Post("/supervisors/add", server.handleSupervisorAdd)
	router.Post("/supervisors/approve", server.withSupervisorAuth(server.handleSupervisorApprove))
	router.Post("/supervisors/fast_approve", server.withSupervisorAuth(server.handleSupervisorFastApprove))
	router.Post("/supervisors/remove", server.withSupervisorAuth(server.handleSupervisorRemove))
	router.Post("/supervisors/reset", server.withDeviceAuth(server.handleSupervisorReset))
	router.Post("/supervisors/veto", server.withSupervisorAuth(server.handleSupervisorVeto))
	router.Get("/inbox", server.withAnyAuth(server.handleInbox))
	router.Post("/acks", server.withAnyAuth(server.handleAck))
	router.Get("/receipts", server.withAnyAuth(server.handleReceipts))
	router.Get("/audit", server.withAnyAuth(server.handleAudit))
	router.Route("/messages", func(r chi.Router) {
		r.Post("/", server.withDeviceAuth(server.handlePostMessage))
		r.Get("/{messageID}", server.withAnyAuth(server.handleGetMessage))
	})

	addr := getEnvString("PC_HTTP_ADDR", ":8080")
	log.Printf("server listening on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return fallback
}

func getEnvString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (s *Server) runMigrations(ctx context.Context) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS pairs (
pair_id TEXT PRIMARY KEY,
policy_version INTEGER NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS devices (
id TEXT PRIMARY KEY,
pair_id TEXT NOT NULL,
side TEXT NOT NULL,
api_key TEXT NOT NULL,
created_at TIMESTAMP NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS supervisors (
id TEXT PRIMARY KEY,
pair_id TEXT NOT NULL,
side TEXT NOT NULL,
display_name TEXT,
api_key TEXT NOT NULL,
status TEXT NOT NULL,
created_at TIMESTAMP NOT NULL,
updated_at TIMESTAMP
);`,
		`CREATE TABLE IF NOT EXISTS pairing_tokens (
token TEXT PRIMARY KEY,
pair_id TEXT NOT NULL,
side TEXT NOT NULL,
expires_at TIMESTAMP NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS messages (
id TEXT PRIMARY KEY,
pair_id TEXT NOT NULL,
from_device_id TEXT NOT NULL,
header TEXT NOT NULL,
ciphertext TEXT,
created_at TIMESTAMP NOT NULL,
retention_until TIMESTAMP NOT NULL,
purged_at TIMESTAMP,
policy_version INTEGER NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS message_recipients (
message_id TEXT NOT NULL,
recipient_id TEXT NOT NULL,
recipient_type TEXT NOT NULL,
side TEXT,
required INTEGER NOT NULL,
ack_state TEXT NOT NULL,
acked_at TIMESTAMP,
PRIMARY KEY (message_id, recipient_id)
);`,
		`CREATE TABLE IF NOT EXISTS pending_events (
id TEXT PRIMARY KEY,
pair_id TEXT NOT NULL,
side TEXT NOT NULL,
type TEXT NOT NULL,
status TEXT NOT NULL,
payload TEXT NOT NULL,
created_at TIMESTAMP NOT NULL,
effective_at TIMESTAMP NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS audit_log (
id INTEGER PRIMARY KEY AUTOINCREMENT,
pair_id TEXT NOT NULL,
actor_type TEXT NOT NULL,
actor_id TEXT NOT NULL,
event_type TEXT NOT NULL,
details TEXT,
created_at TIMESTAMP NOT NULL
);`,
	}
	for _, stmt := range schema {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type activateRequest struct {
	PairID    string          `json:"pair_id"`
	Side      string          `json:"side"`
	DevicePub json.RawMessage `json:"device_pub"`
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	var req activateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	side := strings.ToUpper(strings.TrimSpace(req.Side))
	if side != "A" && side != "B" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid side"})
		return
	}
	pairID := strings.TrimSpace(req.PairID)
	if pairID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pair_id required"})
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx start failed"})
		return
	}
	defer tx.Rollback()

	var policyVersion int
	err = tx.QueryRowContext(r.Context(), "SELECT policy_version FROM pairs WHERE pair_id = ?", pairID).Scan(&policyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		policyVersion = 1
		if _, err := tx.ExecContext(r.Context(), "INSERT INTO pairs(pair_id, policy_version) VALUES(?, ?)", pairID, policyVersion); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create pair failed"})
			return
		}
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pair lookup failed"})
		return
	}

	deviceID := newID()
	apiKey := newID()
	now := time.Now().UTC()
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO devices(id, pair_id, side, api_key, created_at) VALUES(?,?,?,?,?)", deviceID, pairID, side, apiKey, now); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "device insert failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"pair_id":        pairID,
		"side":           side,
		"device_id":      deviceID,
		"api_key":        apiKey,
		"policy_version": policyVersion,
	})
}

func (s *Server) withDeviceAuth(next func(http.ResponseWriter, *http.Request, deviceRecord)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		device, err := s.authenticateDevice(r.Context(), r)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, sql.ErrNoRows) {
				status = http.StatusUnauthorized
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		next(w, r, device)
	}
}

func (s *Server) withSupervisorAuth(next func(http.ResponseWriter, *http.Request, supervisorRecord)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sup, err := s.authenticateSupervisor(r.Context(), r)
		if err != nil {
			status := http.StatusUnauthorized
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		next(w, r, sup)
	}
}

type authContext struct {
	device     *deviceRecord
	supervisor *supervisorRecord
}

func (s *Server) withAnyAuth(next func(http.ResponseWriter, *http.Request, authContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if device, err := s.authenticateDevice(r.Context(), r); err == nil {
			next(w, r, authContext{device: &device})
			return
		}
		if sup, err := s.authenticateSupervisor(r.Context(), r); err == nil {
			next(w, r, authContext{supervisor: &sup})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
	}
}

func (s *Server) authenticateDevice(ctx context.Context, r *http.Request) (deviceRecord, error) {
	id := r.Header.Get("X-Device-ID")
	key := r.Header.Get("X-Device-Key")
	if id == "" || key == "" {
		return deviceRecord{}, errors.New("missing device credentials")
	}
	var device deviceRecord
	err := s.db.QueryRowContext(ctx, "SELECT id, pair_id, side, api_key FROM devices WHERE id = ?", id).Scan(&device.ID, &device.PairID, &device.Side, &device.APIKey)
	if err != nil {
		return deviceRecord{}, err
	}
	if device.APIKey != key {
		return deviceRecord{}, errors.New("invalid device key")
	}
	return device, nil
}

func (s *Server) authenticateSupervisor(ctx context.Context, r *http.Request) (supervisorRecord, error) {
	id := r.Header.Get("X-Supervisor-ID")
	key := r.Header.Get("X-Supervisor-Key")
	if id == "" || key == "" {
		return supervisorRecord{}, errors.New("missing supervisor credentials")
	}
	var sup supervisorRecord
	err := s.db.QueryRowContext(ctx, "SELECT id, pair_id, side, api_key, status FROM supervisors WHERE id = ?", id).Scan(&sup.ID, &sup.PairID, &sup.Side, &sup.APIKey, &sup.Status)
	if err != nil {
		return supervisorRecord{}, err
	}
	if sup.APIKey != key {
		return supervisorRecord{}, errors.New("invalid supervisor key")
	}
	if sup.Status != "active" {
		return supervisorRecord{}, errors.New("supervisor inactive")
	}
	return sup, nil
}

func (s *Server) handlePairingStart(w http.ResponseWriter, r *http.Request, device deviceRecord) {
	var body struct {
		Side string `json:"side"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	side := strings.ToUpper(strings.TrimSpace(body.Side))
	if side == "" {
		side = device.Side
	}
	if side != device.Side {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "side mismatch"})
		return
	}
	token := newID()
	expires := time.Now().UTC().Add(s.pairingTokenTTL)
	_, err := s.db.ExecContext(r.Context(), "INSERT INTO pairing_tokens(token, pair_id, side, expires_at) VALUES(?,?,?,?)", token, device.PairID, side, expires)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pairing_token": token,
		"expires_at":    expires.Format(time.RFC3339),
	})
}

type addSupervisorRequest struct {
	PairID       string `json:"pair_id"`
	Side         string `json:"side"`
	PairingToken string `json:"pairing_token"`
	Supervisor   struct {
		DisplayName string `json:"display_name"`
	} `json:"supervisor"`
}

func (s *Server) handleSupervisorAdd(w http.ResponseWriter, r *http.Request) {
	var req addSupervisorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	pairID := strings.TrimSpace(req.PairID)
	side := strings.ToUpper(strings.TrimSpace(req.Side))
	token := strings.TrimSpace(req.PairingToken)
	if pairID == "" || side == "" || token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx failed"})
		return
	}
	defer tx.Rollback()

	var tokenPairID, tokenSide, expiresStr string
	err = tx.QueryRowContext(r.Context(), "SELECT pair_id, side, expires_at FROM pairing_tokens WHERE token = ?", token).Scan(&tokenPairID, &tokenSide, &expiresStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, expiresStr)
	if parseErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token parse failed"})
		return
	}
	if tokenPairID != pairID || tokenSide != side {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token mismatch"})
		return
	}
	if time.Now().UTC().After(expires) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token expired"})
		return
	}

	var policyVersion int
	err = tx.QueryRowContext(r.Context(), "SELECT policy_version FROM pairs WHERE pair_id = ?", pairID).Scan(&policyVersion)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pair not found"})
		return
	}

	countActive, err := countActiveSupervisorsTx(r.Context(), tx, pairID, side)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "count supervisors failed"})
		return
	}

	supervisorID := newID()
	apiKey := newID()
	now := time.Now().UTC()

	if countActive == 0 {
		if _, err := tx.ExecContext(r.Context(), "INSERT INTO supervisors(id, pair_id, side, display_name, api_key, status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
			supervisorID, pairID, side, req.Supervisor.DisplayName, apiKey, "active", now, now); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "supervisor insert failed"})
			return
		}
		if _, err := tx.ExecContext(r.Context(), "UPDATE pairs SET policy_version = policy_version + 1 WHERE pair_id = ?", pairID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy bump failed"})
			return
		}
		if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_log(pair_id, actor_type, actor_id, event_type, details, created_at) VALUES(?,?,?,?,?,?)",
			pairID, "system", "system", "supervisor_add", fmt.Sprintf("auto approved supervisor %s", supervisorID), now); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit failed"})
			return
		}
		if _, err := tx.ExecContext(r.Context(), "DELETE FROM pairing_tokens WHERE token = ?", token); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token cleanup failed"})
			return
		}
		if err := tx.Commit(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         "active",
			"supervisor_id":  supervisorID,
			"api_key":        apiKey,
			"policy_version": policyVersion + 1,
		})
		return
	}

	pendingID := newID()
	payload := map[string]any{
		"supervisor_id": supervisorID,
		"api_key":       apiKey,
		"display_name":  req.Supervisor.DisplayName,
	}
	payloadBytes, _ := json.Marshal(payload)
	effective := now.Add(s.pendingWindow)
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO supervisors(id, pair_id, side, display_name, api_key, status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
		supervisorID, pairID, side, req.Supervisor.DisplayName, apiKey, "pending", now, now); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "supervisor pending insert failed"})
		return
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO pending_events(id, pair_id, side, type, status, payload, created_at, effective_at) VALUES(?,?,?,?,?,?,?,?)",
		pendingID, pairID, side, "add", "pending", string(payloadBytes), now, effective); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending insert failed"})
		return
	}
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM pairing_tokens WHERE token = ?", token); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token cleanup failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "pending",
		"supervisor_id": supervisorID,
		"api_key":       apiKey,
		"pending_id":    pendingID,
		"effective_at":  effective.Format(time.RFC3339),
	})
}

func countActiveSupervisorsTx(ctx context.Context, tx *sql.Tx, pairID, side string) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, "SELECT COUNT(1) FROM supervisors WHERE pair_id = ? AND side = ? AND status = 'active'", pairID, side).Scan(&count)
	return count, err
}

func (s *Server) handleSupervisorApprove(w http.ResponseWriter, r *http.Request, sup supervisorRecord) {
	s.handleSupervisorApproval(w, r, sup, true)
}

func (s *Server) handleSupervisorFastApprove(w http.ResponseWriter, r *http.Request, sup supervisorRecord) {
	s.handleSupervisorApproval(w, r, sup, false)
}

func (s *Server) handleSupervisorApproval(w http.ResponseWriter, r *http.Request, sup supervisorRecord, sameSide bool) {
	var req struct {
		PairID    string `json:"pair_id"`
		PendingID string `json:"pending_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	pairID := strings.TrimSpace(req.PairID)
	pendingID := strings.TrimSpace(req.PendingID)
	if pairID == "" || pendingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	if sup.PairID != pairID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pair mismatch"})
		return
	}

	var targetSide string
	if sameSide {
		targetSide = sup.Side
	} else {
		if sup.Side == "A" {
			targetSide = "B"
		} else {
			targetSide = "A"
		}
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx failed"})
		return
	}
	defer tx.Rollback()

	var side, eventType, status, payload string
	var effective string
	err = tx.QueryRowContext(r.Context(), "SELECT side, type, status, payload, effective_at FROM pending_events WHERE id = ? AND pair_id = ?", pendingID, pairID).Scan(&side, &eventType, &status, &payload, &effective)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pending not found"})
		return
	}
	if side != targetSide || eventType != "add" || status != "pending" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not approvable"})
		return
	}

	var payloadData map[string]any
	_ = json.Unmarshal([]byte(payload), &payloadData)
	supervisorID, _ := payloadData["supervisor_id"].(string)

	now := time.Now().UTC()
	if _, err := tx.ExecContext(r.Context(), "UPDATE supervisors SET status = 'active', updated_at = ? WHERE id = ?", now, supervisorID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "activate supervisor failed"})
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE pending_events SET status = 'executed', effective_at = ? WHERE id = ?", now, pendingID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending update failed"})
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE pairs SET policy_version = policy_version + 1 WHERE pair_id = ?", pairID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy bump failed"})
		return
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_log(pair_id, actor_type, actor_id, event_type, details, created_at) VALUES(?,?,?,?,?,?)",
		pairID, "supervisor", sup.ID, "supervisor_approve", fmt.Sprintf("approved supervisor %s", supervisorID), now); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handleSupervisorRemove(w http.ResponseWriter, r *http.Request, sup supervisorRecord) {
	var req struct {
		PairID  string   `json:"pair_id"`
		Side    string   `json:"side"`
		Targets []string `json:"targets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	pairID := strings.TrimSpace(req.PairID)
	if pairID == "" || len(req.Targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	if sup.PairID != pairID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pair mismatch"})
		return
	}
	side := strings.ToUpper(strings.TrimSpace(req.Side))
	if side == "" {
		side = sup.Side
	}
	if side != sup.Side {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "side mismatch"})
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx failed"})
		return
	}
	defer tx.Rollback()

	countActive, err := countActiveSupervisorsTx(r.Context(), tx, pairID, side)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "count failed"})
		return
	}
	removing := 0
	isSelf := false
	for _, id := range req.Targets {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		removing++
		if id == sup.ID {
			isSelf = true
		}
	}
	if removing == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no targets"})
		return
	}
	if countActive-removing <= 0 && isSelf {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "last supervisor"})
		return
	}

	payloadBytes, _ := json.Marshal(map[string]any{"targets": req.Targets})
	effective := time.Now().UTC().Add(s.pendingWindow)
	pendingID := newID()
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO pending_events(id, pair_id, side, type, status, payload, created_at, effective_at) VALUES(?,?,?,?,?,?,?,?)",
		pendingID, pairID, side, "remove", "pending", string(payloadBytes), time.Now().UTC(), effective); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending insert failed"})
		return
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_log(pair_id, actor_type, actor_id, event_type, details, created_at) VALUES(?,?,?,?,?,?)",
		pairID, "supervisor", sup.ID, "supervisor_remove", fmt.Sprintf("scheduled removal %s", strings.Join(req.Targets, ",")), time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "pending", "pending_id": pendingID, "effective_at": effective.Format(time.RFC3339)})
}

func (s *Server) handleSupervisorReset(w http.ResponseWriter, r *http.Request, device deviceRecord) {
	var req struct {
		PairID       string `json:"pair_id"`
		Side         string `json:"side"`
		PairingToken string `json:"pairing_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	pairID := strings.TrimSpace(req.PairID)
	side := strings.ToUpper(strings.TrimSpace(req.Side))
	if side == "" {
		side = device.Side
	}
	if pairID == "" || side == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	if device.PairID != pairID || device.Side != side {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "mismatch"})
		return
	}
	token := strings.TrimSpace(req.PairingToken)
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token required"})
		return
	}

	var tokenPairID, tokenSide, expiresStr string
	err := s.db.QueryRowContext(r.Context(), "SELECT pair_id, side, expires_at FROM pairing_tokens WHERE token = ?", token).Scan(&tokenPairID, &tokenSide, &expiresStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, expiresStr)
	if parseErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token parse failed"})
		return
	}
	if tokenPairID != pairID || tokenSide != side || time.Now().UTC().After(expires) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token invalid"})
		return
	}

	effective := time.Now().UTC().Add(s.pendingWindow)
	pendingID := newID()
	payloadBytes, _ := json.Marshal(map[string]any{"action": "reset"})
	_, err = s.db.ExecContext(r.Context(), "INSERT INTO pending_events(id, pair_id, side, type, status, payload, created_at, effective_at) VALUES(?,?,?,?,?,?,?,?)",
		pendingID, pairID, side, "reset", "pending", string(payloadBytes), time.Now().UTC(), effective)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending insert failed"})
		return
	}
	_, _ = s.db.ExecContext(r.Context(), "DELETE FROM pairing_tokens WHERE token = ?", token)
	writeJSON(w, http.StatusOK, map[string]any{"status": "pending", "pending_id": pendingID, "effective_at": effective.Format(time.RFC3339)})
}

func (s *Server) handleSupervisorVeto(w http.ResponseWriter, r *http.Request, sup supervisorRecord) {
	var req struct {
		PairID    string `json:"pair_id"`
		PendingID string `json:"pending_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	pairID := strings.TrimSpace(req.PairID)
	pendingID := strings.TrimSpace(req.PendingID)
	if pairID == "" || pendingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	if sup.PairID != pairID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pair mismatch"})
		return
	}

	res, err := s.db.ExecContext(r.Context(), "UPDATE pending_events SET status = 'canceled' WHERE id = ? AND pair_id = ? AND status = 'pending'", pendingID, pairID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not cancelable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "vetoed"})
}
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request, auth authContext) {
	pairID := ""
	if auth.device != nil {
		pairID = auth.device.PairID
	} else if auth.supervisor != nil {
		pairID = auth.supervisor.PairID
	}
	if pairID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown pair"})
		return
	}

	policy, err := s.buildPolicy(r.Context(), pairID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) buildPolicy(ctx context.Context, pairID string) (map[string]any, error) {
	var policyVersion int
	if err := s.db.QueryRowContext(ctx, "SELECT policy_version FROM pairs WHERE pair_id = ?", pairID).Scan(&policyVersion); err != nil {
		return nil, err
	}

	devices := map[string]string{}
	rows, err := s.db.QueryContext(ctx, "SELECT id, side FROM devices WHERE pair_id = ?", pairID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, side string
		if err := rows.Scan(&id, &side); err != nil {
			return nil, err
		}
		devices[side] = id
	}

	supervisors := map[string][]map[string]any{"A": {}, "B": {}}
	rows, err = s.db.QueryContext(ctx, "SELECT id, side, display_name, status FROM supervisors WHERE pair_id = ?", pairID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, side, displayName, status string
		if err := rows.Scan(&id, &side, &displayName, &status); err != nil {
			return nil, err
		}
		supervisors[side] = append(supervisors[side], map[string]any{
			"id":           id,
			"display_name": displayName,
			"status":       status,
		})
	}

	pending := []map[string]any{}
	rows, err = s.db.QueryContext(ctx, "SELECT id, side, type, status, payload, effective_at FROM pending_events WHERE pair_id = ?", pairID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, side, typ, status, payload string
		var effective string
		if err := rows.Scan(&id, &side, &typ, &status, &payload, &effective); err != nil {
			return nil, err
		}
		pending = append(pending, map[string]any{
			"id":           id,
			"side":         side,
			"type":         typ,
			"status":       status,
			"payload":      json.RawMessage(payload),
			"effective_at": effective,
		})
	}

	return map[string]any{
		"pair_id":        pairID,
		"policy_version": policyVersion,
		"devices":        devices,
		"supervisors":    supervisors,
		"pending_events": pending,
	}, nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, auth authContext) {
	pairID := ""
	if auth.device != nil {
		pairID = auth.device.PairID
	} else if auth.supervisor != nil {
		pairID = auth.supervisor.PairID
	}
	if pairID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown pair"})
		return
	}
	policy, err := s.buildPolicy(r.Context(), pairID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

type postMessageRequest struct {
	PairID        string   `json:"pair_id"`
	To            string   `json:"to"`
	Recipients    []string `json:"recipients"`
	Header        string   `json:"header"`
	Ciphertext    string   `json:"ciphertext"`
	PolicyVersion int      `json:"policy_version"`
}

func (s *Server) handlePostMessage(w http.ResponseWriter, r *http.Request, device deviceRecord) {
	var req postMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if req.PairID != device.PairID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pair mismatch"})
		return
	}
	if req.PolicyVersion == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_version required"})
		return
	}

	policy, err := s.buildPolicy(r.Context(), device.PairID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy fetch failed"})
		return
	}
	currentVersion := policy["policy_version"].(int)
	if req.PolicyVersion != currentVersion {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "POLICY_STALE"})
		return
	}

	recipientSet := map[string]struct{}{}
	for _, id := range req.Recipients {
		id = strings.TrimSpace(id)
		if id != "" {
			recipientSet[id] = struct{}{}
		}
	}
	if _, ok := recipientSet[req.To]; !ok {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "INVALID_RECIPIENTS"})
		return
	}

	devices := policy["devices"].(map[string]string)
	peerSide := "A"
	if device.Side == "A" {
		peerSide = "B"
	}
	peerID := devices[peerSide]
	if peerID == "" || peerID != req.To {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "INVALID_RECIPIENTS"})
		return
	}

	requiredRecipients := []string{peerID}
	supervisors := policy["supervisors"].(map[string][]map[string]any)
	for _, side := range []string{device.Side, peerSide} {
		for _, sup := range supervisors[side] {
			if status, ok := sup["status"].(string); ok && status == "active" {
				if id, ok := sup["id"].(string); ok {
					requiredRecipients = append(requiredRecipients, id)
				}
			}
		}
	}
	for _, reqID := range requiredRecipients {
		if _, ok := recipientSet[reqID]; !ok {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "INVALID_RECIPIENTS"})
			return
		}
	}

	messageID := newID()
	now := time.Now().UTC()
	retention := now.Add(s.spoolTTL)
	for _, side := range []string{device.Side, peerSide} {
		if len(activeSupervisors(supervisors[side])) > 0 {
			candidate := now.Add(s.supervisorWindow)
			if candidate.After(retention) {
				retention = candidate
			}
		}
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx failed"})
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(), "INSERT INTO messages(id, pair_id, from_device_id, header, ciphertext, created_at, retention_until, policy_version) VALUES(?,?,?,?,?,?,?,?)",
		messageID, device.PairID, device.ID, req.Header, req.Ciphertext, now, retention, req.PolicyVersion)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "message insert failed"})
		return
	}

	for id := range recipientSet {
		recipientType := "device"
		side := ""
		if id == devices["A"] {
			side = "A"
		}
		if id == devices["B"] {
			side = "B"
		}
		if id != devices["A"] && id != devices["B"] {
			recipientType = "supervisor"
			if supSide := findSupervisorSide(supervisors, id); supSide != "" {
				side = supSide
			}
		}
		required := 0
		for _, reqID := range requiredRecipients {
			if reqID == id {
				required = 1
				break
			}
		}
		_, err := tx.ExecContext(r.Context(), "INSERT INTO message_recipients(message_id, recipient_id, recipient_type, side, required, ack_state) VALUES(?,?,?,?,?,?)",
			messageID, id, recipientType, side, required, "pending")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "recipients insert failed"})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "commit failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"message_id": messageID, "created_at": now.Format(time.RFC3339)})
}

func activeSupervisors(list []map[string]any) []map[string]any {
	var out []map[string]any
	for _, sup := range list {
		if status, ok := sup["status"].(string); ok && status == "active" {
			out = append(out, sup)
		}
	}
	return out
}

func findSupervisorSide(supervisors map[string][]map[string]any, id string) string {
	for side, list := range supervisors {
		for _, sup := range list {
			if supID, ok := sup["id"].(string); ok && supID == id {
				return side
			}
		}
	}
	return ""
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request, auth authContext) {
	recipientID := ""
	typeLabel := ""
	if auth.device != nil {
		recipientID = auth.device.ID
		typeLabel = "device"
	} else if auth.supervisor != nil {
		recipientID = auth.supervisor.ID
		typeLabel = "supervisor"
	}
	if recipientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `SELECT m.id, m.created_at, m.from_device_id, mr.ack_state
        FROM message_recipients mr
        JOIN messages m ON m.id = mr.message_id
        WHERE mr.recipient_id = ?
        ORDER BY m.created_at DESC LIMIT 50`, recipientID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "inbox fetch failed"})
		return
	}
	defer rows.Close()

	items := []map[string]any{}
	for rows.Next() {
		var id, fromDeviceID, ackState string
		var created string
		if err := rows.Scan(&id, &created, &fromDeviceID, &ackState); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan failed"})
			return
		}
		items = append(items, map[string]any{
			"message_id":  id,
			"from_device": fromDeviceID,
			"created_at":  created,
			"ack_state":   ackState,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"recipient_type": typeLabel, "items": items})
}

func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request, auth authContext) {
	messageID := chi.URLParam(r, "messageID")
	if strings.TrimSpace(messageID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}

	recipientID := ""
	pairID := ""
	if auth.device != nil {
		recipientID = auth.device.ID
		pairID = auth.device.PairID
	} else if auth.supervisor != nil {
		recipientID = auth.supervisor.ID
		pairID = auth.supervisor.PairID
	}

	var messagePairID string
	var ciphertext sql.NullString
	var header string
	var created string
	var purgedAt sql.NullString
	err := s.db.QueryRowContext(r.Context(), `SELECT m.pair_id, m.header, m.ciphertext, m.created_at, m.purged_at
        FROM messages m
        JOIN message_recipients mr ON mr.message_id = m.id
        WHERE m.id = ? AND mr.recipient_id = ?`, messageID, recipientID).Scan(&messagePairID, &header, &ciphertext, &created, &purgedAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	if messagePairID != pairID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "pair mismatch"})
		return
	}
	if purgedAt.Valid || !ciphertext.Valid || ciphertext.String == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "message purged"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message_id": messageID,
		"header":     header,
		"ciphertext": ciphertext.String,
		"created_at": created,
	})
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request, auth authContext) {
	var req struct {
		MessageID string `json:"message_id"`
		State     string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	state := strings.ToLower(strings.TrimSpace(req.State))
	if state == "" {
		state = "delivered"
	}
	if state != "delivered" && state != "read" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid state"})
		return
	}
	recipientID := ""
	if auth.device != nil {
		recipientID = auth.device.ID
	} else if auth.supervisor != nil {
		recipientID = auth.supervisor.ID
	}
	if recipientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}

	res, err := s.db.ExecContext(r.Context(), "UPDATE message_recipients SET ack_state = ?, acked_at = ? WHERE message_id = ? AND recipient_id = ?", state, time.Now().UTC(), req.MessageID, recipientID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ack failed"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acked"})
}

func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request, auth authContext) {
	recipientID := ""
	if auth.device != nil {
		recipientID = auth.device.ID
	} else if auth.supervisor != nil {
		recipientID = auth.supervisor.ID
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT message_id, ack_state, acked_at FROM message_recipients WHERE recipient_id = ? ORDER BY acked_at DESC LIMIT 100`, recipientID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "receipts failed"})
		return
	}
	defer rows.Close()

	items := []map[string]any{}
	for rows.Next() {
		var messageID, state string
		var ackedAt sql.NullString
		if err := rows.Scan(&messageID, &state, &ackedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan failed"})
			return
		}
		item := map[string]any{"message_id": messageID, "state": state}
		if ackedAt.Valid {
			item["acked_at"] = ackedAt.String
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, auth authContext) {
	pairID := ""
	if auth.device != nil {
		pairID = auth.device.PairID
	} else if auth.supervisor != nil {
		pairID = auth.supervisor.PairID
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT actor_type, actor_id, event_type, details, created_at FROM audit_log WHERE pair_id = ? ORDER BY created_at DESC LIMIT 100`, pairID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit failed"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var actorType, actorID, eventType, details string
		var created string
		if err := rows.Scan(&actorType, &actorID, &eventType, &details, &created); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan failed"})
			return
		}
		items = append(items, map[string]any{
			"actor_type": actorType,
			"actor_id":   actorID,
			"event_type": eventType,
			"details":    details,
			"created_at": created,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) startPendingWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.processPendingEvents(ctx); err != nil {
				log.Printf("pending worker error: %v", err)
			}
		}
	}
}

func (s *Server) processPendingEvents(ctx context.Context) error {
	now := time.Now().UTC()
	rows, err := s.db.QueryContext(ctx, "SELECT id, pair_id, side, type, payload FROM pending_events WHERE status = 'pending' AND effective_at <= ?", now)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, pairID, side, typ, payload string
		if err := rows.Scan(&id, &pairID, &side, &typ, &payload); err != nil {
			return err
		}
		if err := s.executePendingEvent(ctx, id, pairID, side, typ, payload); err != nil {
			log.Printf("execute pending %s failed: %v", id, err)
		}
	}
	return nil
}

func (s *Server) executePendingEvent(ctx context.Context, id, pairID, side, typ, payload string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var status string
	err = tx.QueryRowContext(ctx, "SELECT status FROM pending_events WHERE id = ?", id).Scan(&status)
	if err != nil {
		return err
	}
	if status != "pending" {
		return tx.Commit()
	}

	now := time.Now().UTC()
	switch typ {
	case "add":
		var payloadData map[string]any
		_ = json.Unmarshal([]byte(payload), &payloadData)
		supervisorID, _ := payloadData["supervisor_id"].(string)
		if _, err := tx.ExecContext(ctx, "UPDATE supervisors SET status = 'active', updated_at = ? WHERE id = ?", now, supervisorID); err != nil {
			return err
		}
	case "remove":
		var payloadData struct {
			Targets []string `json:"targets"`
		}
		_ = json.Unmarshal([]byte(payload), &payloadData)
		for _, t := range payloadData.Targets {
			if _, err := tx.ExecContext(ctx, "UPDATE supervisors SET status = 'removed', updated_at = ? WHERE id = ?", now, strings.TrimSpace(t)); err != nil {
				return err
			}
		}
	case "reset":
		if _, err := tx.ExecContext(ctx, "UPDATE supervisors SET status = 'removed', updated_at = ? WHERE pair_id = ? AND side = ?", now, pairID, side); err != nil {
			return err
		}
	default:
		return errors.New("unknown pending type")
	}

	if _, err := tx.ExecContext(ctx, "UPDATE pairs SET policy_version = policy_version + 1 WHERE pair_id = ?", pairID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE pending_events SET status = 'executed', effective_at = ? WHERE id = ?", now, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Server) startPurgeWorker(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.purgeExpiredMessages(ctx); err != nil {
				log.Printf("purge worker error: %v", err)
			}
		}
	}
}

func (s *Server) purgeExpiredMessages(ctx context.Context) error {
	now := time.Now().UTC()
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM messages WHERE purged_at IS NULL AND (ciphertext IS NOT NULL AND ciphertext != '') AND retention_until <= ?", now)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, "UPDATE messages SET ciphertext = '', purged_at = ? WHERE id = ?", now, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lrw, r)
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, lrw.status, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
