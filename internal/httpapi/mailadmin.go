package httpapi

import (
	"encoding/json"
	"net/http"

	"go.londer.be/cardinal/internal/mail"
	"go.londer.be/cardinal/internal/store"
)

// Configuring notification email from the console.
//
// The same settings the CLI edits, because they live in the database rather than
// the configuration file — a deployment running the published image cannot edit
// files inside it, and changing a relay should not mean rebuilding a container.
//
// The relay password is write-only here. It goes in and is never read back: a
// settings page that could show it is a settings page that hands it to whoever
// is behind the reader, and there is no question answered by displaying it that
// "set" does not answer.

type mailSettingsBody struct {
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"fromAddress"`
	FromName    string `json:"fromName"`
	ReplyTo     string `json:"replyTo"`
	TLSMode     string `json:"tlsMode"`
}

func (s *Server) handleGetMailSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	settings, err := s.store.MailSettings(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "reading mail settings failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the mail settings")
		return
	}
	pending, failing, err := s.store.PendingMail(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "counting queued mail failed", "error", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     settings.Enabled,
		"host":        settings.Host,
		"port":        settings.Port,
		"username":    settings.Username,
		"fromAddress": settings.FromAddress,
		"fromName":    settings.FromName,
		"replyTo":     settings.ReplyTo,
		"tlsMode":     settings.TLSMode,

		// Whether, never what.
		"passwordSet": settings.Username != "",

		// So the page can say "twelve waiting, four failing" rather than
		// leaving somebody to discover from a colleague that nothing arrived.
		"queued":  pending,
		"failing": failing,
	})
}

func (s *Server) handleSaveMailSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var body mailSettingsBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	switch body.TLSMode {
	case "starttls", "tls", "none":
	default:
		writeError(w, http.StatusBadRequest, "tlsMode must be starttls, tls or none")
		return
	}
	if body.Port <= 0 || body.Port > 65535 {
		writeError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}

	actorID := session.SubjectID
	err := s.store.SaveMailSettings(ctx, store.MailSettings{
		Enabled:     body.Enabled,
		Host:        body.Host,
		Port:        body.Port,
		Username:    body.Username,
		Password:    body.Password, // empty leaves the stored one alone
		FromAddress: body.FromAddress,
		FromName:    body.FromName,
		ReplyTo:     body.ReplyTo,
		TLSMode:     body.TLSMode,
	}, s.cfg.Mail.EncryptionKey, &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "saving mail settings failed", "error", err)
		writeError(w, http.StatusInternalServerError,
			"could not save the mail settings — if a password was given, "+
				"mail.encryption_key may not be set")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleSendTestMail sends one and reports what the relay said.
//
// Directly rather than through the outbox, because the point is the answer. A
// test that queued would say "queued" and leave somebody reading a log.
func (s *Server) handleSendTestMail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil || body.To == "" {
		writeError(w, http.StatusBadRequest, "an address to send to is required")
		return
	}

	settings, err := s.store.MailSettingsWithPassword(ctx, s.cfg.Mail.EncryptionKey)
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"could not read the settings — mail.encryption_key may not be set")
		return
	}
	if settings.Host == "" {
		writeError(w, http.StatusBadRequest, "no relay host is configured")
		return
	}

	subject, rendered, err := mail.Render(mail.KindTest, nil, mail.Data{
		Product:    s.cfg.WebAuthn.RPDisplayName,
		Login:      "(test)",
		ConsoleURL: s.cfg.Server.PublicURL,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not render the test message")
		return
	}

	sendErr := mail.Send(ctx, mail.Relay{
		Host: settings.Host, Port: settings.Port,
		Username: settings.Username, Password: settings.Password,
		FromAddress: settings.FromAddress, FromName: settings.FromName,
		ReplyTo: settings.ReplyTo, TLSMode: settings.TLSMode,
	}, mail.Message{To: body.To, Subject: subject, Body: rendered})
	if sendErr != nil {
		// The relay's own words, passed through. "550 user unknown" and
		// "certificate signed by unknown authority" want completely different
		// responses, and a page that says "sending failed" makes somebody go to
		// a terminal to find out which.
		writeJSON(w, http.StatusOK, map[string]any{
			"sent": false, "error": sendErr.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// handleListMailTemplates returns every message, built-in and overridden.
func (s *Server) handleListMailTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	overrides, err := s.store.MailTemplates(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the templates")
		return
	}

	type templateBody struct {
		Kind        string `json:"kind"`
		Subject     string `json:"subject"`
		Body        string `json:"body"`
		Overridden  bool   `json:"overridden"`
		BuiltInSub  string `json:"builtInSubject"`
		BuiltInBody string `json:"builtInBody"`
	}

	out := make([]templateBody, 0, len(mail.Kinds()))
	for _, kind := range mail.Kinds() {
		builtin, _ := mail.Builtin(kind)
		item := templateBody{
			Kind:    string(kind),
			Subject: builtin.Subject, Body: builtin.Body,
			BuiltInSub: builtin.Subject, BuiltInBody: builtin.Body,
		}
		if o, ok := overrides[string(kind)]; ok {
			item.Subject, item.Body, item.Overridden = o.Subject, o.Body, true
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": out})
}

func (s *Server) handleSaveMailTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)
	kind := r.PathValue("kind")

	if _, ok := mail.Builtin(mail.Kind(kind)); !ok {
		writeError(w, http.StatusNotFound, "no such message")
		return
	}

	var body struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	// Rendered before it is stored, so a template that will not compile is
	// refused here rather than silently dropping every message it would have
	// produced. The notifier logs and drops a broken one, which is the right
	// behaviour at send time and a terrible way to find out.
	if _, _, err := mail.Render(mail.Kind(kind),
		&mail.Template{Subject: body.Subject, Body: body.Body},
		mail.Data{
			Login: "example", When: "now", ConsoleURL: s.cfg.Server.PublicURL,
			URL: s.cfg.Server.PublicURL + "/enroll?token=example",
		}); err != nil {
		writeError(w, http.StatusBadRequest, "that template does not render: "+err.Error())
		return
	}

	actorID := session.SubjectID
	if err := s.store.SaveMailTemplate(ctx, store.MailTemplate{
		Kind: kind, Subject: body.Subject, Body: body.Body,
	}, &actorID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the template")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResetMailTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.store.ResetMailTemplate(ctx, r.PathValue("kind")); err != nil {
		writeError(w, http.StatusInternalServerError, "could not reset the template")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
