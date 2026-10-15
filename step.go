package obsdk

import (
	"encoding/json"
	"time"
)

// StepKind says what the caller has to do next.
type StepKind string

const (
	// StepRedirect: send the user's browser to Redirect.URL. When they come
	// back, call Resume with StepInput.Callback set to the full callback URL
	// (or just its query/fragment). Fragments never reach servers, so a
	// frontend may need to forward them.
	StepRedirect StepKind = "redirect"
	// StepInputRequired: ask the user for Fields and call Resume with StepInput.Values.
	StepInputRequired StepKind = "input"
	// StepDisplay: show Challenge/Message to the user (e.g. an app-confirmation
	// code) and call Resume after the user acted. Use Wait for decoupled polling.
	StepDisplay StepKind = "display"
	// StepWait: nothing for the user to type. Show Challenge/Message if
	// present, wait at least WaitFor, then call Resume with an empty input.
	StepWait StepKind = "wait"
	// StepDone: the operation finished; read Session / Accounts / Transactions / Payment.
	StepDone StepKind = "done"
)

// Step is one stop in a resumable operation. It is plain data and safe to
// send to a frontend as JSON. State is opaque: pass it back to Resume unchanged.
// State may contain tokens, so treat it like a Session.
type Step struct {
	Kind StepKind `json:"kind"`

	// State resumes the operation. Empty on StepDone.
	State string `json:"state,omitempty"`

	// NeedsUser is true when a person must act (redirect, input, app approval).
	NeedsUser bool `json:"needs_user"`

	Message   string        `json:"message,omitempty"`
	Redirect  *Redirect     `json:"redirect,omitempty"`
	Fields    []Field       `json:"fields,omitempty"`
	Challenge *Challenge    `json:"challenge,omitempty"`
	WaitFor   time.Duration `json:"wait_for,omitempty"`

	// Session is set on every step once the operation has one (after login,
	// or the session a transaction export started from). Persist it whenever
	// it is non-nil, not only on StepDone: a flow that fails later still
	// leaves a usable session behind.
	Session *Session `json:"session,omitempty"`

	// Set on StepDone.
	Accounts     []Account       `json:"accounts,omitempty"`     // accounts discovered during Connect; some banks expose them only once
	Transactions *TxPage         `json:"transactions,omitempty"` // for transaction exports that needed user approval
	Payment      *Payment        `json:"payment,omitempty"`      // payments: set once the bank created the payment, on every step after that
	Raw          json.RawMessage `json:"raw,omitempty"`
}

// StepInput feeds Resume.
type StepInput struct {
	Callback string            // raw redirect callback: URL, query string, fragment, JSON or urlencoded JSON
	Values   map[string]string // answers to Step.Fields, by Field.Key
}

// Redirect tells the caller where to send the user.
type Redirect struct {
	URL string `json:"url"`
}

// Challenge is what the user must see for app-based approval.
type Challenge struct {
	Code           string `json:"code,omitempty"`             // e.g. a 4-digit code shown in the bank app
	AutoStartToken string `json:"auto_start_token,omitempty"` // to launch a same-device bank app
	ImageURL       string `json:"image_url,omitempty"`        // QR image; may need bank credentials to fetch
	Text           string `json:"text,omitempty"`
}

// FieldKind describes how to render an input.
type FieldKind string

const (
	FieldText   FieldKind = "text"
	FieldSecret FieldKind = "secret"
	FieldOTP    FieldKind = "otp"
	FieldSelect FieldKind = "select"
)

// Field is one requested input. Keys are stable across banks where the
// meaning is the same (auth_method, personal_id, phone_number, psu_id, otp, bank_id).
type Field struct {
	Key      string    `json:"key"`
	Label    string    `json:"label"`
	Kind     FieldKind `json:"kind"`
	Required bool      `json:"required"`
	Pattern  string    `json:"pattern,omitempty"` // regexp the value should match, when the bank publishes one
	Options  []Option  `json:"options,omitempty"`
}

// Option is a choice for FieldSelect.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}
