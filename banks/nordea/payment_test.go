package nordea

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

func newCountryClient(t *testing.T, srv *httptest.Server, country obsdk.Country) *client {
	t.Helper()
	cfg := obsdk.Config{
		Env:         obsdk.Sandbox,
		Credentials: obsdk.Credentials{ClientID: "cid", ClientSecret: "secret", RedirectURL: "https://example.com"},
		Seal:        &obsdk.Seal{Key: rsaKey(t)},
		Now:         func() time.Time { return frozen },
		NewID:       func(p string) string { return p + "-1" },
		Extra:       map[string]string{},
	}
	if srv != nil {
		cfg.HTTPClient, cfg.Extra[paramBaseURL] = srv.Client(), srv.URL
	}
	c, err := obsdk.New(obsdk.Target{Bank: "nordea", Country: country}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*client)
}

func payRequest(t obsdk.PaymentType, ccy, from string, to obsdk.Identifier) obsdk.PaymentRequest {
	return obsdk.PaymentRequest{Type: t,
		Debtor:    &obsdk.PaymentDebtor{Account: &obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: from}},
		Transfers: []obsdk.Transfer{{Amount: obsdk.Money{Amount: "12.24", Currency: ccy}, Creditor: obsdk.Creditor{Name: "Payee", Account: to}}}}
}

func TestBuildPayment(t *testing.T) {
	se := newCountryClient(t, nil, "SE")
	r := payRequest(obsdk.PaymentDomestic, "SEK", "SE8030000000041351300039", obsdk.Identifier{Scheme: obsdk.SchemeBankgiro, Value: "330-0308"})
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceOCR, Value: "1831653108"}
	p, err := se.buildPayment(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	want := `{"amount":"12.24","currency":"SEK","creditor":{"account":{"value":"3300308","type":"BGNR"},"reference":{"value":"1831653108","type":"OCR"}},"debtor":{"account":{"value":"SE8030000000041351300039","type":"IBAN","currency":"SEK"}},"external_id":"request-1"}`
	if string(b) != want {
		t.Fatalf("bankgiro body:\n got %s\nwant %s", b, want)
	}

	no := newCountryClient(t, nil, "NO")
	r = payRequest(obsdk.PaymentDomestic, "NOK", "NO2860010503178", obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "60301132843"})
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: SchemeKID, Value: "1234567890003"}
	if p, _ = no.buildPayment(r); p.Creditor.Account.Type != "BBAN_NO" || p.Creditor.Reference.Type != "OCR" || p.Creditor.Name != "Payee" {
		t.Fatalf("KID: %+v", p)
	}

	fi := newCountryClient(t, nil, "FI")
	r = payRequest(obsdk.PaymentSEPAInstant, "EUR", "FI7473834510057469", obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI1450000120236228"})
	r.Transfers[0].Remittance = []string{"Invoice"}
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}
	if _, err := fi.buildPayment(r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("message and reference together: want ErrInvalidRequest, got %v", err)
	}
	r.Transfers[0].Reference = nil
	if p, _ = fi.buildPayment(r); p.Urgency != "express" {
		t.Fatalf("instant: %+v", p)
	}
}

func TestPaymentSpecs(t *testing.T) {
	info, _ := obsdk.Lookup("nordea")
	for _, tc := range []struct {
		c    obsdk.Country
		seg  obsdk.Segment
		t    obsdk.PaymentType
		want bool
	}{
		{"FI", obsdk.Personal, obsdk.PaymentSEPA, true}, {"FI", obsdk.Personal, obsdk.PaymentSEPAInstant, true},
		{"SE", obsdk.Personal, obsdk.PaymentDomestic, true}, {"SE", obsdk.Personal, obsdk.PaymentSEPA, false},
		{"FI", obsdk.Business, obsdk.PaymentSEPA, false}, {"NO", obsdk.Personal, obsdk.PaymentCrossBorder, false},
	} {
		if _, ok := info.PaymentSpec(tc.c, tc.seg, tc.t); ok != tc.want {
			t.Errorf("%s %s %s: offered=%t, want %t", tc.c, tc.seg, tc.t, ok, tc.want)
		}
	}
	spec, _ := info.PaymentSpec("SE", obsdk.Personal, obsdk.PaymentDomestic)
	r := payRequest(obsdk.PaymentDomestic, "SEK", "SE8030000000041351300039", obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "SE2730000000032704620016"})
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceOCR, Value: "1831653108"}
	if err := spec.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("OCR to an account payee: want ErrInvalidRequest, got %v", err)
	}
	r.Debtor = nil
	r.Transfers[0].Reference = nil
	if err := spec.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("missing debtor: want ErrInvalidRequest, got %v", err)
	}
}

func TestPaymentStatusCodes(t *testing.T) {
	for code, want := range map[string]obsdk.PaymentStatus{
		"PendingUserApproval": obsdk.PaymentReceived, "UserApprovalCancelled": obsdk.PaymentReceived, "Confirmed": obsdk.PaymentAccepted,
		"OnHold": obsdk.PaymentInProgress, "Paid": obsdk.PaymentCompleted, "InsufficientFunds": obsdk.PaymentRejected,
		"Deleted": obsdk.PaymentCancelled, "PendingSecondConfirmation": obsdk.PaymentPartiallyAccepted,
	} {
		if got, _ := paymentStatus(code); got != want {
			t.Errorf("%s: %s, want %s", code, got, want)
		}
	}
}

// TestPaymentFlow runs create, sign callback and status against a fake Nordea.
func TestPaymentFlow(t *testing.T) {
	for _, tc := range []struct {
		name, callback, status string
		check                  func(*testing.T, *obsdk.Step, error)
	}{
		{"paid", "https://example.com?success=true&state=state-1&auth_code=ac&response_code=rc", "Paid", func(t *testing.T, st *obsdk.Step, err error) {
			if err != nil || st.Kind != obsdk.StepDone || st.Payment.Status != obsdk.PaymentCompleted || st.Session == nil || st.Session.AccessToken != "pay-at" {
				t.Fatalf("paid: %+v %v", st, err)
			}
		}},
		{"cancelled by user", "https://example.com?success=false&state=state-1", "UserApprovalCancelled", func(t *testing.T, st *obsdk.Step, err error) {
			var fe *obsdk.FlowError
			if !errors.Is(err, obsdk.ErrAuthFailed) || !errors.As(err, &fe) || fe.Payment == nil {
				t.Fatalf("want ErrAuthFailed with the payment, got %v", err)
			}
		}},
		{"rejected", "https://example.com?success=true&state=state-1", "InsufficientFunds", func(t *testing.T, st *obsdk.Step, err error) {
			if !errors.Is(err, obsdk.ErrPaymentRejected) {
				t.Fatalf("want ErrPaymentRejected, got %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var created map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/personal/v4/payments/authorization/sepa-credit-transfer":
					_ = json.Unmarshal(body, &created)
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"response":{"_links":[{"rel":"redirect","href":"https://sign.nordea.example/?x=1"},
						{"rel":"status","href":"/v4/single-sca-payments/p-1/status"}]}}`))
				case r.URL.Path == "/personal/v4/single-sca-payments/p-1/status":
					_, _ = w.Write([]byte(`{"response":{"payment_id":"p-1","status":"` + tc.status + `"}}`))
				case r.URL.Path == "/personal/v5/authorize/token":
					_, _ = w.Write([]byte(`{"access_token":"pay-at","expires_in":3599,"refresh_token":"pay-rt"}`))
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			c := newCountryClient(t, srv, "FI")
			r := payRequest(obsdk.PaymentSEPA, "EUR", "FI7473834510057469", obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "FI1450000120236228"})
			st, err := c.InitiatePayment(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if st.Redirect.URL != "https://sign.nordea.example/?x=1" || st.Payment.ID != "p-1" || st.Payment.Status != obsdk.PaymentReceived {
				t.Fatalf("first step: %+v", st)
			}
			auth, _ := created["authentication"].(map[string]any)
			if auth["state"] != "state-1" || auth["redirect_uri"] != "https://example.com" {
				t.Fatalf("authentication block: %v", created)
			}
			done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: tc.callback})
			tc.check(t, done, err)
		})
	}
}

func TestCancelNeedsPaymentSession(t *testing.T) {
	c := newCountryClient(t, nil, "FI")
	pay, _ := c.toPayment("p-1", obsdk.PaymentSEPA, "Confirmed", "", nil)
	if _, err := c.CancelPayment(context.Background(), pay.Ref, obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) ||
		!strings.Contains(err.Error(), "Session") {
		t.Fatalf("want ErrInvalidRequest naming the session, got %v", err)
	}
}
