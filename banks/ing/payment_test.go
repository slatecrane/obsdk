package ing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	obsdk "github.com/slatecrane/obsdk"
)

func sepaRequest() obsdk.PaymentRequest {
	return obsdk.PaymentRequest{
		Type: obsdk.PaymentSEPA, PSU: obsdk.PSUContext{IP: "198.51.100.7"},
		Transfers: []obsdk.Transfer{{
			Amount:     obsdk.Money{Amount: "1.25", Currency: "EUR"},
			Creditor:   obsdk.Creditor{Name: "John Doe", Account: obsdk.Identifier{Scheme: obsdk.SchemeIBAN, Value: "NL91ABNA0417164300"}},
			Remittance: []string{"Invoice 42"},
		}},
	}
}

func TestBuildInstructionSendsOnlyWhatWasSet(t *testing.T) {
	in, err := buildInstruction(sepaRequest())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(in)
	want := `{"instructedAmount":{"amount":"1.25","currency":"EUR"},"creditorAccount":{"iban":"NL91ABNA0417164300"},"creditorName":"John Doe","remittanceInformationUnstructured":"Invoice 42"}`
	if string(b) != want {
		t.Fatalf("body:\n got %s\nwant %s", b, want)
	}

	r := sepaRequest()
	r.Type, r.ChargeBearer = obsdk.PaymentCrossBorder, obsdk.ChargeBearerShared
	r.Transfers[0].Creditor.Account = obsdk.Identifier{Scheme: obsdk.SchemeBBAN, Value: "123456789"}
	r.Transfers[0].Creditor.Agent = &obsdk.Agent{BIC: "CHASUS33"}
	r.Transfers[0].Creditor.Address = &obsdk.PostalAddress{Street: "Main St", BuildingNumber: "1", Town: "New York", Country: "US"}
	r.Transfers[0].Reference = &obsdk.Reference{Scheme: obsdk.ReferenceRF, Value: "RF18539007547034"}
	in, err = buildInstruction(r)
	if err != nil {
		t.Fatal(err)
	}
	if in.CreditorAccount.BBAN != "123456789" || in.CreditorAgent != "CHASUS33" || in.ChargeBearer != "SHAR" ||
		in.CreditorAddress.TownName != "New York" || in.Structured.Reference != "RF18539007547034" || in.Structured.Type.CodeOrProprietary.Code != "SCOR" {
		t.Fatalf("cross-border: %+v", in)
	}

	r.Transfers[0].Creditor.Address = &obsdk.PostalAddress{Lines: []string{"Main St 1", "New York"}, Country: "US"}
	if _, err := buildInstruction(r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("address lines: want ErrInvalidRequest, got %v", err)
	}

	r = sepaRequest()
	r.Type = obsdk.PaymentSEPAInstant
	if in, _ := buildInstruction(r); in.LocalInstrumentCode != "INST" {
		t.Fatalf("instant: %+v", in)
	}
}

func TestPaymentSpecs(t *testing.T) {
	info, _ := obsdk.Lookup("ing")
	for _, tc := range []struct {
		c    obsdk.Country
		t    obsdk.PaymentType
		want bool
	}{
		{"NL", obsdk.PaymentSEPA, true}, {"NL", obsdk.PaymentSEPAInstant, true}, {"NL", obsdk.PaymentCrossBorder, true},
		{"IT", obsdk.PaymentCrossBorder, false}, {"RO", obsdk.PaymentDomestic, true}, {"RO", obsdk.PaymentSEPAInstant, false},
		{"NL", obsdk.PaymentDomestic, false},
	} {
		if _, ok := info.PaymentSpec(tc.c, obsdk.Personal, tc.t); ok != tc.want {
			t.Errorf("%s %s: offered=%t, want %t", tc.c, tc.t, ok, tc.want)
		}
	}
	spec, _ := info.PaymentSpec("NL", obsdk.Personal, obsdk.PaymentSEPA)
	r := sepaRequest()
	r.Transfers[0].Creditor.Name = "Jöhn Doe" // outside ING's character set
	if err := spec.Validate(r, frozen); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("name pattern: want ErrInvalidRequest, got %v", err)
	}
}

// fakePIS answers payment creation, status and deletion like ING's v2 API.
type fakePIS struct {
	mu      sync.Mutex
	status  string
	created []byte
	deleted bool
}

func (f *fakePIS) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"app","expires_in":900}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/payments/sepa-credit-transfers":
			// Go's server canonicalizes names; check the raw spelling arrived lower case.
			if _, ok := r.Header["X-Jws-Signature"]; !ok || r.Header.Get("Digest") == "" ||
				r.Header.Get("TPP-Redirect-URI") != "https://www.example.com/" || r.Header.Get("PSU-IP-Address") != "198.51.100.7" ||
				r.Header.Get("Authorization") != "Bearer app" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.created, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"transactionStatus":"RCVD","paymentId":"p-1","_links":{"scaRedirect":"https://myaccount.ing.com/payment-initiation/p-1/NL","status":"https://api.ing.com/v2/payments/sepa-credit-transfers/p-1/status"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/payments/sepa-credit-transfers/p-1/status":
			_, _ = w.Write([]byte(`{"transactionStatus":"` + f.status + `","stsRsnInf":[{"rsn":{"cd":"AM04"}}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v2/payments/sepa-credit-transfers/p-1":
			f.deleted, f.status = true, "CANC"
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestPaymentFlow(t *testing.T) {
	for _, tc := range []struct {
		status string
		check  func(*testing.T, *obsdk.Step, error)
	}{
		{"ACSP", func(t *testing.T, st *obsdk.Step, err error) {
			if err != nil || st.Kind != obsdk.StepDone || st.Payment.Status != obsdk.PaymentInProgress || st.Payment.ID != "p-1" {
				t.Fatalf("approved: %+v %v", st, err)
			}
		}},
		{"RCVD", func(t *testing.T, st *obsdk.Step, err error) {
			var fe *obsdk.FlowError
			if !errors.Is(err, obsdk.ErrAuthFailed) || !errors.As(err, &fe) || fe.Payment == nil {
				t.Fatalf("not approved: want ErrAuthFailed with the payment, got %v", err)
			}
		}},
		{"RJCT", func(t *testing.T, st *obsdk.Step, err error) {
			var pe *obsdk.PaymentRejectedError
			if !errors.As(err, &pe) || pe.Reason != "AM04" || pe.Payment.Status != obsdk.PaymentRejected {
				t.Fatalf("rejected: want PaymentRejectedError AM04, got %v", err)
			}
		}},
	} {
		t.Run(tc.status, func(t *testing.T) {
			f := &fakePIS{status: tc.status}
			srv := httptest.NewServer(f.handler(t))
			defer srv.Close()
			c := newTestClient(t, srv, rsaKey(t))
			st, err := c.InitiatePayment(context.Background(), sepaRequest())
			if err != nil {
				t.Fatal(err)
			}
			if st.Kind != obsdk.StepRedirect || !strings.Contains(st.Redirect.URL, "/payment-initiation/p-1/") ||
				st.Payment == nil || st.Payment.Status != obsdk.PaymentReceived {
				t.Fatalf("first step: %+v", st)
			}
			if !strings.Contains(string(f.created), `"creditorName":"John Doe"`) {
				t.Fatalf("created body: %s", f.created)
			}
			done, err := c.Resume(context.Background(), st.State, obsdk.StepInput{Callback: "https://www.example.com/"})
			tc.check(t, done, err)
		})
	}
}

func TestPaymentRequiresPSUIP(t *testing.T) {
	c := newTestClient(t, nil, rsaKey(t))
	r := sepaRequest()
	r.PSU = obsdk.PSUContext{}
	if _, err := c.InitiatePayment(context.Background(), r); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest, got %v", err)
	}
}

func TestCancelAndStatus(t *testing.T) {
	f := &fakePIS{status: "ACCP"}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := newTestClient(t, srv, rsaKey(t))
	pay, err := c.toPayment(&payFlow{Type: obsdk.PaymentSEPA, Product: productSEPA, ID: "p-1"}, "RCVD", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.PaymentStatus(context.Background(), pay.Ref, obsdk.PaymentCallOptions{})
	if err != nil || res.Data.Status != obsdk.PaymentAccepted {
		t.Fatalf("status: %+v %v", res, err)
	}
	st, err := c.CancelPayment(context.Background(), pay.Ref, obsdk.PaymentCallOptions{})
	if err != nil || !f.deleted || st.Kind != obsdk.StepDone || st.Payment.Status != obsdk.PaymentCancelled || !st.Payment.Final {
		t.Fatalf("cancel: %+v %v", st, err)
	}
	if _, err := c.PaymentStatus(context.Background(), "obs1.e30", obsdk.PaymentCallOptions{}); !errors.Is(err, obsdk.ErrInvalidRequest) {
		t.Fatalf("bad ref: %v", err)
	}
}

func TestPaymentStatusCodes(t *testing.T) {
	for code, want := range map[string]obsdk.PaymentStatus{
		"RCVD": obsdk.PaymentReceived, "ACTC": obsdk.PaymentReceived, "ACCP": obsdk.PaymentAccepted, "ACSP": obsdk.PaymentInProgress,
		"PATC": obsdk.PaymentPartiallyAccepted, "ACSC": obsdk.PaymentCompleted, "RJCT": obsdk.PaymentRejected, "CANC": obsdk.PaymentCancelled,
	} {
		if got, _ := paymentStatus(code); got != want {
			t.Errorf("%s: %s, want %s", code, got, want)
		}
	}
}

func TestGatewayErrorShape(t *testing.T) {
	code, text := parseError([]byte(`{"error":{"code":"SignatureError","message":"Invalid JWS Signature.","severity":"error"}}`))
	if code != "SignatureError" || text != "Invalid JWS Signature." {
		t.Fatalf("got %q %q", code, text)
	}
	code, text = parseError([]byte(`{"error":"invalid_grant","error_description":"Refresh token is revoked."}`))
	if code != "invalid_grant" || text != "Refresh token is revoked." {
		t.Fatalf("got %q %q", code, text)
	}
}
