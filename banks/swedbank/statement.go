package swedbank

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"

	obsdk "github.com/slatecrane/obsdk"
)

const maxStatementFiles = 200

// maxStatementBytes caps the total uncompressed size of a statement archive.
// A variable so tests can lower it.
var maxStatementBytes int64 = 256 << 20

// startStatement begins the extended-history export for an account. Swedbank
// wants a one-off "transactionsOver90Days" consent, then a posted statement
// request, each of which can need user approval. The caller drives it with
// Resume like Connect; everything is the same state machine.
func (c *client) startStatement(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery, to time.Time) (*obsdk.TxResult, error) {
	if q.Options.PSU == nil || q.Options.PSU.IP == "" || q.Options.PSU.UserAgent == "" {
		return nil, fmt.Errorf("%w: transactions older than 90 days need Options.PSU with IP and UserAgent (the user must approve access)", obsdk.ErrInvalidRequest)
	}
	redirectURL := c.cfg.Credentials.RedirectURL
	if redirectURL == "" {
		return nil, fmt.Errorf("%w: redirect URL required for extended history", obsdk.ErrInvalidConfig)
	}
	// The consent needs the account's IBAN/BBAN; the session only knows the resource id.
	res, err := c.aisCall(ctx, s, kindDetailed, req{op: opAccounts, path: c.apiBase() + "/accounts/" + url.PathEscape(q.AccountID)}, q.Options.PSU)
	if err != nil {
		return nil, err
	}
	var one struct {
		Account json.RawMessage `json:"account"`
	}
	raw := json.RawMessage(res.body)
	if json.Unmarshal(res.body, &one) == nil && len(one.Account) > 0 {
		raw = one.Account
	}
	acc, err := toAccount(raw)
	if err != nil || accountRef(acc) == "" {
		return nil, fmt.Errorf("swedbank: cannot identify account %s for the history export", q.AccountID)
	}
	method := s.Meta["approach"]
	if method == "" {
		method = methodRedirect
	}
	f := &flow{
		Goal: goalStatement, Phase: phOver90Start, Method: method, PSU: *q.Options.PSU, RedirectURL: redirectURL,
		ValidityDays: defaultConsentDays, Values: map[string]string{}, Session: s.Clone(),
		Stmt: &stmtFlow{AccountID: q.AccountID, AccountRef: accountRef(acc), From: day(q.From), To: day(to), Status: bookingStatus(q.Status)},
	}
	if m := s.Meta["auth_method"]; m != "" {
		f.Values["auth_method"] = m
	}
	step, err := c.run(ctx, f, obsdk.StepInput{})
	if err != nil {
		return nil, err
	}
	return stepToTxResult(step), nil
}

func stepToTxResult(step *obsdk.Step) *obsdk.TxResult {
	if step.Kind == obsdk.StepDone && step.Transactions != nil {
		return &obsdk.TxResult{TxPage: *step.Transactions}
	}
	return &obsdk.TxResult{Step: step}
}

// statementFromLinks handles a GET that answered with an offline statement (HTTP 210).
func (c *client) statementFromLinks(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery, r *resp) (*obsdk.TxResult, error) {
	var b struct {
		ID    string          `json:"statementId"`
		Links map[string]link `json:"_links"`
	}
	if err := json.Unmarshal(r.body, &b); err != nil || b.Links["download"].Href == "" {
		return nil, fmt.Errorf("swedbank: offline statement response without a download link")
	}
	f := &flow{
		Goal: goalStatement, Phase: phStmtDownload, Method: methodRedirect, Values: map[string]string{}, Session: s.Clone(),
		Stmt: &stmtFlow{AccountID: q.AccountID, ID: b.ID, DownloadPath: b.Links["download"].Href, StatusPath: b.Links["status"].Href},
	}
	if q.Options.PSU != nil {
		f.PSU = *q.Options.PSU
	}
	if _, ok := s.Consents[kindDetailed]; ok {
		f.Values["consent_kind"] = kindDetailed
	}
	step, err := c.run(ctx, f, obsdk.StepInput{})
	if err != nil {
		return nil, err
	}
	return stepToTxResult(step), nil
}

func (f *flow) stmtConsentKind() string {
	if f.Values["consent_kind"] != "" {
		return f.Values["consent_kind"]
	}
	return kindOver90
}

type statementResponse struct {
	ID     string          `json:"statementId"`
	Status string          `json:"statementStatus"`
	Links  map[string]link `json:"_links"`
}

func (c *client) stmtPost(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	st := f.Stmt
	r, err := c.aisCall(ctx, f.Session, kindOver90, req{
		op: opStatement, method: http.MethodPost, path: c.apiBase() + "/accounts/" + url.PathEscape(st.AccountID) + "/transactions",
		query: url.Values{"dateFrom": {st.From}, "dateTo": {st.To}, "bookingStatus": {st.Status}},
		header: map[string]string{
			"TPP-Redirect-Preferred": fmt.Sprint(f.Method == methodRedirect), "TPP-Redirect-URI": f.RedirectURL,
		},
	}, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	var b statementResponse
	if err := json.Unmarshal(r.body, &b); err != nil {
		return nil, false, fmt.Errorf("swedbank: unreadable statement response")
	}
	st.ID, st.StatusPath = b.ID, b.Links["status"].Href
	if r.status == 210 { // signed, or no approval needed
		st.DownloadPath = b.Links["download"].Href
		f.Phase = phStmtDownload
		return nil, true, nil
	}
	st.DownloadPath = c.apiBase() + "/accounts/" + url.PathEscape(st.AccountID) + "/transactions/" + url.PathEscape(st.ID) + "/download"
	sca := &scaFlow{Purpose: "approve access to older transactions", Subject: "the history export", Op: opStatement,
		After: phStmtStatus, ConsentKind: kindOver90}
	sca.scaLinks(b.Links)
	return startSCA(f, sca)
}

func (c *client) stmtStatus(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	path := f.Stmt.StatusPath
	if path == "" {
		path = c.apiBase() + "/accounts/" + url.PathEscape(f.Stmt.AccountID) + "/transactions/" + url.PathEscape(f.Stmt.ID) + "/status"
	}
	r, err := c.aisCall(ctx, f.Session, f.stmtConsentKind(), req{op: opStatement, path: path}, &f.PSU)
	if err != nil {
		return nil, false, err
	}
	var b struct {
		Status string `json:"statementStatus"`
	}
	_ = json.Unmarshal(r.body, &b)
	if b.Status == "signed" {
		f.Phase = phStmtDownload
		return nil, true, nil
	}
	return waitStep(f, false, pollInterval), false, nil
}

func (c *client) stmtDownload(ctx context.Context, f *flow) (*obsdk.Step, bool, error) {
	kind := f.stmtConsentKind()
	if _, ok := f.Session.Consents[kind]; !ok {
		kind = kindOver90
	}
	if f.Session.Consents[kind].ID == "" && kind == kindOver90 {
		return nil, false, &obsdk.ReauthError{Reason: "no_" + kind + "_consent", Consent: kind}
	}
	res, err := c.do(ctx, c.downloadReq(f, kind))
	if err != nil {
		return nil, false, err
	}
	switch res.status {
	case http.StatusOK:
		page, err := parseStatementArchive(res.body)
		if err != nil {
			return nil, false, err
		}
		return &obsdk.Step{Kind: obsdk.StepDone, Transactions: &page}, false, nil
	case http.StatusPreconditionRequired: // 428: still being generated
		f.Message = "The bank is still preparing the statement."
		return waitStep(f, false, statementInterval), false, nil
	}
	return nil, false, c.apiErr(opStatement, res)
}

func (c *client) downloadReq(f *flow, kind string) req {
	h := map[string]string{"Authorization": bearer(f.Session), "Consent-ID": f.Session.Consents[kind].ID}
	psuHeaders(h, &f.PSU)
	return req{op: opStatement, method: http.MethodGet, path: f.Stmt.DownloadPath, header: h, ais: true}
}

// parseStatementArchive unpacks the statement ZIP (one or more JSON files) and
// merges it into one page. A plain JSON body is accepted too.
func parseStatementArchive(data []byte) (obsdk.TxPage, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if json.Valid(data) {
			return parseTransactions(data)
		}
		return obsdk.TxPage{}, fmt.Errorf("swedbank: statement is neither a ZIP archive nor JSON: %w", err)
	}
	if len(zr.File) > maxStatementFiles {
		return obsdk.TxPage{}, fmt.Errorf("swedbank: statement archive has %d files (limit %d)", len(zr.File), maxStatementFiles)
	}
	files := append([]*zip.File(nil), zr.File...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	var merged obsdk.TxPage
	var raws []json.RawMessage
	var total int64
	for _, zf := range files {
		if zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return merged, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxStatementBytes-total+1))
		rc.Close()
		if err != nil {
			return merged, err
		}
		if total += int64(len(b)); total > maxStatementBytes {
			return merged, fmt.Errorf("swedbank: statement archive is larger than %d bytes uncompressed", maxStatementBytes)
		}
		p, err := parseTransactions(b)
		if err != nil {
			return merged, fmt.Errorf("swedbank: %s: %w", zf.Name, err)
		}
		merged.Transactions = append(merged.Transactions, p.Transactions...)
		raws = append(raws, json.RawMessage(b))
	}
	merged.Raw, _ = json.Marshal(raws)
	return merged, nil
}
