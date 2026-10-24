package ceskasporitelna

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	obsdk "github.com/slatecrane/obsdk"
	"github.com/slatecrane/obsdk/internal/cbs"
)

const aisBase = aisRoot + "/my/accounts"

// maxAccountPages bounds the account listing, in case a page number never
// advances.
const maxAccountPages = 50

// aisCall performs an account-information GET with the user's token.
func (c *client) aisCall(ctx context.Context, s *obsdk.Session, r req) (*resp, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" {
		return nil, &obsdk.ReauthError{Reason: "no_access_token"}
	}
	if s.AccessExpired(c.now()) {
		return nil, fmt.Errorf("%w (expired %s)", obsdk.ErrAccessExpired, s.AccessExpiresAt.Format(time.RFC3339))
	}
	r.method, r.bearer = http.MethodGet, s.AccessToken
	res, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return nil, c.apiErr(r.op, res)
	}
	return res, nil
}

// accountPath checks an account id (ČS's are 40 hex digits; escaped anyway).
func accountPath(id string) (string, error) {
	if id == "" || len(id) > 120 {
		return "", fmt.Errorf("%w: %q is not a Česká spořitelna account id", obsdk.ErrInvalidRequest, id)
	}
	return aisBase + "/" + url.PathEscape(id), nil
}

// accounts reads every page of the account list. psu is set when the user
// is present.
func (c *client) accounts(ctx context.Context, s *obsdk.Session, psu *obsdk.PSUContext) ([]obsdk.Account, json.RawMessage, error) {
	out := []obsdk.Account{}
	var raws []json.RawMessage
	q := url.Values{}
	for i := 0; i < maxAccountPages; i++ {
		res, err := c.aisCall(ctx, s, req{op: opAccounts, path: aisBase, query: q, psu: psu})
		if err != nil {
			return nil, nil, err
		}
		var b cbs.AccountList
		if err := json.Unmarshal(res.body, &b); err != nil {
			return nil, nil, fmt.Errorf("ceskasporitelna: unreadable account list: %w", err)
		}
		for _, r := range b.Accounts {
			a, err := cbs.ToAccount(r)
			if err != nil {
				return nil, nil, fmt.Errorf("ceskasporitelna: unreadable account: %w", err)
			}
			out = append(out, a)
		}
		raws = append(raws, res.body)
		n, ok := b.Next()
		if !ok {
			break
		}
		q = url.Values{"page": {strconv.Itoa(n)}}
	}
	if len(raws) == 1 {
		return out, raws[0], nil
	}
	raw, _ := json.Marshal(raws)
	return out, raw, nil
}

// Accounts lists the payment accounts the user granted access to.
func (c *client) Accounts(ctx context.Context, s *obsdk.Session, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Account], error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	accs, raw, err := c.accounts(ctx, s, o.PSU)
	if err != nil {
		return nil, err
	}
	return &obsdk.Result[[]obsdk.Account]{Data: accs, Raw: raw}, nil
}

// Balances returns the account's balances: available (CLAV) and, where ČS
// sends it, closing booked (CLBD).
func (c *client) Balances(ctx context.Context, s *obsdk.Session, accountID string, o obsdk.CallOptions) (*obsdk.Result[[]obsdk.Balance], error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	p, err := accountPath(accountID)
	if err != nil {
		return nil, err
	}
	res, err := c.aisCall(ctx, s, req{op: opBalances, path: p + "/balance", psu: o.PSU})
	if err != nil {
		return nil, err
	}
	out, err := cbs.ToBalances(res.body)
	if err != nil {
		return nil, fmt.Errorf("ceskasporitelna: unreadable balances: %w", err)
	}
	return &obsdk.Result[[]obsdk.Balance]{Data: out, Raw: res.body}, nil
}

// Transactions returns a page of the account's history. ČS lists booked
// items (BOOK) and informational ones (INFO, which do not move the balance)
// and has no filter for them.
//
// The cursor is the query of the next request: ČS's next page number plus
// the date filters and page size, which it wants repeated.
func (c *client) Transactions(ctx context.Context, s *obsdk.Session, q obsdk.TxQuery) (*obsdk.TxResult, error) {
	if err := c.checkSession(s); err != nil {
		return nil, err
	}
	p, err := accountPath(q.AccountID)
	if err != nil {
		return nil, err
	}
	query, err := cbs.TxQuery(q, "Česká spořitelna")
	if err != nil {
		return nil, err
	}
	res, err := c.aisCall(ctx, s, req{op: opTransactions, path: p + "/transactions", query: query, psu: q.Options.PSU})
	if err != nil {
		return nil, err
	}
	pg, err := cbs.TxPage(res.body, query, q.Status)
	if err != nil {
		return nil, fmt.Errorf("ceskasporitelna: unreadable transactions: %w", err)
	}
	return &obsdk.TxResult{TxPage: pg}, nil
}
