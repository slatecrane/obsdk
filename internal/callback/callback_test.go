package callback

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name, in string
		want     map[string]string
	}{
		{"full url query", "https://app.example/cb?access_code=abc&state=s1", map[string]string{"access_code": "abc", "state": "s1"}},
		{"fragment", "https://app.example/cb#code=xyz&state=s2", map[string]string{"code": "xyz", "state": "s2"}},
		{"bare query", "code=1&state=2", map[string]string{"code": "1", "state": "2"}},
		{"leading question", "?code=1", map[string]string{"code": "1"}},
		{"bare fragment", "#code=9", map[string]string{"code": "9"}},
		{"json", `{"code":"j","state":"s"}`, map[string]string{"code": "j", "state": "s"}},
		{"urlencoded json", "%7B%22code%22%3A%22u%22%2C%22state%22%3A%22t%22%7D", map[string]string{"code": "u", "state": "t"}},
		{"query wins over fragment", "https://x/cb?code=q#code=f", map[string]string{"code": "q"}},
		{"error", "https://x/cb?error=access_denied&error_description=Cancelled+by+user", map[string]string{"error": "access_denied", "error_description": "Cancelled by user"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.in)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
	if _, err := Parse(""); err == nil {
		t.Error("empty callback should fail")
	}
	if _, err := Parse("https://x/cb"); !errors.Is(err, ErrNoParams) {
		t.Errorf("callback without parameters: err = %v, want ErrNoParams", err)
	}
}

func TestError(t *testing.T) {
	p, _ := Parse("https://x/cb?error=access_denied&error_description=nope")
	code, desc, failed := p.Error()
	if !failed || code != "access_denied" || desc != "nope" {
		t.Fatalf("got %q %q %v", code, desc, failed)
	}
}
