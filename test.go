package test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

var (
	meethueOauthConfig  *oauth2.Config
	codeChallengeMethod oauth2.AuthCodeOption
	codeChallenge       oauth2.AuthCodeOption
	codeVerifierAttr    oauth2.AuthCodeOption
	oauthStateString    = "12345"
)

func init() {
	codeVerifier, _ := createCodeVerifier()
	verifierCode := codeVerifier.codeChallengeS256()
	codeChallengeMethod = oauth2.SetAuthURLParam("code_challenge_method", "S256")
	fmt.Println("challenge ", verifierCode)
	fmt.Println("verifier ", codeVerifier.Value)
	codeChallenge = oauth2.SetAuthURLParam("code_challenge", verifierCode)
	codeVerifierAttr = oauth2.SetAuthURLParam("code_verifier", codeVerifier.Value)

	meethueOauthConfig = &oauth2.Config{
		RedirectURL:  "callback-url-here",
		ClientID:     "client-id-here",
		ClientSecret: "client-secret-here",
		Endpoint:     oauth2.Endpoint{
			AuthURL: "https://<<your_domain_url>>/authorize",
			TokenURL: "https://<your_domain_url>>/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleMeethueLogin)
	http.HandleFunc("/callback", handleMeethueCallback)
	fmt.Println(http.ListenAndServe(":8080", nil))
}

//Navigate to localhost:8080/login
func handleMain(w http.ResponseWriter, r *http.Request) {
	var htmlIndex = `<html>
<body>
	<a href="/login"> get your authorization page</a>
</body>
</html>`

	fmt.Fprintf(w, htmlIndex)
}

func handleMeethueLogin(w http.ResponseWriter, r *http.Request) {
	url := meethueOauthConfig.AuthCodeURL(oauthStateString, codeChallengeMethod, codeChallenge)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleMeethueCallback(w http.ResponseWriter, r *http.Request) {
	content, err := getToken(r.FormValue("state"), r.FormValue("code"))
	if err != nil {
		fmt.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	fmt.Fprintf(w, "Content: %s\n", content)
	fmt.Println("Content: %s\n", content)
}

func getToken(state string, code string) (oauth2.Token, error) {
	if state != oauthStateString {
		return oauth2.Token{}, fmt.Errorf("invalid oauth state")
	}

	token, err := meethueOauthConfig.Exchange(oauth2.NoContext, code, codeVerifierAttr)
	// token, err := meethueOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	return *token, nil
}

//Code verifier
//change values for testing
const (
	DefaultLength = 43
	MinLength     = 43
	MaxLength     = 128
)

//CodeVerifier bla
type CodeVerifier struct {
	Value string
}

func createCodeVerifier() (*CodeVerifier, error) {
	return createCodeVerifierWithLength(DefaultLength)
}

func createCodeVerifierWithLength(length int) (*CodeVerifier, error) {
	if length < MinLength || length > MaxLength {
		return nil, fmt.Errorf("invalid length: %v", length)
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length, length)
	for i := 0; i < length; i++ {
		b[i] = byte(r.Intn(255))
	}
	return createCodeVerifierFromBytes(b)
}

func createCodeVerifierFromBytes(b []byte) (*CodeVerifier, error) {
	return &CodeVerifier{
		Value: encode(b),
	}, nil
}

func (v *CodeVerifier) String() string {
	return v.Value
}

func (v *CodeVerifier) codeChallengePlain() string {
	return v.Value
}

func (v *CodeVerifier) codeChallengeS256() string {
	h := sha256.New()
	h.Write([]byte(v.Value))
	return encode(h.Sum(nil))
}

func encode(msg []byte) string {
	encoded := base64.StdEncoding.EncodeToString(msg)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}
