package portalauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DEXPRO-Solutions-GmbH/go-dauth/http/portalauth"
	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2/clientcredentials"
)

func TestApi(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Run specs")
}

var _ = Describe("Protecting an API via Portal", Ordered, func() {
	var (
		testServer *httptest.Server
	)

	sendRequest := func(path string, token string) (*http.Response, error) {
		req, err := http.NewRequest("GET", testServer.URL+path, nil)
		if err != nil {
			return nil, err
		}

		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		client := http.DefaultClient
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	BeforeAll(func() {
		engine := gin.New()

		By("Setting up JWKS key function for JWT validadtion")
		kf, err := keyfunc.Get("https://portal.dexpro.de/.well-known/jwks.json", keyfunc.Options{})
		if err != nil {
			panic(err)
		}

		By("Setting up JWT Middleware")
		mw := portalauth.NewMiddleware(kf.Keyfunc)

		engine.GET("/private", mw.GinHandler, func(c *gin.Context) {
			user := portalauth.ContextClaims(c)

			c.JSON(200, gin.H{
				"message":   fmt.Sprintf("Hello, %s, you are related to project %s, right?", user.Subject, user.ProjectID),
				"projectId": user.ProjectID,
			})
		})

		By("Starting test server")
		testServer = httptest.NewServer(engine)
	})

	Describe("an endpoint with auth middleware", func() {
		It("should respond with status 401 and reject request if no auth token is provided", func() {
			response, err := sendRequest("/private", "")
			Expect(err).NotTo(HaveOccurred())
			ExpectStatusCode(response, 401)
		})

		It("should respond with status 401 if token is set but invalid", func() {
			response, err := sendRequest("/private", "something-invalid")
			Expect(err).NotTo(HaveOccurred())
			ExpectStatusCode(response, 401)
		})

		Describe("Using a valid auth token", Ordered, func() {
			var token string

			const projectID = "d6c2c833-72d7-5618-86ce-29f9b38af12a"

			BeforeAll(func() {
				Skip("Skipping because CI is not yet set up with required secrets for this test")
				// TODO: Get secrets via ENV variables and set those up in CI

				By("Fetching a valid auth token")

				token = "valid-token"

				cc := clientcredentials.Config{
					ClientID:     projectID,
					ClientSecret: "",
					TokenURL:     "https://portal.dexpro.de/oauth/token",
				}

				t, err := cc.Token(context.TODO())
				Expect(err).ToNot(HaveOccurred())
				Expect(t.AccessToken).ToNot(BeEmpty())
				token = t.AccessToken
			})

			It("should respond with status 200 if token is valid", func() {
				By("Sending Response")
				response, err := sendRequest("/private", token)
				Expect(err).NotTo(HaveOccurred())
				ExpectStatusCode(response, 200)

				By("Decoding Response")
				var responseBody map[string]any
				err = json.NewDecoder(response.Body).Decode(&responseBody)
				Expect(err).ToNot(HaveOccurred(), "Decoding Response failed")

				By("Inspecting Response")
				Expect(responseBody).To(HaveKey("message"))
				Expect(responseBody).To(HaveKey("projectId"))
				Expect(responseBody["projectId"]).To(Equal(projectID))
			})
		})
	})

	AfterAll(func() {
		testServer.Close()
	})

})

func ExpectStatusCode(response *http.Response, expected int) {
	Expect(response.StatusCode).To(Equal(expected), "Unexpected status code")
}
