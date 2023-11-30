package authn

import (
	"log"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// JwksManager is responsible for caching JWKS instances, mapped by their URL. This is internally implemented based on the keyfunc.JWKS type.
//
// This type is pretty stateful as it caches JWKS instances and creates background goroutines for each keyfunc.JWKS.
//
// Remember to call JwksManager.Close before discarding any JwksManager.
type JwksManager struct {
	// lock is used to synchronize access to the jwks map.
	//
	// TODO: To improve performance, switch to a RWMutex.
	lock sync.Mutex

	// jwks is a map of JWKS instances, mapped by the URL used to fetch them.
	//
	// TODO: Maybe it is a good idea to keep keyfunc.JWKS instances only for a dedicated amount of time.
	// This may depend on the limits of this system. How many jwks instances can be created at a time without performance hits?
	jwks map[string]*keyfunc.JWKS
}

func NewJwksManager() *JwksManager {
	return &JwksManager{
		jwks: map[string]*keyfunc.JWKS{},
	}
}

func (m *JwksManager) GetKeyfuncForJwksURL(url string) (jwt.Keyfunc, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	kf := m.jwks[url]
	if kf != nil {
		return kf.Keyfunc, nil
	}

	kf, err := keyfunc.Get(url, keyfunc.Options{
		RefreshErrorHandler: newKeyfuncErrorHandler(url),
		RefreshInterval:     15 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	m.jwks[url] = kf

	return kf.Keyfunc, nil
}

func (m *JwksManager) Close() {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, jwks := range m.jwks {
		jwks.EndBackground()
	}
}

func newKeyfuncErrorHandler(url string) func(err error) {
	return func(err error) {
		log.Printf("background refresh of JWKS for url '%s' failed: %v", url, err)
	}
}
