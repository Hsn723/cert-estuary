package estserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/gorilla/mux"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DefaultBindAddress = ":4443"
	DefaultCACertPath  = "/etc/ssl/certs/ca-certificates.crt"
	DefaultCertName    = "tls.crt"
	DefaultKeyName     = "tls.key"
	DefaultCertPath    = "/tmp/est-server/serving-certs"
)

type Options struct {
	// Client is the client used to interact with the Kubernetes API.
	// It is used to create and manage the CertificateSigningRequest (CSR) resources.
	// It is required to be set.
	// +kubebuilder:validation:Required
	Client client.Client

	// Scheme is the scheme used to decode the resources.
	// It is required to be set.
	// +kubebuilder:validation:Required
	Scheme *runtime.Scheme

	// BindAddress is the bind address for the server.
	// If empty, the default is ":4443".
	BindAddress string

	// Logger is the logger used for the server.
	Logger logr.Logger

	// CertDir is the directory where the server will look for the TLS certificate and key.
	// If empty, the default is "/etc/opt/cert-estuary/certs".
	CertDir string
	// CertName is the name of the TLS certificate file.
	// If empty, the default is "tls.crt".
	CertName string
	// KeyName is the name of the TLS key file.
	// If empty, the default is "tls.key".
	KeyName string
	// CACertPath is the path to the CA certificate file.
	// If empty, the default is "/etc/ssl/certs/ca-certificates.crt".
	CACertPath string

	// TLSOpts is used  to allow configuring the TLS config used for the server.
	// this also allows providing a certificate via GetCertificate.
	TLSOpts []func(*tls.Config)
}

type Server interface {
	// Start runs the server
	Start(ctx context.Context) error
}

func NewServer(o Options) Server {
	return &ESTServer{
		Options: o,
	}
}

func (o *Options) setDefaults() {
	if o.BindAddress == "" {
		o.BindAddress = DefaultBindAddress
	}
	if o.CACertPath == "" {
		o.CACertPath = DefaultCACertPath
	}
	if o.CertName == "" {
		o.CertName = DefaultCertName
	}
	if o.KeyName == "" {
		o.KeyName = DefaultKeyName
	}
	if o.CertDir == "" {
		o.CertDir = DefaultCertPath
	}
}

// ESTServer is the default implementation used for Server.
type ESTServer struct {
	Options Options

	pool *sync.Pool

	once sync.Once

	mu sync.Mutex
	// started is set to true immediately before the server is started
	// and thus can be used  to check if the server has been started.
	started bool
}

func (s *ESTServer) setupServer() {
	s.Options.setDefaults()

	s.pool = &sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
}

func (s *ESTServer) Start(ctx context.Context) error {
	s.once.Do(s.setupServer)

	s.Options.Logger.Info("starting server", "bindAddress", s.Options.BindAddress)

	// accepts clients without certs, but request them for certificate-based auth later.
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequestClientCert,
	}

	for _, opt := range s.Options.TLSOpts {
		opt(cfg)
	}

	if cfg.GetCertificate == nil {
		certPath := filepath.Join(s.Options.CertDir, s.Options.CertName)
		keyPath := filepath.Join(s.Options.CertDir, s.Options.KeyName)

		certWatcher, err := certwatcher.New(certPath, keyPath)
		if err != nil {
			return err
		}
		cfg.GetCertificate = certWatcher.GetCertificate

		go func() {
			if err := certWatcher.Start(ctx); err != nil {
				s.Options.Logger.Error(err, "failed to start cert watcher")
			}
		}()
	}

	r := mux.NewRouter()
	caCertsHandler := s.setupHandlers(s.handleCACerts, s.setRequestID, s.requestLogger)
	enrollHandler := s.setupHandlers(s.handleSimpleEnroll, s.setRequestID, s.requestLogger, s.authenticateClient)
	reenrollHandler := s.setupHandlers(s.handleSimpleReenroll, s.setRequestID, s.requestLogger, s.authenticateClient)

	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.started {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}).Methods(http.MethodGet)
	r.Handle("/.well-known/est/cacerts", caCertsHandler).Methods(http.MethodGet)
	r.Handle("/.well-known/est/simpleenroll", enrollHandler).Methods(http.MethodPost)
	r.Handle("/.well-known/est/simplereenroll", reenrollHandler).Methods(http.MethodPost)

	server := &http.Server{
		Addr:              s.Options.BindAddress,
		TLSConfig:         cfg,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		<-ctx.Done()
		s.Options.Logger.Info("shutting down server")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			s.Options.Logger.Error(err, "failed to shutdown server")
		}
		close(idleConnsClosed)
	}()

	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		s.Options.Logger.Error(err, "failed to start server")
		return err
	}
	<-idleConnsClosed
	return nil
}
