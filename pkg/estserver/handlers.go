package estserver

import (
	"context"
	"net/http"
	"os"

	"github.com/justinas/alice"
)

const (
	RequestIDContextKey = "requestID"
	csrContextKey       = "certificateSigningRequest"
	eacContextKey       = "estAuthorizedClient"
)

func (s *ESTServer) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := getRequestID(r)
		s.Options.Logger.Info("request", "method", r.Method, "url", r.URL.String(), "remoteAddr", r.RemoteAddr, "requestID", requestID)
		next.ServeHTTP(w, r)
	})
}

func (s *ESTServer) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := getRequestID(r)
		ctx := context.WithValue(r.Context(), RequestIDContextKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *ESTServer) authenticateClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csr, err := s.decodeCSR(r)
		if err.Error != nil {
			s.Options.Logger.Error(err.Error, "failed to decode CSR", "requestID", getRequestID(r))
			http.Error(w, err.Error.Error(), err.Code)
			return
		}
		eac, err := s.findAuthenticatedClient(r.Context(), csr)
		if err.Error != nil {
			s.Options.Logger.Error(err.Error, "no matching ESTAuthenticatedClient found", "requestID", getRequestID(r))
			http.Error(w, err.Error.Error(), err.Code)
			return
		}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cert := r.TLS.PeerCertificates[0]
			if err := s.authenticateClientCert(*eac, *cert); err != nil {
				s.Options.Logger.Error(err, "failed to authenticate client certificate", "requestID", getRequestID(r))
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		} else {
			// At the moment, only client certificate authentication is supported.
			// At a later time, if we support other authentication methods, we can add them here.
			// For now, we return an error if no client certificate is found.
			s.Options.Logger.Error(nil, "no client certificate found", "requestID", getRequestID(r))
			http.Error(w, "no client certificate found", http.StatusUnauthorized)
			return
		}
		// Store the CSR and ESTAuthorizedClient in the request context.
		ctx := context.WithValue(r.Context(), csrContextKey, csr)
		ctx = context.WithValue(ctx, eacContextKey, eac)
		r = r.WithContext(ctx)
		s.Options.Logger.Info("client authenticated", "requestID", getRequestID(r), "subject", csr.Subject.CommonName)
		next.ServeHTTP(w, r)
	})
}

func (s *ESTServer) setupHandlers(f http.HandlerFunc, handlers ...alice.Constructor) http.Handler {
	chain := alice.New(handlers...)
	return chain.Then(f)
}

func (s *ESTServer) handleCACerts(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(s.Options.CACertPath)
	if err != nil {
		s.Options.Logger.Error(err, "failed to read CA cert", "requestID", getRequestID(r))
		http.Error(w, "failed to read CA cert", http.StatusInternalServerError)
		return
	}
	p7c, estErr := s.encodePKCS7Response(raw)
	if estErr.Error != nil {
		s.Options.Logger.Error(estErr.Error, "failed to encode CA cert", "requestID", getRequestID(r))
		http.Error(w, estErr.Error.Error(), estErr.Code)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime")
	w.WriteHeader(http.StatusOK)
	if _, err = w.Write(p7c); err != nil {
		s.Options.Logger.Error(err, "failed to write PKCS #7 certificate", "requestID", getRequestID(r))
	}
}

func (s *ESTServer) handleSimpleEnroll(w http.ResponseWriter, r *http.Request) {
	csr, eac, err := s.retrieveRequestContext(r)
	if err.Error != nil {
		s.Options.Logger.Error(err.Error, "failed to retrieve request context", "requestID", getRequestID(r))
		http.Error(w, err.Error.Error(), err.Code)
		return
	}
	p7c, err := s.doSimpleEnroll(r.Context(), csr, eac)
	if err.Error != nil {
		s.Options.Logger.Error(err.Error, "failed to enroll certificate", "requestID", getRequestID(r))
		http.Error(w, err.Error.Error(), err.Code)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime")
	if err.Code == http.StatusAccepted {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(err.Code)
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(p7c); err != nil {
		s.Options.Logger.Error(err, "failed to write PKCS #7 certificate", "requestID", getRequestID(r))
	}
}

func (s *ESTServer) handleSimpleReenroll(w http.ResponseWriter, r *http.Request) {
	csr, eac, err := s.retrieveRequestContext(r)
	if err.Error != nil {
		s.Options.Logger.Error(err.Error, "failed to retrieve request context", "requestID", getRequestID(r))
		http.Error(w, err.Error.Error(), err.Code)
		return
	}
	p7c, err := s.doSimpleReenroll(r.Context(), csr, eac)
	if err.Error != nil {
		s.Options.Logger.Error(err.Error, "failed to reenroll certificate", "requestID", getRequestID(r))
		http.Error(w, err.Error.Error(), err.Code)
		return
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime")
	if err.Code == http.StatusAccepted {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(err.Code)
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(p7c); err != nil {
		s.Options.Logger.Error(err, "failed to write PKCS #7 certificate", "requestID", getRequestID(r))
	}
}
