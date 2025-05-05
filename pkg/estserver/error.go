package estserver

import (
	"errors"
	"net/http"
)

type ESTError struct {
	Error error
	Code  int
}

var (
	UnauthorizedError = ESTError{
		Error: errors.New("UnauthorizedESTClient"),
		Code:  http.StatusUnauthorized,
	}
	NoCertificatesFoundError = ESTError{
		Error: errors.New("NoCertificatesFound"),
		Code:  http.StatusInternalServerError,
	}
	CertificateEncodingError = ESTError{
		Error: errors.New("CertificateEncodingError"),
		Code:  http.StatusInternalServerError,
	}
	CreateCSRFailedError = ESTError{
		Error: errors.New("CreateCSRFailed"),
		Code:  http.StatusInternalServerError,
	}
	CSRMismatchError = ESTError{
		Error: errors.New("CSRMismatch"),
		Code:  http.StatusBadRequest,
	}
	CertificateMismatchError = ESTError{
		Error: errors.New("CertificateMismatch"),
		Code:  http.StatusBadRequest,
	}
	NotReadyError = ESTError{
		Code: http.StatusAccepted,
	}
	NoCertificateToRenewError = ESTError{
		Error: errors.New("NoCertificateToRenew"),
		Code:  http.StatusBadRequest,
	}
)
