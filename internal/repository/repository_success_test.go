package repository

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleRequestCert_Success(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Mock script
	fakeCliPathSh := filepath.Join(tmpDir, "fake_micropki.sh")
	os.WriteFile(fakeCliPathSh, []byte(`#!/bin/sh
while [ "$#" -gt 0 ]; do
    case $1 in
        --out-dir) OUTDIR="$2"; shift ;;
    esac
    shift
done
echo "FAKE_CERT" > "$OUTDIR/repo_test.cert.pem"
`), 0755)

	fakeCliPathBat := filepath.Join(tmpDir, "fake_micropki.bat")
	os.WriteFile(fakeCliPathBat, []byte(`@echo off
set OUTDIR=
:loop
if "%1"=="" goto end
if "%1"=="--out-dir" (
  set OUTDIR=%~2
)
shift
goto loop
:end
echo FAKE_CERT > "%OUTDIR%\repo_test.cert.pem"
`), 0755)

	cliPathToUse := fakeCliPathSh
	if os.PathSeparator == '\\' {
		cliPathToUse = fakeCliPathBat
	}

	srv := &Server{
		CLIPath: cliPathToUse,
	}
	
	csrJSON := `{"csr":"fake csr data"}`
	req := httptest.NewRequest("POST", "/request-cert?template=server", strings.NewReader(csrJSON))
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	srv.handleRequestCert(w, req)
	
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201 Created, got %d", w.Code)
	}
}
