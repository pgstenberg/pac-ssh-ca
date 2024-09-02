package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"net/http/httptest"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func TestGeneratePageTestContent(t *testing.T) {

	expectedSshCmd := "helloworld"
	defaultIdentityFilePath := "~/.ssh/id_rsa"

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		generatePage(rw, expectedSshCmd, defaultIdentityFilePath)
	}))
	defer server.Close()
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	var sshCmd string
	var toBeCopied string
	var idFilePath string

	if err := chromedp.Run(ctx,
		chromedp.Navigate(server.URL),
		chromedp.Value("#ssh-cmd", &sshCmd),
		chromedp.Value("#identity-file-path", &idFilePath),
		chromedp.Text("#copy-target", &toBeCopied),
	); err != nil {
		t.Fatalf("error=%s", err)
	}

	t.Logf("sshCmd=%s", sshCmd)
	t.Logf("toBeCopied=%s", toBeCopied)
	t.Logf("idFilePath=%s", idFilePath)

	if expectedSshCmd != sshCmd {
		t.Fatalf("%s!=%s", expectedSshCmd, sshCmd)
	}
	if defaultIdentityFilePath != idFilePath {
		t.Fatalf("%s!=%s", defaultIdentityFilePath, idFilePath)
	}

	if toBeCopied != fmt.Sprintf("%s > %s-cert.pub", sshCmd, idFilePath) {
		t.Fatalf("%s!=%s", expectedSshCmd, sshCmd)
	}

}

func TestGeneratePageTestClickCopyToClipboard(t *testing.T) {

	command := "foobar"

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		generatePage(rw, command, "~/.ssh/id_rsa")
	}))
	defer server.Close()
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Make sure to timeout after 5 seconds
	ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	clipboardPermission := browser.PermissionDescriptor{Name: "clipboard-read"}

	var clipboardContent string
	var copyTarget string
	if err := chromedp.Run(ctx,
		browser.SetPermission(&clipboardPermission, browser.PermissionSettingGranted).WithOrigin(server.URL),
		chromedp.Navigate(server.URL),
		chromedp.Text("#copy-target", &copyTarget),
		chromedp.Click("#copy-to-clipboard", chromedp.ByID),
		chromedp.Evaluate(`window.navigator.clipboard.readText()`, &clipboardContent, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithAwaitPromise(true)
		}),
	); err != nil {
		t.Fatalf("error=%s", err)
	}

	t.Logf("clipboardContent=%s", clipboardContent)
	t.Logf("copyTarget=%s", copyTarget)

	if copyTarget != clipboardContent {
		t.Fatalf("%s!=%s", copyTarget, clipboardContent)
	}

}

func TestPersistIdentityFilePathWithCookie(t *testing.T) {

	customIdentityFilePath := "~/.ssh/custom_id_rsa"

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		generatePage(rw, "foobar", "~/.ssh/id_rsa")
	}))
	defer server.Close()
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	var cookieValue string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(server.URL),
		chromedp.SetValue("#identity-file-path", customIdentityFilePath),
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := network.GetCookies().Do(ctx)
			if err != nil {
				return err
			}
			for _, cookie := range cookies {
				if cookie.Name == "_id_file_path" {
					cookieValue = cookie.Value
				}
			}
			return nil
		}),
	); err != nil {
		t.Fatalf("error=%s", err)
	}

	t.Logf("cookieValue=%s", cookieValue)

	if cookieValue != customIdentityFilePath {
		t.Fatalf("%s!=%s", cookieValue, customIdentityFilePath)
	}

}
