package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/dimfeld/glog"
	"github.com/dimfeld/httptreemux"
)

type HookHandler func(http.ResponseWriter, *http.Request, map[string]string, *Hook)

func hookHandler(w http.ResponseWriter, r *http.Request, params map[string]string, hook *Hook) {
	githubEventType := r.Header.Get("X-GitHub-Event")

	// we also try to fetch GitLab events
	if githubEventType == "" {
		githubEventType = r.Header.Get("X-Gitlab-Event")
	}

	if r.ContentLength > 16384 {
		// We should never get a request this large.
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	buffer := bytes.Buffer{}
	buffer.ReadFrom(r.Body)
	r.Body.Close()

	if glog.V(2) {
		niceBuffer := &bytes.Buffer{}
		json.Indent(niceBuffer, buffer.Bytes(), "", "  ")
		glog.Infof("Hook %s received data %s\n",
			r.URL.Path, string(niceBuffer.Bytes()))
	}

	if hook.Secret != "" {
		// GitHub
		if r.Header.Get("X-Hub-Signature") != "" {
			secret := r.Header.Get("X-Hub-Signature")
			if !strings.HasPrefix(secret, "sha1=") {
				glog.Warningf("Request with no valid secret for hook %s from %s\n",
					r.URL.Path, r.RemoteAddr)
				w.WriteHeader(http.StatusForbidden)
				return
			}

			hash := hmac.New(sha1.New, []byte(hook.Secret))
			hash.Write(buffer.Bytes())
			expected := hash.Sum(nil)
			seen, err := hex.DecodeString(secret[5:])
			if err != nil || !hmac.Equal(expected, seen) {
				glog.Warningf("Request with bad secret for hook %s from %s\nExpected %s, saw %s",
					r.URL.Path, r.RemoteAddr, hex.EncodeToString(expected), secret)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			// GitLab
		} else if r.Header.Get("X-Gitlab-Token") != "" {
			secret := r.Header.Get("X-Gitlab-Token")
			if secret != hook.Secret {
				glog.Warningf("Request with bad secret for hook %s from %s [%s]",
					r.URL.Path, r.RemoteAddr, secret)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		} else {
			glog.Warningf("Request with no secret for hook %s from %s\n",
				r.URL.Path, r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			return
		}

	}

	event, err := NewEvent(buffer.Bytes(), githubEventType)
	if err != nil {
		glog.Errorf("Error parinsg JSON for %s: %s", r.URL.Path, err)
		return
	}
	event["urlparams"] = params
	go hook.Execute(event)
}

func handlerWrapper(handler HookHandler, hook *Hook) httptreemux.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		glog.Infoln("Called", r.URL.Path)
		handler(w, r, params, hook)
	}
}

func SetupServer(config *Config) (net.Listener, http.Handler) {
	var listener net.Listener = nil

	cer, err := tls.LoadX509KeyPair(config.TlsCertificate, config.TlsKey)
	if err != nil {
		glog.Fatalf("Could not load certificates [%s,%s]\n", config.TlsCertificate, config.TlsKey)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}
	listener, err = tls.Listen("tcp", config.ListenAddress, tlsConfig)
	if err != nil {
		glog.Fatalf("Could not listen on %s: %s\n", config.ListenAddress, err)
	}

	if len(config.AcceptIps) != 0 {
		listenFilter := NewListenFilter(listener, WhiteList)
		for _, a := range config.AcceptIps {
			glog.Infoln("Adding IP filter", a)
			listenFilter.AddString(a)
		}
		listener = listenFilter
	}

	router := httptreemux.New()

	for _, hook := range config.Hook {
		router.POST(hook.Url, handlerWrapper(hookHandler, hook))
	}

	return listener, router
}

func RunServer(config *Config) {
	listener, router := SetupServer(config)
	glog.Fatal(http.Serve(listener, router))
}
