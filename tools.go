package requests

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	_ "unsafe"

	"github.com/gospider007/ja3"
	"golang.org/x/exp/slices"
	"golang.org/x/net/http/httpguts"
)

func getHost(req *http.Request) string {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	_, port, _ := net.SplitHostPort(host)
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
		return fmt.Sprintf("%s:%s", host, port)
	}
	return host
}
func getAddr(uurl *url.URL) (addr string) {
	if uurl == nil {
		return ""
	}
	_, port, _ := net.SplitHostPort(uurl.Host)
	if port == "" {
		if uurl.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
		return fmt.Sprintf("%s:%s", uurl.Host, port)
	}
	return uurl.Host
}
func cloneUrl(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	r := *u
	return &r
}

var replaceMap = map[string]string{
	"Sec-Ch-Ua":          "sec-ch-ua",
	"Sec-Ch-Ua-Mobile":   "sec-ch-ua-mobile",
	"Sec-Ch-Ua-Platform": "sec-ch-ua-platform",
}

/*//go:linkname escapeQuotes mime/multipart.escapeQuotes
func escapeQuotes(string) string

//go:linkname readCookies net/http.readCookies
func readCookies(h http.Header, filter string) []*http.Cookie

//go:linkname readSetCookies net/http.readSetCookies
func readSetCookies(h http.Header) []*http.Cookie

//go:linkname ReadRequest net/http.readRequest
func ReadRequest(b *bufio.Reader) (*http.Request, error)

//go:linkname removeZone net/http.removeZone
func removeZone(host string) string

//go:linkname shouldSendContentLength net/http.(*transferWriter).shouldSendContentLength
func shouldSendContentLength(t *http.Request) bool

//go:linkname removeEmptyPort net/http.removeEmptyPort
func removeEmptyPort(host string) string

//go:linkname redirectBehavior net/http.redirectBehavior
func redirectBehavior(reqMethod string, resp *http.Response, ireq *http.Request) (redirectMethod string, shouldRedirect, includeBody bool)

//go:linkname readTransfer net/http.readTransfer
func readTransfer(msg any, r *bufio.Reader) (err error)
*/

// ---- escapeQuotes (来自 mime/multipart) ----
func escapeQuotes(s string) string {
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			buf.WriteByte('\\')
		}
		buf.WriteByte(s[i])
	}
	return buf.String()
}

// ---- readCookies / readSetCookies ----
func readCookies(h http.Header, filter string) []*http.Cookie {
	lines := h["Cookie"]
	if len(lines) == 0 {
		return nil
	}
	var cookies []*http.Cookie
	for _, line := range lines {
		parts := strings.Split(line, ";")
		for _, part := range parts {
			part = textproto.TrimString(part)
			if len(part) == 0 {
				continue
			}
			name, val, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			name = textproto.TrimString(name)
			if filter != "" && filter != name {
				continue
			}
			val = textproto.TrimString(val)
			cookies = append(cookies, &http.Cookie{Name: name, Value: val})
		}
	}
	return cookies
}

func readSetCookies(h http.Header) []*http.Cookie {
	lines := h["Set-Cookie"]
	if len(lines) == 0 {
		return nil
	}
	cookies := make([]*http.Cookie, 0, len(lines))
	for _, line := range lines {
		c := new(http.Cookie)
		*c = *parseCookie(line)
		cookies = append(cookies, c)
	}
	return cookies
}

func parseCookie(line string) *http.Cookie {
	parts := strings.Split(line, ";")
	if len(parts) == 0 {
		return &http.Cookie{}
	}
	kv := strings.SplitN(parts[0], "=", 2)
	c := &http.Cookie{Name: strings.TrimSpace(kv[0])}
	if len(kv) > 1 {
		c.Value = strings.TrimSpace(kv[1])
	}
	return c
}

// ---- ReadRequest ----
func ReadRequest(b *bufio.Reader) (*http.Request, error) {
	req, err := http.ReadRequest(b)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ---- removeZone (IPv6 地址去掉 zone) ----
func removeZone(host string) string {
	i := strings.LastIndex(host, "%")
	if i == -1 {
		return host
	}
	// 保证是 IPv6 地址
	if strings.Contains(host, ":") {
		return host[:i]
	}
	return host
}

// ---- shouldSendContentLength ----
func shouldSendContentLength(req *http.Request) bool {
	if req.Body == nil {
		return false
	}
	if req.ContentLength > 0 {
		return true
	}
	return false
}

// ---- removeEmptyPort ----
func removeEmptyPort(host string) string {
	if strings.HasSuffix(host, ":") {
		return strings.TrimSuffix(host, ":")
	}
	return host
}

// ---- redirectBehavior ----
func redirectBehavior(reqMethod string, resp *http.Response, ireq *http.Request) (redirectMethod string, shouldRedirect, includeBody bool) {
	switch resp.StatusCode {
	case 301, 302, 303:
		redirectMethod = http.MethodGet
		shouldRedirect = true
		includeBody = false
	case 307, 308:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = true
	default:
		redirectMethod = reqMethod
		shouldRedirect = false
		includeBody = false
	}
	return
}

// ---- readTransfer (简化版，只做占位，避免编译错误) ----
func readTransfer(msg any, r *bufio.Reader) (err error) {
	// 在 Go1.21+ 已经完全重构，原始内部实现不可直接调用
	// 这里给出简化逻辑：仅保证接口兼容
	if _, ok := msg.(*http.Request); ok {
		// 读 Body 到 EOF
		_, err = io.ReadAll(r)
		return err
	}
	return errors.New("unsupported type for readTransfer")
}

var filterHeaderKeys = ja3.DefaultOrderHeadersWithH2()

func httpWrite(r *http.Request, w *bufio.Writer, orderHeaders []string) (err error) {
	for i := range orderHeaders {
		orderHeaders[i] = textproto.CanonicalMIMEHeaderKey(orderHeaders[i])
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	host, err = httpguts.PunycodeHostPort(host)
	if err != nil {
		return err
	}
	host = removeZone(host)
	ruri := r.URL.RequestURI()
	if r.Method == "CONNECT" && r.URL.Path == "" {
		if r.URL.Opaque != "" {
			ruri = r.URL.Opaque
		} else {
			ruri = host
		}
	}
	if r.Header.Get("Host") == "" {
		r.Header.Set("Host", host)
	}
	if r.Header.Get("Connection") == "" {
		r.Header.Set("Connection", "keep-alive")
	}
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", UserAgent)
	}
	if r.Header.Get("Content-Length") == "" && r.ContentLength != 0 && shouldSendContentLength(r) {
		r.Header.Set("Content-Length", fmt.Sprint(r.ContentLength))
	}
	if _, err = w.WriteString(fmt.Sprintf("%s %s %s\r\n", r.Method, ruri, r.Proto)); err != nil {
		return err
	}
	for _, k := range orderHeaders {
		if vs, ok := r.Header[k]; ok {
			if k2, ok := replaceMap[k]; ok {
				k = k2
			}
			if slices.Contains(filterHeaderKeys, k) {
				continue
			}
			for _, v := range vs {
				if _, err = w.WriteString(fmt.Sprintf("%s: %s\r\n", k, v)); err != nil {
					return err
				}
			}
		}
	}
	for k, vs := range r.Header {
		if !slices.Contains(orderHeaders, k) {
			if k2, ok := replaceMap[k]; ok {
				k = k2
			}
			if slices.Contains(filterHeaderKeys, k) {
				continue
			}
			for _, v := range vs {
				if _, err = w.WriteString(fmt.Sprintf("%s: %s\r\n", k, v)); err != nil {
					return err
				}
			}
		}
	}
	if _, err = w.WriteString("\r\n"); err != nil {
		return err
	}
	if r.Body != nil {
		if _, err = io.Copy(w, r.Body); err != nil {
			return err
		}
	}
	return w.Flush()
}
func NewRequestWithContext(ctx context.Context, method string, u *url.URL, body io.Reader) (*http.Request, error) {
	req := (&http.Request{}).WithContext(ctx)
	if method == "" {
		req.Method = http.MethodGet
	} else {
		req.Method = strings.ToUpper(method)
	}
	req.URL = u
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Host = u.Host
	u.Host = removeEmptyPort(u.Host)
	if body != nil {
		if v, ok := body.(interface{ Len() int }); ok {
			req.ContentLength = int64(v.Len())
		}
		rc, ok := body.(io.ReadCloser)
		if !ok {
			rc = io.NopCloser(body)
		}
		req.Body = rc
	}
	return req, nil
}

func readResponse(tp *textproto.Reader, req *http.Request) (*http.Response, error) {
	resp := &http.Response{
		Request: req,
	}
	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	proto, status, ok := strings.Cut(line, " ")
	if !ok {
		return nil, errors.New("malformed HTTP response")
	}
	resp.Proto = proto
	resp.Status = strings.TrimLeft(status, " ")
	statusCode, _, _ := strings.Cut(resp.Status, " ")
	if resp.StatusCode, err = strconv.Atoi(statusCode); err != nil {
		return nil, errors.New("malformed HTTP status code")
	}
	if resp.ProtoMajor, resp.ProtoMinor, ok = http.ParseHTTPVersion(resp.Proto); !ok {
		return nil, errors.New("malformed HTTP version")
	}
	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = http.Header(mimeHeader)
	return resp, readTransfer(resp, tp.R)
}

func addCookie(req *http.Request, cookies Cookies) {
	cooks := Cookies(readCookies(req.Header, ""))
	for _, cook := range cookies {
		if val := cooks.Get(cook.Name); val == nil {
			cooks = cooks.append(cook)
		}
	}
	if result := cooks.String(); result != "" {
		req.Header.Set("Cookie", result)
	}
}
