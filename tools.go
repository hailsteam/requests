package requests

import (
	"bufio"
	"bytes"
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

// helper: 是否包含 chunked
func containsChunked(te []string) bool {
	for _, v := range te {
		if strings.EqualFold(v, "chunked") {
			return true
		}
	}
	return false
}

// chunkedReader: streaming 解析 chunked body，並在遇到 0-chunk 時把 trailer 寫回 resp.Trailer
type chunkedReader struct {
	r    *bufio.Reader
	tr   *textproto.Reader
	resp *http.Response

	rem  int64 // 剩餘 bytes in current chunk
	done bool
}

func newChunkedReader(r *bufio.Reader, resp *http.Response) *chunkedReader {
	return &chunkedReader{
		r:    r,
		tr:   textproto.NewReader(r),
		resp: resp,
	}
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.done {
		return 0, io.EOF
	}

	// 如果當前 chunk 還有剩餘，從 r 讀取（最多讀 len(p) 或 rem）
	if cr.rem > 0 {
		toRead := int64(len(p))
		if toRead > cr.rem {
			toRead = cr.rem
		}
		n, err := io.ReadFull(cr.r, p[:toRead])
		if n > 0 {
			cr.rem -= int64(n)
			// 如果剛好讀完 chunk，消耗後面的 CRLF
			if cr.rem == 0 {
				// consume CRLF after chunk
				// 常見為 "\r\n"，我們做容錯處理
				b, err2 := cr.r.ReadByte()
				if err2 == nil {
					if b == '\r' {
						// try read '\n'
						if _, _ = cr.r.ReadByte(); true {
						}
					} else if b == '\n' {
						// ok
					} else {
						// 非預期字元：放回一個 byte (impossible with bufio), so ignore
					}
				} else {
					// ignore
				}
			}
			return n, err
		}
		return n, err
	}

	// 當前 chunk 已耗盡，需解析下一個 chunk size 行
	line, err := cr.tr.ReadLine()
	if err != nil {
		return 0, err
	}
	// chunk-size 可能有 extensions，取分號前
	if idx := strings.IndexByte(line, ';'); idx != -1 {
		line = line[:idx]
	}
	sz, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
	if err != nil {
		return 0, err
	}
	if sz == 0 {
		// 讀 trailers（MIME headers），並放入 resp.Trailer
		mimeHeader, err := cr.tr.ReadMIMEHeader()
		if err != nil {
			return 0, err
		}
		if cr.resp != nil {
			cr.resp.Trailer = http.Header(mimeHeader)
		}
		cr.done = true
		return 0, io.EOF
	}
	cr.rem = sz
	// 現在遞迴呼叫自己去讀 chunk 內容
	return cr.Read(p)
}

func (cr *chunkedReader) Close() error {
	// 保守處理：若尚未完成，讀完剩下的 chunk，確保 trailer 被讀入
	if cr.done {
		return nil
	}
	var buf [1024]byte
	for {
		_, err := cr.Read(buf[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// readTransfer: 解析 msg (*http.Request 或 *http.Response) 的 body，並把 Body 設回去
func readTransfer(msg any, r *bufio.Reader) (err error) {
	switch m := msg.(type) {
	case *http.Request:
		// Request: 以 ContentLength / TransferEncoding 判斷
		// 優先使用 Request.ContentLength（如果已被解析）
		if m.ContentLength > 0 {
			m.Body = io.NopCloser(io.LimitReader(r, m.ContentLength))
			return nil
		}
		// 如果 TransferEncoding 含 chunked（或 header 標記 chunked），使用 chunkedReader
		if containsChunked(m.TransferEncoding) || strings.EqualFold(m.Header.Get("Transfer-Encoding"), "chunked") {
			m.Body = io.NopCloser(newChunkedReader(r, nil))
			return nil
		}
		// 否則視為沒有 body（或 identity）：設為 NoBody
		m.Body = http.NoBody
		return nil

	case *http.Response:
		// Response: 若為 HEAD 或任意 no-body status code，則無 body
		if m.Request != nil && m.Request.Method == http.MethodHead {
			m.Body = http.NoBody
			return nil
		}
		if (m.StatusCode >= 100 && m.StatusCode < 200) || m.StatusCode == 204 || m.StatusCode == 304 {
			m.Body = http.NoBody
			return nil
		}

		// chunked?
		if containsChunked(m.TransferEncoding) || strings.EqualFold(m.Header.Get("Transfer-Encoding"), "chunked") {
			m.Body = io.NopCloser(newChunkedReader(r, m))
			return nil
		}

		// Content-Length?
		if cl := m.Header.Get("Content-Length"); cl != "" {
			n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
			if err == nil {
				if n == 0 {
					m.Body = http.NoBody
					return nil
				}
				m.Body = io.NopCloser(io.LimitReader(r, n))
				return nil
			}
			// parse error -> fallthrough to identity handling
		}

		// identity (no length & no chunked)：
		// * 標準庫在這種情況會把 body 視為直到 connection close，
		//   正確處理需要在 higher-level 管理 connection；這裡簡單採一次性讀取到記憶體作為兜底，
		//   若資料很大或希望 streaming，應改為把整個連線 lifecycle 的責任一起移植/管理。
		all, err := io.ReadAll(r)
		if err != nil && err != io.EOF {
			return err
		}
		m.Body = io.NopCloser(bytes.NewReader(all))
		return nil

	default:
		return errors.New("unsupported type for readTransfer")
	}
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
