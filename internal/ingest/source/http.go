package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HTTPSource struct {
	websiteID   string
	id          string
	url         string
	headers     map[string]string
	rangePolicy RangePolicy
	index       *HTTPIndex
	compression string
	client      *http.Client
}

type HTTPIndex struct {
	URL     string
	Method  string
	Headers map[string]string
	JSONMap map[string]string
}

func NewHTTPSource(websiteID, id, url string, headers map[string]string, rangePolicy RangePolicy, index *HTTPIndex, compression string) *HTTPSource {
	return NewHTTPSourceWithTimeout(websiteID, id, url, headers, rangePolicy, index, compression, 30*time.Second)
}

func NewHTTPSourceWithTimeout(
	websiteID, id, url string,
	headers map[string]string,
	rangePolicy RangePolicy,
	index *HTTPIndex,
	compression string,
	timeout time.Duration,
) *HTTPSource {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return &HTTPSource{
		websiteID:   websiteID,
		id:          id,
		url:         url,
		headers:     headers,
		rangePolicy: rangePolicy,
		index:       index,
		compression: compression,
		client:      client,
	}
}

func (s *HTTPSource) ID() string {
	return s.id
}

func (s *HTTPSource) Type() SourceType {
	return SourceHTTP
}

func (s *HTTPSource) ListTargets(ctx context.Context) ([]TargetRef, error) {
	if s.index == nil {
		return []TargetRef{{
			WebsiteID: s.websiteID,
			SourceID:  s.id,
			Key:       s.url,
			Meta: TargetMeta{
				Compressed: isCompressedByName(s.url, s.compression),
			},
		}}, nil
	}

	indexURL := s.index.URL
	method := strings.ToUpper(strings.TrimSpace(s.index.Method))
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, indexURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range s.index.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http index status %d", resp.StatusCode)
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	itemsField := getJSONMapField(s.index.JSONMap, "items", "items")
	rawItems, ok := payload[itemsField]
	if !ok {
		return nil, fmt.Errorf("http index missing field: %s", itemsField)
	}

	items, ok := rawItems.([]interface{})
	if !ok {
		return nil, fmt.Errorf("http index field %s is not array", itemsField)
	}

	pathField := getJSONMapField(s.index.JSONMap, "path", "path")
	sizeField := getJSONMapField(s.index.JSONMap, "size", "size")
	mtimeField := getJSONMapField(s.index.JSONMap, "mtime", "mtime")
	etagField := getJSONMapField(s.index.JSONMap, "etag", "etag")
	compressedField := getJSONMapField(s.index.JSONMap, "compressed", "compressed")

	targets := make([]TargetRef, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		path, _ := obj[pathField].(string)
		if strings.TrimSpace(path) == "" {
			continue
		}

		meta := TargetMeta{
			Compressed: isCompressedByName(path, s.compression),
		}
		if sizeValue, ok := obj[sizeField]; ok {
			meta.Size = parseInt64(sizeValue)
		}
		if etagValue, ok := obj[etagField].(string); ok {
			meta.ETag = etagValue
		}
		if mtimeValue, ok := obj[mtimeField]; ok {
			meta.ModTime = parseTimeValue(mtimeValue)
		}
		if compressedValue, ok := obj[compressedField]; ok {
			if parsed, ok := compressedValue.(bool); ok {
				meta.Compressed = parsed
			}
		}

		targets = append(targets, TargetRef{
			WebsiteID: s.websiteID,
			SourceID:  s.id,
			Key:       path,
			Meta:      meta,
		})
	}

	return targets, nil
}

func (s *HTTPSource) OpenRange(ctx context.Context, target TargetRef, start, end int64) (io.ReadCloser, error) {
	if s.rangePolicy == RangeFull && start > 0 {
		return nil, ErrRangeNotSupported
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.Key, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	if start > 0 || end > 0 {
		if s.rangePolicy == RangeFull {
			return nil, ErrRangeNotSupported
		}
		rangeHeader := buildRangeHeader(start, end)
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusPartialContent {
		return resp.Body, nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if start > 0 && s.rangePolicy != RangeFull {
			resp.Body.Close()
			return nil, ErrRangeNotSupported
		}
		return resp.Body, nil
	}

	resp.Body.Close()
	return nil, fmt.Errorf("http status %d", resp.StatusCode)
}

func (s *HTTPSource) OpenStream(ctx context.Context, target TargetRef) (io.ReadCloser, error) {
	_ = ctx
	_ = target
	return nil, ErrStreamNotSupported
}

func (s *HTTPSource) Stat(ctx context.Context, target TargetRef) (TargetMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.Key, nil)
	if err != nil {
		return TargetMeta{}, err
	}
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return TargetMeta{}, err
	}
	defer resp.Body.Close()

	meta := TargetMeta{
		Compressed: isCompressedByName(target.Key, s.compression),
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return meta, fmt.Errorf("http status %d", resp.StatusCode)
	}

	if length := resp.Header.Get("Content-Length"); length != "" {
		if parsed, err := strconv.ParseInt(length, 10, 64); err == nil {
			meta.Size = parsed
		}
	}
	meta.ETag = strings.Trim(resp.Header.Get("ETag"), "\"")
	if last := resp.Header.Get("Last-Modified"); last != "" {
		if parsed, err := http.ParseTime(last); err == nil {
			meta.ModTime = parsed
		}
	}

	return meta, nil
}

func buildRangeHeader(start, end int64) string {
	if end > 0 && end > start {
		return fmt.Sprintf("bytes=%d-%d", start, end-1)
	}
	return fmt.Sprintf("bytes=%d-", start)
}

func getJSONMapField(jsonMap map[string]string, key, fallback string) string {
	if jsonMap == nil {
		return fallback
	}
	if value := strings.TrimSpace(jsonMap[key]); value != "" {
		return value
	}
	return fallback
}

func parseInt64(value interface{}) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int64:
		return typed
	case int:
		return int64(typed)
	case string:
		if parsed, err := strconv.ParseInt(typed, 10, 64); err == nil {
			return parsed
		}
	}
	return 0
}

func parseTimeValue(value interface{}) time.Time {
	switch typed := value.(type) {
	case float64:
		return time.Unix(int64(typed), 0)
	case int64:
		return time.Unix(typed, 0)
	case int:
		return time.Unix(int64(typed), 0)
	case string:
		layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"}
		for _, layout := range layouts {
			if parsed, err := time.Parse(layout, typed); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}
