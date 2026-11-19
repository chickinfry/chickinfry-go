package server

import (
	"errors"
	"unicode/utf8"

	"github.com/chickinfry/chickinfry-go/server/host"
)

const storageObjectLimit = 4 << 20

// Storage reads and writes one declared storage through the host storage port.
// The logical name comes from the declaration; credentials stay in the host.
type Storage struct {
	request Request
	name    string
}

// NewStorage defers credential resolution to the first storage operation.
func NewStorage(request Request, name string) Storage {
	return Storage{request: request, name: name}
}

type storageGetQuery struct {
	RID  int64  `json:"rid"`
	Op   string `json:"op"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

type storagePutQuery struct {
	RID         int64  `json:"rid"`
	Op          string `json:"op"`
	Name        string `json:"name"`
	Key         string `json:"key"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// Get returns the stored bytes, or nil when the object is absent.
func (storage Storage) Get(key string) ([]byte, error) {
	if err := validStorageKey(key); err != nil {
		return nil, err
	}
	response, err := storage.request.call("storage", storageGetQuery{RID: storage.request.RID, Op: "get", Name: storage.name, Key: key})
	if err != nil {
		return nil, err
	}
	var value *[]byte
	if err := host.EnvelopeLimit(response, "value", &value, host.StorageFrame); err != nil {
		return nil, storageFailure(err)
	}
	if value == nil {
		return nil, nil
	}
	if len(*value) > storageObjectLimit {
		return nil, errors.New("storage object exceeds the supported 4 MiB limit")
	}
	return *value, nil
}

// Put stores bytes under one key and confirms the write.
func (storage Storage) Put(key string, body []byte, contentType string) error {
	if err := validStorageKey(key); err != nil {
		return err
	}
	if len(body) > storageObjectLimit {
		return errors.New("storage object exceeds the supported 4 MiB limit")
	}
	response, err := storage.request.call("storage", storagePutQuery{RID: storage.request.RID, Op: "put", Name: storage.name, Key: key, ContentType: contentType, Body: body})
	if err != nil {
		return err
	}
	if err := host.EnvelopeLimit(response, "", nil, host.StorageFrame); err != nil {
		return storageFailure(err)
	}
	return nil
}

func validStorageKey(key string) error {
	if key == "" || len(key) > 1024 {
		return errors.New("invalid storage object key")
	}
	start := 0
	for index := 0; index <= len(key); index++ {
		if index == len(key) || key[index] == '/' {
			segment := key[start:index]
			if segment == "." || segment == ".." {
				return errors.New("invalid storage object key")
			}
			start = index + 1
		}
	}
	for _, character := range key {
		if character < 32 || character == 127 {
			return errors.New("invalid storage object key")
		}
	}
	if !utf8.ValidString(key) {
		return errors.New("invalid storage object key")
	}
	return nil
}

func storageFailure(err error) error {
	if failure, ok := errors.AsType[*host.Error](err); ok {
		if failure.Code == "binding_unavailable" {
			return &OperationError{Status: 503, Code: "service_unavailable"}
		}
		return err
	}
	return err
}
