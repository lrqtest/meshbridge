package api

import (
	"net/http"

	"github.com/mineai/kit/httpx"
)

const authJSONLimit = 16 << 10

// Read the whole bounded document before any password hash work. A decoder
// alone can accept a small first object followed by an oversized JSON tail.
func decodeAuthJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return httpx.ReadDocument(w, r, v, authJSONLimit)
}
