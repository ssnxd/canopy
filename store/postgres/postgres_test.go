package postgres

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/lib/pq"
	"github.com/ssnxd/canopy"
)

func TestMapErrClassifiesPostgresErrors(t *testing.T) {
	conflict := &pq.Error{Code: "23505", Message: "duplicate key"}
	if err := mapErr(conflict); !errors.Is(err, canopy.ErrConflict) || !errors.Is(err, conflict) {
		t.Fatalf("unique violation = %v, want conflict preserving cause", err)
	}
	failure := errors.New("connection lost")
	if err := mapErr(failure); !errors.Is(err, canopy.ErrStorageFailure) || !errors.Is(err, failure) {
		t.Fatalf("backend failure = %v, want storage failure preserving cause", err)
	}
	if err := mapErr(sql.ErrNoRows); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("no rows = %v, want not found", err)
	}
}

func TestMapRowsPropagatesRowsAffectedFailure(t *testing.T) {
	failure := errors.New("rows affected unavailable")
	if err := mapRows(nil, failingResult{err: failure}); !errors.Is(err, canopy.ErrStorageFailure) || !errors.Is(err, failure) {
		t.Fatalf("mapRows() = %v, want storage failure preserving cause", err)
	}
}

type failingResult struct {
	err error
}

func (r failingResult) LastInsertId() (int64, error) {
	return 0, r.err
}

func (r failingResult) RowsAffected() (int64, error) {
	return 0, r.err
}
