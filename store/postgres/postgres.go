package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ssnxd/canopy"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, Migration)
	return err
}

func (s *Store) FindUserByID(ctx context.Context, id string) (*canopy.User, error) {
	row := s.db.QueryRowContext(ctx, `
select id, name, email, email_verified, image, created_at, updated_at
from "user" where id = $1`, id)
	var u canopy.User
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*canopy.User, error) {
	row := s.db.QueryRowContext(ctx, `
select id, name, email, email_verified, image, created_at, updated_at
from "user" where lower(email) = lower($1)`, email)
	var u canopy.User
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *Store) CreateUser(ctx context.Context, u *canopy.User) error {
	_, err := s.db.ExecContext(ctx, `
insert into "user" (id, name, email, email_verified, image, created_at, updated_at)
values ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, u.Name, u.Email, u.EmailVerified, u.Image, u.CreatedAt, u.UpdatedAt)
	return mapErr(err)
}

func (s *Store) UpdateUser(ctx context.Context, u *canopy.User) error {
	res, err := s.db.ExecContext(ctx, `
update "user" set name=$2, email=$3, email_verified=$4, image=$5, updated_at=$6 where id=$1`,
		u.ID, u.Name, u.Email, u.EmailVerified, u.Image, u.UpdatedAt)
	return mapRows(err, res)
}

func (s *Store) FindAccount(ctx context.Context, providerID, accountID string) (*canopy.Account, error) {
	row := s.db.QueryRowContext(ctx, accountSelect(`where provider_id=$1 and account_id=$2`), providerID, accountID)
	return scanAccount(row)
}

func (s *Store) FindAccountByUserProvider(ctx context.Context, userID, providerID string) (*canopy.Account, error) {
	row := s.db.QueryRowContext(ctx, accountSelect(`where user_id=$1 and provider_id=$2`), userID, providerID)
	return scanAccount(row)
}

func (s *Store) CreateAccount(ctx context.Context, a *canopy.Account) error {
	_, err := s.db.ExecContext(ctx, `
insert into account (
	id, user_id, account_id, provider_id, access_token, refresh_token, access_token_expires_at,
	refresh_token_expires_at, scope, id_token, password, created_at, updated_at
) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		a.ID, a.UserID, a.AccountID, a.ProviderID, a.AccessToken, a.RefreshToken, a.AccessTokenExpiresAt,
		a.RefreshTokenExpiresAt, a.Scope, a.IDToken, a.Password, a.CreatedAt, a.UpdatedAt)
	return mapErr(err)
}

func (s *Store) UpdateAccount(ctx context.Context, a *canopy.Account) error {
	res, err := s.db.ExecContext(ctx, `
update account set
	access_token=$2, refresh_token=$3, access_token_expires_at=$4, refresh_token_expires_at=$5,
	scope=$6, id_token=$7, password=$8, updated_at=$9
where id=$1`,
		a.ID, a.AccessToken, a.RefreshToken, a.AccessTokenExpiresAt, a.RefreshTokenExpiresAt,
		a.Scope, a.IDToken, a.Password, a.UpdatedAt)
	return mapRows(err, res)
}

func (s *Store) CreateSession(ctx context.Context, ses *canopy.Session) error {
	_, err := s.db.ExecContext(ctx, `
insert into session (id, user_id, token, expires_at, ip_address, user_agent, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8)`,
		ses.ID, ses.UserID, ses.Token, ses.ExpiresAt, ses.IPAddress, ses.UserAgent, ses.CreatedAt, ses.UpdatedAt)
	return mapErr(err)
}

func (s *Store) FindSessionByToken(ctx context.Context, token string) (*canopy.SessionData, error) {
	row := s.db.QueryRowContext(ctx, `
select
	u.id, u.name, u.email, u.email_verified, u.image, u.created_at, u.updated_at,
	se.id, se.user_id, se.token, se.expires_at, se.ip_address, se.user_agent, se.created_at, se.updated_at
from session se
join "user" u on u.id = se.user_id
where se.token=$1`, token)
	var data canopy.SessionData
	if err := row.Scan(
		&data.User.ID, &data.User.Name, &data.User.Email, &data.User.EmailVerified, &data.User.Image, &data.User.CreatedAt, &data.User.UpdatedAt,
		&data.Session.ID, &data.Session.UserID, &data.Session.Token, &data.Session.ExpiresAt, &data.Session.IPAddress, &data.Session.UserAgent, &data.Session.CreatedAt, &data.Session.UpdatedAt,
	); err != nil {
		return nil, mapErr(err)
	}
	return &data, nil
}

func (s *Store) UpdateSession(ctx context.Context, ses *canopy.Session) error {
	res, err := s.db.ExecContext(ctx, `
update session set expires_at=$2, ip_address=$3, user_agent=$4, updated_at=$5 where id=$1`,
		ses.ID, ses.ExpiresAt, ses.IPAddress, ses.UserAgent, ses.UpdatedAt)
	return mapRows(err, res)
}

func (s *Store) DeleteSessionByToken(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx, `delete from session where token=$1`, token)
	return mapRows(err, res)
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `delete from session where user_id=$1`, userID)
	return mapErr(err)
}

func (s *Store) CreateVerification(ctx context.Context, v *canopy.Verification) error {
	_, err := s.db.ExecContext(ctx, `
insert into verification (id, identifier, value, expires_at, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6)`, v.ID, v.Identifier, v.Value, v.ExpiresAt, v.CreatedAt, v.UpdatedAt)
	return mapErr(err)
}

func (s *Store) ConsumeVerification(ctx context.Context, identifier, value string, now time.Time) (*canopy.Verification, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `
delete from verification
where identifier=$1 and value=$2 and expires_at > $3
returning id, identifier, value, expires_at, created_at, updated_at`, identifier, value, now)
	var v canopy.Verification
	if err := row.Scan(&v.ID, &v.Identifier, &v.Value, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) DeleteExpiredVerifications(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `delete from verification where expires_at <= $1`, now)
	return mapErr(err)
}

type scanner interface {
	Scan(dest ...any) error
}

func accountSelect(where string) string {
	return fmt.Sprintf(`
select id, user_id, account_id, provider_id, access_token, refresh_token, access_token_expires_at,
	refresh_token_expires_at, scope, id_token, password, created_at, updated_at
from account %s`, where)
}

func scanAccount(row scanner) (*canopy.Account, error) {
	var a canopy.Account
	if err := row.Scan(
		&a.ID, &a.UserID, &a.AccountID, &a.ProviderID, &a.AccessToken, &a.RefreshToken,
		&a.AccessTokenExpiresAt, &a.RefreshTokenExpiresAt, &a.Scope, &a.IDToken, &a.Password,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, mapErr(err)
	}
	return &a, nil
}

func mapRows(err error, res sql.Result) error {
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return canopy.ErrNotFound
	}
	return nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return canopy.ErrNotFound
	}
	return err
}
