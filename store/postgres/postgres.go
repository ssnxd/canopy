package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/sessions"
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

const userColumns = `id, name, email, email_verified, image, role, banned, ban_reason, ban_expires_at, created_at, updated_at`

func scanUser(row scanner) (*canopy.User, error) {
	var u canopy.User
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image, &u.Role, &u.Banned, &u.BanReason, &u.BanExpiresAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *Store) FindUserByID(ctx context.Context, id string) (*canopy.User, error) {
	row := s.db.QueryRowContext(ctx, `select `+userColumns+` from "user" where id = $1`, id)
	return scanUser(row)
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*canopy.User, error) {
	row := s.db.QueryRowContext(ctx, `select `+userColumns+` from "user" where lower(email) = lower($1)`, email)
	return scanUser(row)
}

const userInsert = `
insert into "user" (id, name, email, email_verified, image, role, banned, ban_reason, ban_expires_at, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`

func userInsertArgs(u *canopy.User) []any {
	return []any{u.ID, u.Name, u.Email, u.EmailVerified, u.Image, u.Role, u.Banned, u.BanReason, u.BanExpiresAt, u.CreatedAt, u.UpdatedAt}
}

func (s *Store) CreateUser(ctx context.Context, u *canopy.User) error {
	_, err := s.db.ExecContext(ctx, userInsert, userInsertArgs(u)...)
	return mapErr(err)
}

func (s *Store) CreateUserAccount(ctx context.Context, u *canopy.User, a *canopy.Account) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, userInsert, userInsertArgs(u)...); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx, `
insert into account (
	id, user_id, account_id, provider_id, access_token, refresh_token, access_token_expires_at,
	refresh_token_expires_at, scope, id_token, password, created_at, updated_at
) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		a.ID, a.UserID, a.AccountID, a.ProviderID, a.AccessToken, a.RefreshToken, a.AccessTokenExpiresAt,
		a.RefreshTokenExpiresAt, a.Scope, a.IDToken, a.Password, a.CreatedAt, a.UpdatedAt); err != nil {
		return mapErr(err)
	}
	return tx.Commit()
}

func (s *Store) UpdateUser(ctx context.Context, u *canopy.User) error {
	res, err := s.db.ExecContext(ctx, `
update "user" set name=$2, email=$3, email_verified=$4, image=$5, role=$6, banned=$7, ban_reason=$8, ban_expires_at=$9, updated_at=$10 where id=$1`,
		u.ID, u.Name, u.Email, u.EmailVerified, u.Image, u.Role, u.Banned, u.BanReason, u.BanExpiresAt, u.UpdatedAt)
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
	insert into session (id, user_id, token, expires_at, ip_address, user_agent, active_organization_id, impersonated_by, created_at, updated_at)
	values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		ses.ID, ses.UserID, sessions.TokenDigest(ses.Token), ses.ExpiresAt, ses.IPAddress, ses.UserAgent, ses.ActiveOrganizationID, ses.ImpersonatedBy, ses.CreatedAt, ses.UpdatedAt)
	return mapErr(err)
}

func (s *Store) FindSessionByToken(ctx context.Context, token string) (*canopy.SessionData, error) {
	row := s.db.QueryRowContext(ctx, `
select
	u.id, u.name, u.email, u.email_verified, u.image, u.role, u.banned, u.ban_reason, u.ban_expires_at, u.created_at, u.updated_at,
	se.id, se.user_id, se.token, se.expires_at, se.ip_address, se.user_agent, se.active_organization_id, se.impersonated_by, se.created_at, se.updated_at
from session se
join "user" u on u.id = se.user_id
	where se.token=$1`, sessions.TokenDigest(token))
	var data canopy.SessionData
	var storedToken string
	if err := row.Scan(
		&data.User.ID, &data.User.Name, &data.User.Email, &data.User.EmailVerified, &data.User.Image, &data.User.Role, &data.User.Banned, &data.User.BanReason, &data.User.BanExpiresAt, &data.User.CreatedAt, &data.User.UpdatedAt,
		&data.Session.ID, &data.Session.UserID, &storedToken, &data.Session.ExpiresAt, &data.Session.IPAddress, &data.Session.UserAgent, &data.Session.ActiveOrganizationID, &data.Session.ImpersonatedBy, &data.Session.CreatedAt, &data.Session.UpdatedAt,
	); err != nil {
		return nil, mapErr(err)
	}
	data.Session.Token = token
	return &data, nil
}

func (s *Store) UpdateSession(ctx context.Context, ses *canopy.Session) error {
	res, err := s.db.ExecContext(ctx, `
update session set expires_at=$2, ip_address=$3, user_agent=$4, active_organization_id=$5, impersonated_by=$6, updated_at=$7 where id=$1`,
		ses.ID, ses.ExpiresAt, ses.IPAddress, ses.UserAgent, ses.ActiveOrganizationID, ses.ImpersonatedBy, ses.UpdatedAt)
	return mapRows(err, res)
}

func (s *Store) DeleteSessionByToken(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx, `delete from session where token=$1`, sessions.TokenDigest(token))
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

func (s *Store) GetTwoFactor(ctx context.Context, userID string) (*canopy.TwoFactor, error) {
	row := s.db.QueryRowContext(ctx, `
select user_id, secret, enabled, created_at, updated_at from two_factor where user_id=$1`, userID)
	var tf canopy.TwoFactor
	if err := row.Scan(&tf.UserID, &tf.Secret, &tf.Enabled, &tf.CreatedAt, &tf.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &tf, nil
}

func (s *Store) UpsertTwoFactor(ctx context.Context, tf *canopy.TwoFactor) error {
	_, err := s.db.ExecContext(ctx, `
insert into two_factor (user_id, secret, enabled, created_at, updated_at)
values ($1,$2,$3,$4,$5)
on conflict (user_id) do update set secret=excluded.secret, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		tf.UserID, tf.Secret, tf.Enabled, tf.CreatedAt, tf.UpdatedAt)
	return mapErr(err)
}

func (s *Store) DeleteTwoFactor(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `delete from two_factor_backup_code where user_id=$1`, userID); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx, `delete from two_factor where user_id=$1`, userID); err != nil {
		return mapErr(err)
	}
	return tx.Commit()
}

func (s *Store) ReplaceBackupCodes(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `delete from two_factor_backup_code where user_id=$1`, userID); err != nil {
		return mapErr(err)
	}
	now := time.Now().UTC()
	for _, hash := range codeHashes {
		if _, err := tx.ExecContext(ctx, `
insert into two_factor_backup_code (user_id, code_hash, created_at) values ($1,$2,$3)`, userID, hash, now); err != nil {
			return mapErr(err)
		}
	}
	return tx.Commit()
}

func (s *Store) ConsumeBackupCode(ctx context.Context, userID, codeHash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `delete from two_factor_backup_code where user_id=$1 and code_hash=$2`, userID, codeHash)
	if err != nil {
		return false, mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) CreateOrganization(ctx context.Context, org *canopy.Organization) error {
	_, err := s.db.ExecContext(ctx, `
insert into organization (id, name, slug, created_at, updated_at) values ($1,$2,$3,$4,$5)`,
		org.ID, org.Name, org.Slug, org.CreatedAt, org.UpdatedAt)
	return mapErr(err)
}

func (s *Store) FindOrganizationByID(ctx context.Context, id string) (*canopy.Organization, error) {
	row := s.db.QueryRowContext(ctx, `select id, name, slug, created_at, updated_at from organization where id=$1`, id)
	return scanOrganization(row)
}

func (s *Store) FindOrganizationBySlug(ctx context.Context, slug string) (*canopy.Organization, error) {
	row := s.db.QueryRowContext(ctx, `select id, name, slug, created_at, updated_at from organization where lower(slug)=lower($1)`, slug)
	return scanOrganization(row)
}

func (s *Store) ListOrganizationsForUser(ctx context.Context, userID string) ([]canopy.Organization, error) {
	rows, err := s.db.QueryContext(ctx, `
select o.id, o.name, o.slug, o.created_at, o.updated_at
from organization o
join organization_member m on m.organization_id = o.id
where m.user_id = $1
order by o.created_at`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var orgs []canopy.Organization
	for rows.Next() {
		var o canopy.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, mapErr(err)
		}
		orgs = append(orgs, o)
	}
	return orgs, mapErr(rows.Err())
}

func (s *Store) UpdateOrganization(ctx context.Context, org *canopy.Organization) error {
	res, err := s.db.ExecContext(ctx, `update organization set name=$2, slug=$3, updated_at=$4 where id=$1`,
		org.ID, org.Name, org.Slug, org.UpdatedAt)
	return mapRows(err, res)
}

func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `delete from organization where id=$1`, id)
	return mapRows(err, res)
}

func (s *Store) CreateMember(ctx context.Context, member *canopy.Member) error {
	_, err := s.db.ExecContext(ctx, `
insert into organization_member (id, organization_id, user_id, role, created_at, updated_at) values ($1,$2,$3,$4,$5,$6)`,
		member.ID, member.OrganizationID, member.UserID, member.Role, member.CreatedAt, member.UpdatedAt)
	return mapErr(err)
}

func (s *Store) FindMember(ctx context.Context, orgID, userID string) (*canopy.Member, error) {
	row := s.db.QueryRowContext(ctx, `
select id, organization_id, user_id, role, created_at, updated_at
from organization_member where organization_id=$1 and user_id=$2`, orgID, userID)
	return scanMember(row)
}

func (s *Store) ListMembers(ctx context.Context, orgID string) ([]canopy.Member, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, organization_id, user_id, role, created_at, updated_at
from organization_member where organization_id=$1 order by created_at`, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var members []canopy.Member
	for rows.Next() {
		var m canopy.Member
		if err := rows.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.Role, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, mapErr(err)
		}
		members = append(members, m)
	}
	return members, mapErr(rows.Err())
}

func (s *Store) UpdateMember(ctx context.Context, member *canopy.Member) error {
	res, err := s.db.ExecContext(ctx, `update organization_member set role=$3, updated_at=$4 where organization_id=$1 and user_id=$2`,
		member.OrganizationID, member.UserID, member.Role, member.UpdatedAt)
	return mapRows(err, res)
}

func (s *Store) DeleteMember(ctx context.Context, orgID, userID string) error {
	res, err := s.db.ExecContext(ctx, `delete from organization_member where organization_id=$1 and user_id=$2`, orgID, userID)
	return mapRows(err, res)
}

func (s *Store) CreateInvitation(ctx context.Context, invitation *canopy.Invitation) error {
	_, err := s.db.ExecContext(ctx, `
insert into organization_invitation (id, organization_id, email, role, status, inviter_id, expires_at, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		invitation.ID, invitation.OrganizationID, invitation.Email, invitation.Role, invitation.Status,
		invitation.InviterID, invitation.ExpiresAt, invitation.CreatedAt, invitation.UpdatedAt)
	return mapErr(err)
}

func (s *Store) FindInvitation(ctx context.Context, id string) (*canopy.Invitation, error) {
	row := s.db.QueryRowContext(ctx, `
select id, organization_id, email, role, status, inviter_id, expires_at, created_at, updated_at
from organization_invitation where id=$1`, id)
	return scanInvitation(row)
}

func (s *Store) ListInvitationsForOrg(ctx context.Context, orgID string) ([]canopy.Invitation, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, organization_id, email, role, status, inviter_id, expires_at, created_at, updated_at
from organization_invitation where organization_id=$1 order by created_at`, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var invitations []canopy.Invitation
	for rows.Next() {
		var v canopy.Invitation
		if err := rows.Scan(&v.ID, &v.OrganizationID, &v.Email, &v.Role, &v.Status, &v.InviterID, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, mapErr(err)
		}
		invitations = append(invitations, v)
	}
	return invitations, mapErr(rows.Err())
}

func (s *Store) UpdateInvitation(ctx context.Context, invitation *canopy.Invitation) error {
	res, err := s.db.ExecContext(ctx, `
update organization_invitation set email=$2, role=$3, status=$4, expires_at=$5, updated_at=$6 where id=$1`,
		invitation.ID, invitation.Email, invitation.Role, invitation.Status, invitation.ExpiresAt, invitation.UpdatedAt)
	return mapRows(err, res)
}

func (s *Store) ListUsers(ctx context.Context, q canopy.UserQuery) ([]canopy.User, int, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	pattern := "%" + strings.ToLower(strings.TrimSpace(q.Search)) + "%"
	var total int
	if err := s.db.QueryRowContext(ctx, `
select count(*) from "user" where lower(name) like $1 or lower(email) like $1`, pattern).Scan(&total); err != nil {
		return nil, 0, mapErr(err)
	}
	rows, err := s.db.QueryContext(ctx, `
select `+userColumns+` from "user"
where lower(name) like $1 or lower(email) like $1
order by created_at
limit $2 offset $3`, pattern, limit, q.Offset)
	if err != nil {
		return nil, 0, mapErr(err)
	}
	defer rows.Close()
	var users []canopy.User
	for rows.Next() {
		var u canopy.User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.EmailVerified, &u.Image, &u.Role, &u.Banned, &u.BanReason, &u.BanExpiresAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, mapErr(err)
		}
		users = append(users, u)
	}
	return users, total, mapErr(rows.Err())
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]canopy.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, user_id, token, expires_at, ip_address, user_agent, active_organization_id, impersonated_by, created_at, updated_at
from session where user_id=$1 order by created_at`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var sessions []canopy.Session
	for rows.Next() {
		var se canopy.Session
		var storedToken string
		if err := rows.Scan(&se.ID, &se.UserID, &storedToken, &se.ExpiresAt, &se.IPAddress, &se.UserAgent, &se.ActiveOrganizationID, &se.ImpersonatedBy, &se.CreatedAt, &se.UpdatedAt); err != nil {
			return nil, mapErr(err)
		}
		sessions = append(sessions, se)
	}
	return sessions, mapErr(rows.Err())
}

func scanOrganization(row scanner) (*canopy.Organization, error) {
	var o canopy.Organization
	if err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &o, nil
}

func scanMember(row scanner) (*canopy.Member, error) {
	var m canopy.Member
	if err := row.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.Role, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &m, nil
}

func scanInvitation(row scanner) (*canopy.Invitation, error) {
	var v canopy.Invitation
	if err := row.Scan(&v.ID, &v.OrganizationID, &v.Email, &v.Role, &v.Status, &v.InviterID, &v.ExpiresAt, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &v, nil
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
