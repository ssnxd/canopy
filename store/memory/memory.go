// Package memory is an in-memory canopy.Store. It is useful for tests and
// for local development. It is not durable and it does not scale across
// processes. Use a persistent store such as store/postgres in production.
package memory

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/sessions"
)

// Store is an in-memory implementation of canopy.Store. It also
// implements the optional capability interfaces.
type Store struct {
	mu            sync.Mutex
	users         map[string]*canopy.User
	accounts      map[string]*canopy.Account
	sessions      map[string]*canopy.Session
	verifications map[string]*canopy.Verification
	twoFactor     map[string]*canopy.TwoFactor
	backupCodes   map[string]map[string]bool
	organizations map[string]*canopy.Organization
	members       map[string]*canopy.Member
	invitations   map[string]*canopy.Invitation
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		users:         map[string]*canopy.User{},
		accounts:      map[string]*canopy.Account{},
		sessions:      map[string]*canopy.Session{},
		verifications: map[string]*canopy.Verification{},
		twoFactor:     map[string]*canopy.TwoFactor{},
		backupCodes:   map[string]map[string]bool{},
		organizations: map[string]*canopy.Organization{},
		members:       map[string]*canopy.Member{},
		invitations:   map[string]*canopy.Invitation{},
	}
}

func memberKey(orgID, userID string) string { return orgID + "|" + userID }

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func accountKey(providerID, accountID string) string {
	return providerID + "|" + accountID
}

func (s *Store) FindUserByID(ctx context.Context, id string) (*canopy.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[id]; u != nil {
		cp := *u
		return &cp, nil
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*canopy.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := normalizeEmail(email)
	for _, u := range s.users {
		if normalizeEmail(u.Email) == target {
			cp := *u
			return &cp, nil
		}
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) CreateUser(ctx context.Context, user *canopy.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createUserLocked(user)
}

func (s *Store) createUserLocked(user *canopy.User) error {
	target := normalizeEmail(user.Email)
	for _, u := range s.users {
		if normalizeEmail(u.Email) == target {
			return canopy.ErrConflict
		}
	}
	cp := *user
	s.users[user.ID] = &cp
	return nil
}

func (s *Store) UpdateUser(ctx context.Context, user *canopy.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users[user.ID] == nil {
		return canopy.ErrNotFound
	}
	cp := *user
	s.users[user.ID] = &cp
	return nil
}

func (s *Store) FindAccount(ctx context.Context, providerID, accountID string) (*canopy.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.accounts[accountKey(providerID, accountID)]; a != nil {
		cp := *a
		return &cp, nil
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) FindAccountByUserProvider(ctx context.Context, userID, providerID string) (*canopy.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.UserID == userID && a.ProviderID == providerID {
			cp := *a
			return &cp, nil
		}
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) CreateAccount(ctx context.Context, account *canopy.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createAccountLocked(account)
}

func (s *Store) createAccountLocked(account *canopy.Account) error {
	if s.accounts[accountKey(account.ProviderID, account.AccountID)] != nil {
		return canopy.ErrConflict
	}
	for _, a := range s.accounts {
		if a.UserID == account.UserID && a.ProviderID == account.ProviderID {
			return canopy.ErrConflict
		}
	}
	cp := *account
	s.accounts[accountKey(account.ProviderID, account.AccountID)] = &cp
	return nil
}

func (s *Store) CreateUserAccount(ctx context.Context, user *canopy.User, account *canopy.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.createUserLocked(user); err != nil {
		return err
	}
	if err := s.createAccountLocked(account); err != nil {
		delete(s.users, user.ID)
		return err
	}
	return nil
}

func (s *Store) UpdateAccount(ctx context.Context, account *canopy.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := accountKey(account.ProviderID, account.AccountID)
	if s.accounts[key] == nil {
		return canopy.ErrNotFound
	}
	cp := *account
	s.accounts[key] = &cp
	return nil
}

func (s *Store) CreateSession(ctx context.Context, session *canopy.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessions.TokenDigest(session.Token)
	if s.sessions[key] != nil {
		return canopy.ErrConflict
	}
	cp := *session
	cp.Token = ""
	s.sessions[key] = &cp
	return nil
}

func (s *Store) FindSessionByToken(ctx context.Context, token string) (*canopy.SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessions[sessions.TokenDigest(token)]
	if session == nil {
		return nil, canopy.ErrNotFound
	}
	user := s.users[session.UserID]
	if user == nil {
		return nil, canopy.ErrNotFound
	}
	sessionCopy := *session
	sessionCopy.Token = token
	return &canopy.SessionData{User: *user, Session: sessionCopy}, nil
}

func (s *Store) UpdateSession(ctx context.Context, session *canopy.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessions.TokenDigest(session.Token)
	if s.sessions[key] == nil {
		return canopy.ErrNotFound
	}
	cp := *session
	cp.Token = ""
	s.sessions[key] = &cp
	return nil
}

func (s *Store) DeleteSessionByToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sessions.TokenDigest(token)
	if s.sessions[key] == nil {
		return canopy.ErrNotFound
	}
	delete(s.sessions, key)
	return nil
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *Store) CreateVerification(ctx context.Context, v *canopy.Verification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *v
	s.verifications[v.Identifier+"|"+v.Value] = &cp
	return nil
}

func (s *Store) ReplaceVerification(ctx context.Context, v *canopy.Verification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, existing := range s.verifications {
		if existing.Identifier == v.Identifier {
			delete(s.verifications, key)
		}
	}
	cp := *v
	s.verifications[v.Identifier+"|"+v.Value] = &cp
	return nil
}

func (s *Store) ConsumeVerification(ctx context.Context, identifier, value string, now time.Time) (*canopy.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := identifier + "|" + value
	v := s.verifications[key]
	if v == nil || !v.ExpiresAt.After(now) {
		return nil, canopy.ErrNotFound
	}
	delete(s.verifications, key)
	cp := *v
	return &cp, nil
}

func (s *Store) DeleteVerificationsByIdentifier(ctx context.Context, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteVerificationsByIdentifierLocked(identifier)
	return nil
}

func (s *Store) deleteVerificationsByIdentifierLocked(identifier string) {
	for key, verification := range s.verifications {
		if verification.Identifier == identifier {
			delete(s.verifications, key)
		}
	}
}

func (s *Store) DeleteExpiredVerifications(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, v := range s.verifications {
		if !v.ExpiresAt.After(now) {
			delete(s.verifications, key)
		}
	}
	return nil
}

// ApplyPasswordReset atomically consumes the reset token, updates the password
// account, revokes sessions, and invalidates every other reset token.
func (s *Store) ApplyPasswordReset(
	ctx context.Context,
	identifier string,
	value string,
	now time.Time,
	account *canopy.Account,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	verificationKey := identifier + "|" + value
	verification := s.verifications[verificationKey]
	if verification == nil || !verification.ExpiresAt.After(now) {
		return canopy.ErrNotFound
	}
	accountKey := accountKey(account.ProviderID, account.AccountID)
	if s.accounts[accountKey] == nil {
		return canopy.ErrNotFound
	}
	accountCopy := *account
	s.accounts[accountKey] = &accountCopy
	for token, session := range s.sessions {
		if session.UserID == account.UserID {
			delete(s.sessions, token)
		}
	}
	s.deleteVerificationsByIdentifierLocked(identifier)
	return nil
}

func (s *Store) GetTwoFactor(ctx context.Context, userID string) (*canopy.TwoFactor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tf := s.twoFactor[userID]; tf != nil {
		cp := *tf
		return &cp, nil
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) UpsertTwoFactor(ctx context.Context, tf *canopy.TwoFactor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *tf
	s.twoFactor[tf.UserID] = &cp
	return nil
}

func (s *Store) EnableTwoFactor(ctx context.Context, tf *canopy.TwoFactor, codeHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.twoFactor[tf.UserID] == nil {
		return canopy.ErrNotFound
	}
	tfCopy := *tf
	codeSet := make(map[string]bool, len(codeHashes))
	for _, hash := range codeHashes {
		codeSet[hash] = true
	}
	s.twoFactor[tf.UserID] = &tfCopy
	s.backupCodes[tf.UserID] = codeSet
	return nil
}

func (s *Store) DeleteTwoFactor(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.twoFactor, userID)
	delete(s.backupCodes, userID)
	return nil
}

func (s *Store) ReplaceBackupCodes(ctx context.Context, userID string, codeHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := make(map[string]bool, len(codeHashes))
	for _, hash := range codeHashes {
		set[hash] = true
	}
	s.backupCodes[userID] = set
	return nil
}

func (s *Store) ConsumeBackupCode(ctx context.Context, userID, codeHash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.backupCodes[userID]
	if set == nil || !set[codeHash] {
		return false, nil
	}
	delete(set, codeHash)
	return true, nil
}

func (s *Store) ConsumeTOTPStep(ctx context.Context, userID string, counter int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tf := s.twoFactor[userID]
	if tf == nil {
		return false, canopy.ErrNotFound
	}
	if counter <= tf.LastTOTPStep {
		return false, nil
	}
	tf.LastTOTPStep = counter
	tf.UpdatedAt = time.Now().UTC()
	return true, nil
}

func (s *Store) CreateOrganization(ctx context.Context, org *canopy.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createOrganizationLocked(org)
}

func (s *Store) createOrganizationLocked(org *canopy.Organization) error {
	for _, o := range s.organizations {
		if strings.EqualFold(o.Slug, org.Slug) {
			return canopy.ErrConflict
		}
	}
	cp := *org
	s.organizations[org.ID] = &cp
	return nil
}

func (s *Store) CreateOrganizationWithOwner(ctx context.Context, org *canopy.Organization, owner *canopy.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.createOrganizationLocked(org); err != nil {
		return err
	}
	key := memberKey(owner.OrganizationID, owner.UserID)
	if s.members[key] != nil {
		delete(s.organizations, org.ID)
		return canopy.ErrConflict
	}
	ownerCopy := *owner
	s.members[key] = &ownerCopy
	return nil
}

func (s *Store) FindOrganizationByID(ctx context.Context, id string) (*canopy.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.organizations[id]; o != nil {
		cp := *o
		return &cp, nil
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) FindOrganizationBySlug(ctx context.Context, slug string) (*canopy.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.organizations {
		if strings.EqualFold(o.Slug, slug) {
			cp := *o
			return &cp, nil
		}
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) ListOrganizationsForUser(ctx context.Context, userID string) ([]canopy.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var orgs []canopy.Organization
	for _, m := range s.members {
		if m.UserID == userID {
			if o := s.organizations[m.OrganizationID]; o != nil {
				orgs = append(orgs, *o)
			}
		}
	}
	return orgs, nil
}

func (s *Store) UpdateOrganization(ctx context.Context, org *canopy.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.organizations[org.ID] == nil {
		return canopy.ErrNotFound
	}
	cp := *org
	s.organizations[org.ID] = &cp
	return nil
}

func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.organizations[id] == nil {
		return canopy.ErrNotFound
	}
	delete(s.organizations, id)
	for key, m := range s.members {
		if m.OrganizationID == id {
			delete(s.members, key)
		}
	}
	return nil
}

func (s *Store) CreateMember(ctx context.Context, member *canopy.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memberKey(member.OrganizationID, member.UserID)
	if s.members[key] != nil {
		return canopy.ErrConflict
	}
	cp := *member
	s.members[key] = &cp
	return nil
}

func (s *Store) FindMember(ctx context.Context, orgID, userID string) (*canopy.Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.members[memberKey(orgID, userID)]; m != nil {
		cp := *m
		return &cp, nil
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) ListMembers(ctx context.Context, orgID string) ([]canopy.Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var members []canopy.Member
	for _, m := range s.members {
		if m.OrganizationID == orgID {
			members = append(members, *m)
		}
	}
	return members, nil
}

func (s *Store) UpdateMember(ctx context.Context, member *canopy.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memberKey(member.OrganizationID, member.UserID)
	if s.members[key] == nil {
		return canopy.ErrNotFound
	}
	cp := *member
	s.members[key] = &cp
	return nil
}

func (s *Store) UpdateMemberRole(ctx context.Context, member *canopy.Member, protectedRole string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memberKey(member.OrganizationID, member.UserID)
	current := s.members[key]
	if current == nil {
		return canopy.ErrNotFound
	}
	if current.Role == protectedRole && member.Role != protectedRole {
		owners := 0
		for _, candidate := range s.members {
			if candidate.OrganizationID == member.OrganizationID && candidate.Role == protectedRole {
				owners++
			}
		}
		if owners <= 1 {
			return canopy.ErrLastOrganizationOwner
		}
	}
	cp := *member
	s.members[key] = &cp
	return nil
}

func (s *Store) DeleteMember(ctx context.Context, orgID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memberKey(orgID, userID)
	if s.members[key] == nil {
		return canopy.ErrNotFound
	}
	delete(s.members, key)
	return nil
}

func (s *Store) ClearActiveOrganization(ctx context.Context, orgID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, session := range s.sessions {
		if session.UserID == userID && session.ActiveOrganizationID == orgID {
			session.ActiveOrganizationID = ""
			session.UpdatedAt = time.Now().UTC()
		}
	}
	return nil
}

func (s *Store) RemoveMemberAndClearSessions(ctx context.Context, orgID, userID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memberKey(orgID, userID)
	if s.members[key] == nil {
		return canopy.ErrNotFound
	}
	delete(s.members, key)
	for _, session := range s.sessions {
		if session.UserID == userID && session.ActiveOrganizationID == orgID {
			session.ActiveOrganizationID = ""
			session.UpdatedAt = now
		}
	}
	return nil
}

func (s *Store) CreateInvitation(ctx context.Context, invitation *canopy.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *invitation
	s.invitations[invitation.ID] = &cp
	return nil
}

func (s *Store) FindInvitation(ctx context.Context, id string) (*canopy.Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v := s.invitations[id]; v != nil {
		cp := *v
		return &cp, nil
	}
	return nil, canopy.ErrNotFound
}

func (s *Store) ListInvitationsForOrg(ctx context.Context, orgID string) ([]canopy.Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var invitations []canopy.Invitation
	for _, v := range s.invitations {
		if v.OrganizationID == orgID {
			invitations = append(invitations, *v)
		}
	}
	return invitations, nil
}

func (s *Store) UpdateInvitation(ctx context.Context, invitation *canopy.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invitations[invitation.ID] == nil {
		return canopy.ErrNotFound
	}
	cp := *invitation
	s.invitations[invitation.ID] = &cp
	return nil
}

func (s *Store) AcceptInvitation(
	ctx context.Context,
	invitationID string,
	email string,
	now time.Time,
	member *canopy.Member,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation := s.invitations[invitationID]
	if invitation == nil ||
		invitation.Status != "pending" ||
		!invitation.ExpiresAt.After(now) ||
		!strings.EqualFold(strings.TrimSpace(invitation.Email), strings.TrimSpace(email)) {
		return canopy.ErrNotFound
	}
	if key := memberKey(member.OrganizationID, member.UserID); s.members[key] == nil {
		memberCopy := *member
		s.members[key] = &memberCopy
	}
	invitation.Status = "accepted"
	invitation.UpdatedAt = now
	return nil
}

func (s *Store) ListUsers(ctx context.Context, q canopy.UserQuery) ([]canopy.User, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	search := strings.ToLower(strings.TrimSpace(q.Search))
	var matched []canopy.User
	for _, u := range s.users {
		if search == "" || strings.Contains(strings.ToLower(u.Name), search) || strings.Contains(strings.ToLower(u.Email), search) {
			matched = append(matched, *u)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].CreatedAt.Before(matched[j].CreatedAt) })
	total := len(matched)
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	start := q.Offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	return matched[start:end], total, nil
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]canopy.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sessions []canopy.Session
	for _, se := range s.sessions {
		if se.UserID == userID {
			sessions = append(sessions, *se)
		}
	}
	return sessions, nil
}
