package canopy

import (
	"context"
	"sync"
	"time"
)

type memoryStore struct {
	mu            sync.Mutex
	usersByEmail  map[string]*User
	accountsByKey map[string]*Account
	sessionsByTok map[string]*Session
	verifications map[string]*Verification
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		usersByEmail:  map[string]*User{},
		accountsByKey: map[string]*Account{},
		sessionsByTok: map[string]*Session{},
		verifications: map[string]*Verification{},
	}
}

func (s *memoryStore) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.usersByEmail[normalizeEmail(email)]
	if u == nil {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *memoryStore) FindUserByID(ctx context.Context, id string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.usersByEmail {
		if u.ID == id {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *memoryStore) CreateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email := normalizeEmail(user.Email)
	if s.usersByEmail[email] != nil {
		return ErrConflict
	}
	cp := *user
	s.usersByEmail[email] = &cp
	return nil
}

func (s *memoryStore) UpdateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email := normalizeEmail(user.Email)
	if s.usersByEmail[email] == nil {
		return ErrNotFound
	}
	cp := *user
	s.usersByEmail[email] = &cp
	return nil
}

func (s *memoryStore) FindAccount(ctx context.Context, providerID, accountID string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneAccount(s.accountsByKey[providerID+"|"+accountID])
}

func (s *memoryStore) FindAccountByUserProvider(ctx context.Context, userID, providerID string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accountsByKey {
		if a.UserID == userID && a.ProviderID == providerID {
			cp := *a
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *memoryStore) CreateAccount(ctx context.Context, account *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := account.ProviderID + "|" + account.AccountID
	if s.accountsByKey[key] != nil {
		return ErrConflict
	}
	cp := *account
	s.accountsByKey[key] = &cp
	return nil
}

func (s *memoryStore) CreateUserAccount(ctx context.Context, user *User, account *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email := normalizeEmail(user.Email)
	accountKey := account.ProviderID + "|" + account.AccountID
	if s.usersByEmail[email] != nil || s.accountsByKey[accountKey] != nil {
		return ErrConflict
	}
	userCopy := *user
	accountCopy := *account
	s.usersByEmail[email] = &userCopy
	s.accountsByKey[accountKey] = &accountCopy
	return nil
}

func (s *memoryStore) UpdateAccount(ctx context.Context, account *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := account.ProviderID + "|" + account.AccountID
	if s.accountsByKey[key] == nil {
		return ErrNotFound
	}
	cp := *account
	s.accountsByKey[key] = &cp
	return nil
}

func (s *memoryStore) CreateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *session
	s.sessionsByTok[session.Token] = &cp
	return nil
}

func (s *memoryStore) FindSessionByToken(ctx context.Context, token string) (*SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ses := s.sessionsByTok[token]
	if ses == nil {
		return nil, ErrNotFound
	}
	for _, u := range s.usersByEmail {
		if u.ID == ses.UserID {
			return &SessionData{User: *u, Session: *ses}, nil
		}
	}
	return nil, ErrNotFound
}

func (s *memoryStore) UpdateSession(ctx context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionsByTok[session.Token] == nil {
		return ErrNotFound
	}
	cp := *session
	s.sessionsByTok[session.Token] = &cp
	return nil
}

func (s *memoryStore) DeleteSessionByToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionsByTok[token] == nil {
		return ErrNotFound
	}
	delete(s.sessionsByTok, token)
	return nil
}

func (s *memoryStore) DeleteUserSessions(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, ses := range s.sessionsByTok {
		if ses.UserID == userID {
			delete(s.sessionsByTok, tok)
		}
	}
	return nil
}

func (s *memoryStore) CreateVerification(ctx context.Context, verification *Verification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *verification
	s.verifications[verification.Identifier+"|"+verification.Value] = &cp
	return nil
}

func (s *memoryStore) ConsumeVerification(ctx context.Context, identifier, value string, now time.Time) (*Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := identifier + "|" + value
	v := s.verifications[key]
	if v == nil || !v.ExpiresAt.After(now) {
		return nil, ErrNotFound
	}
	delete(s.verifications, key)
	cp := *v
	return &cp, nil
}

func (s *memoryStore) DeleteExpiredVerifications(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, v := range s.verifications {
		if !v.ExpiresAt.After(now) {
			delete(s.verifications, key)
		}
	}
	return nil
}

func cloneAccount(a *Account) (*Account, error) {
	if a == nil {
		return nil, ErrNotFound
	}
	cp := *a
	return &cp, nil
}

type testAuditLogger struct {
	events []AuditEvent
}

func (l *testAuditLogger) LogAuthEvent(ctx context.Context, event AuditEvent) {
	l.events = append(l.events, event)
}
