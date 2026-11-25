// Package framing holds HTTP framing rules shared by the keyring and the
// relay. It has no dependencies, so the relay stays small.
package framing

// HTTP10AnswerLimit bounds the answer the keyring and the relay hold for an
// HTTP/1.0 caller, which only gets a complete answer with its length. The
// keyring applies it both to what it reads and to what it would send after
// masking.
const HTTP10AnswerLimit = 32 << 20
