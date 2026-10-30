//! Errores tipados del workspace (sin `unwrap` en bibliotecas).

use std::fmt;

/// Error de biblioteca.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Argumento fuera de rango / inválido.
    InvalidArg(&'static str),
    /// Estado inconsistente del modelo.
    InvariantBroken(&'static str),
    /// Entrada de transcripción / protocolo inválida.
    Protocol(&'static str),
    /// E/S encapsulada como mensaje estático cuando no hay alloc context.
    Msg(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArg(s) => write!(f, "invalid arg: {s}"),
            Error::InvariantBroken(s) => write!(f, "invariant broken: {s}"),
            Error::Protocol(s) => write!(f, "protocol: {s}"),
            Error::Msg(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Resultado de biblioteca.
pub type Result<T> = std::result::Result<T, Error>;
