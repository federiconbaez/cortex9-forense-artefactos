//! Traits genéricos para modelos, propiedades y mutantes.

use crate::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::hash::Hash;

/// Estado de un modelo (debe ser hasheable para dedupe BFS/DFS).
pub trait State: Clone + Eq + Hash + Debug + Send + Sync {
    /// Resumen corto para DOT / logs.
    fn label(&self) -> String;
}

/// Acción que transforma un estado.
pub trait Action: Clone + Debug + Send + Sync {
    /// Nombre estable de la acción.
    fn name(&self) -> &str;
}

/// Transición observada.
#[derive(Clone, Debug)]
pub struct Transition<S: State, A: Action> {
    /// Estado origen.
    pub from: S,
    /// Acción aplicada.
    pub action: A,
    /// Estado destino.
    pub to: S,
}

/// Contraejemplo mínimo (traza reproducible).
#[derive(Clone, Debug)]
pub struct Counterexample<S: State, A: Action> {
    /// Propiedad violada.
    pub property: String,
    /// Traza desde el inicial hasta la violación.
    pub trace: Vec<Transition<S, A>>,
}

/// Modelo con estados iniciales y sucesores.
pub trait Model: Send + Sync {
    /// Tipo de estado.
    type S: State;
    /// Tipo de acción.
    type A: Action;

    /// Nombre del modelo.
    fn name(&self) -> &str;

    /// Estados iniciales.
    fn initials(&self) -> Vec<Self::S>;

    /// Sucesores de un estado.
    fn successors(&self, state: &Self::S) -> Result<Vec<(Self::A, Self::S)>>;
}

/// Propiedad / invariante evaluable en un estado (y opcionalmente traza).
pub trait Property<M: Model>: Send + Sync {
    /// Nombre de la propiedad.
    fn name(&self) -> &str;

    /// ¿Se cumple en este estado?
    fn holds(&self, model: &M, state: &M::S) -> Result<bool>;
}

/// Resultado de verificación.
#[derive(Clone, Debug)]
pub enum CheckOutcome<S: State, A: Action> {
    /// Sin violaciones.
    Ok {
        /// Estados explorados.
        states: u64,
        /// Transiciones.
        transitions: u64,
        /// Tiempo en ms.
        elapsed_ms: u64,
    },
    /// Violación con contraejemplo.
    Violated {
        /// Estados explorados hasta el hallazgo.
        states: u64,
        /// Transiciones.
        transitions: u64,
        /// Tiempo en ms.
        elapsed_ms: u64,
        /// Contraejemplo.
        counterexample: Counterexample<S, A>,
    },
}

/// Mutante intencional: el checker debe detectarlo.
pub trait Mutant: Send + Sync {
    /// Identificador estable.
    fn id(&self) -> &str;
    /// Modelo al que aplica.
    fn model(&self) -> &str;
    /// Ejecuta la detección; `true` = el fallo del mutante fue observado.
    fn detect(&self) -> Result<bool>;
}

/// Informe serializable de una medición Monte-Carlo.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct McReport {
    /// Nombre.
    pub name: String,
    /// Trials.
    pub trials: u64,
    /// Propiedades ok / trials.
    pub properties: Vec<(String, u64)>,
    /// ¿Todas cumplidas?
    pub all_pass: bool,
}
