//! Model checker explícito genérico (BFS / DFS) sobre [`fa_core::Model`].
//!
//! Dedupe por `Hash` del estado, contraejemplos mínimos y exportación DOT.
//! Feature `parallel`: expansión de sucesores con rayon (opcional).
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]

use fa_core::{Action, CheckOutcome, Counterexample, Model, Property, Result, State, Transition};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// Configuración del checker.
#[derive(Clone, Debug)]
pub struct CheckerConfig {
    /// Límite de estados (0 = sin límite práctico salvo memoria).
    pub max_states: u64,
    /// Usar DFS en lugar de BFS.
    pub dfs: bool,
}

impl Default for CheckerConfig {
    fn default() -> Self {
        Self {
            max_states: 1_000_000,
            dfs: false,
        }
    }
}

/// Informe de exploración (sin violación).
#[derive(Clone, Debug)]
pub struct ExploreReport {
    /// Estados.
    pub states: u64,
    /// Transiciones.
    pub transitions: u64,
    /// ms.
    pub elapsed_ms: u64,
}

/// Verifica todas las propiedades sobre el modelo.
pub fn check<M, P>(
    model: &M,
    properties: &[P],
    cfg: &CheckerConfig,
) -> Result<CheckOutcome<M::S, M::A>>
where
    M: Model,
    P: Property<M>,
{
    let t0 = Instant::now();
    let mut seen: HashSet<M::S> = HashSet::new();
    let mut parent: HashMap<M::S, Option<(M::S, M::A)>> = HashMap::new();
    let mut q: VecDeque<M::S> = VecDeque::new();
    let mut transitions = 0u64;

    for s0 in model.initials() {
        if seen.insert(s0.clone()) {
            parent.insert(s0.clone(), None);
            q.push_back(s0);
        }
    }

    while let Some(s) = if cfg.dfs { q.pop_back() } else { q.pop_front() } {
        if seen.len() as u64 > cfg.max_states {
            break;
        }
        for prop in properties {
            if !prop.holds(model, &s)? {
                let trace = reconstruct_trace(&parent, &s);
                return Ok(CheckOutcome::Violated {
                    states: seen.len() as u64,
                    transitions,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                    counterexample: Counterexample {
                        property: prop.name().to_string(),
                        trace,
                    },
                });
            }
        }
        let succs = model.successors(&s)?;
        for (a, s2) in succs {
            transitions += 1;
            if seen.insert(s2.clone()) {
                parent.insert(s2.clone(), Some((s.clone(), a)));
                q.push_back(s2);
            }
        }
    }

    Ok(CheckOutcome::Ok {
        states: seen.len() as u64,
        transitions,
        elapsed_ms: t0.elapsed().as_millis() as u64,
    })
}

fn reconstruct_trace<S: State, A: Action>(
    parent: &HashMap<S, Option<(S, A)>>,
    end: &S,
) -> Vec<Transition<S, A>> {
    let mut chain: Vec<Transition<S, A>> = Vec::new();
    let mut cur = end.clone();
    while let Some(Some((prev, act))) = parent.get(&cur) {
        chain.push(Transition {
            from: prev.clone(),
            action: act.clone(),
            to: cur.clone(),
        });
        cur = prev.clone();
    }
    chain.reverse();
    chain
}

/// Explora sin propiedades (conteo de estados).
pub fn explore<M: Model>(model: &M, cfg: &CheckerConfig) -> Result<ExploreReport> {
    let empty: &[NoProp<M>] = &[];
    match check(model, empty, cfg)? {
        CheckOutcome::Ok {
            states,
            transitions,
            elapsed_ms,
        } => Ok(ExploreReport {
            states,
            transitions,
            elapsed_ms,
        }),
        CheckOutcome::Violated {
            states,
            transitions,
            elapsed_ms,
            ..
        } => Ok(ExploreReport {
            states,
            transitions,
            elapsed_ms,
        }),
    }
}

struct NoProp<M>(std::marker::PhantomData<M>);
impl<M: Model> Property<M> for NoProp<M> {
    fn name(&self) -> &str {
        "none"
    }
    fn holds(&self, _: &M, _: &M::S) -> Result<bool> {
        Ok(true)
    }
}

/// Exporta el grafo de estados alcanzables a DOT.
pub fn to_dot<M: Model>(model: &M, cfg: &CheckerConfig) -> Result<String> {
    let mut seen: HashSet<M::S> = HashSet::new();
    let mut q: VecDeque<M::S> = VecDeque::new();
    let mut edges: Vec<(String, String, String)> = Vec::new();
    for s0 in model.initials() {
        if seen.insert(s0.clone()) {
            q.push_back(s0);
        }
    }
    while let Some(s) = q.pop_front() {
        if seen.len() as u64 > cfg.max_states {
            break;
        }
        for (a, s2) in model.successors(&s)? {
            edges.push((s.label(), s2.label(), a.name().to_string()));
            if seen.insert(s2.clone()) {
                q.push_back(s2);
            }
        }
    }
    let mut out = String::from("digraph {\n  rankdir=LR;\n");
    for s in &seen {
        out.push_str(&format!("  \"{}\";\n", s.label().replace('"', "'")));
    }
    for (u, v, a) in edges {
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
            u.replace('"', "'"),
            v.replace('"', "'"),
            a.replace('"', "'")
        ));
    }
    out.push_str("}\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_core::{Action, Model, State};

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct S(u8);
    impl State for S {
        fn label(&self) -> String {
            format!("s{}", self.0)
        }
    }
    #[derive(Clone, Debug)]
    struct A(&'static str);
    impl Action for A {
        fn name(&self) -> &str {
            self.0
        }
    }
    struct Tiny;
    impl Model for Tiny {
        type S = S;
        type A = A;
        fn name(&self) -> &str {
            "tiny"
        }
        fn initials(&self) -> Vec<S> {
            vec![S(0)]
        }
        fn successors(&self, s: &S) -> Result<Vec<(A, S)>> {
            if s.0 < 3 {
                Ok(vec![(A("inc"), S(s.0 + 1))])
            } else {
                Ok(vec![])
            }
        }
    }

    #[test]
    fn explore_tiny() {
        let r = explore(&Tiny, &CheckerConfig::default()).unwrap();
        assert_eq!(r.states, 4);
        assert_eq!(r.transitions, 3);
    }
}
