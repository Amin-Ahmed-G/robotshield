//! Per-joint limits.

use serde::{Deserialize, Serialize};

/// Which quantity of a joint command a limit applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Position,
    Velocity,
    Effort,
}

impl Field {
    pub const ALL: [Field; 3] = [Field::Position, Field::Velocity, Field::Effort];

    pub fn as_str(self) -> &'static str {
        match self {
            Field::Position => "position",
            Field::Velocity => "velocity",
            Field::Effort => "effort",
        }
    }
}

/// Allowed ranges for one joint. Infinite bounds disable a check.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct JointLimits {
    pub position_min: f64,
    pub position_max: f64,
    /// Symmetric |velocity| limit.
    pub velocity: f64,
    /// Symmetric |effort| limit.
    pub effort: f64,
}

impl Default for JointLimits {
    fn default() -> Self {
        Self {
            position_min: f64::NEG_INFINITY,
            position_max: f64::INFINITY,
            velocity: f64::INFINITY,
            effort: f64::INFINITY,
        }
    }
}

impl JointLimits {
    /// (low, high) for a field; velocity and effort are symmetric.
    pub fn bounds(&self, field: Field) -> (f64, f64) {
        match field {
            Field::Position => (self.position_min, self.position_max),
            Field::Velocity => (-self.velocity.abs(), self.velocity.abs()),
            Field::Effort => (-self.effort.abs(), self.effort.abs()),
        }
    }

    pub fn clamp(&self, field: Field, value: f64) -> f64 {
        let (low, high) = self.bounds(field);
        value.max(low).min(high)
    }

    pub fn violates(&self, field: Field, value: f64) -> bool {
        let (low, high) = self.bounds(field);
        value < low || value > high
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_and_bounds() {
        let lim = JointLimits { position_min: -0.5, position_max: 2.0, velocity: 1.0, ..Default::default() };
        assert_eq!(lim.clamp(Field::Position, 3.0), 2.0);
        assert_eq!(lim.clamp(Field::Position, -1.0), -0.5);
        assert_eq!(lim.clamp(Field::Velocity, -4.0), -1.0);
        assert!(lim.violates(Field::Velocity, 1.1));
        assert!(!lim.violates(Field::Effort, 1e6));
    }
}
