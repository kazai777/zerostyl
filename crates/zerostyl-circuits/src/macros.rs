/// Register a circuit with a [`Registry`](crate::Registry).
///
/// Expects the named crate (or in-scope module) to expose a public
/// `descriptor() -> &'static dyn CircuitDescriptor` function — the canonical
/// shape every ZeroStyl circuit follows. See `examples/example_demo/` for
/// the minimal template.
///
/// The macro expands to a [`Registry::register`](crate::Registry::register) call,
/// so use `?` to propagate registration errors (e.g. duplicate names).
///
/// # Example
///
/// ```ignore
/// use zerostyl_circuits::{register_circuit, Registry};
///
/// let registry = Registry::new();
/// register_circuit!(registry, state_mask)?;
/// register_circuit!(registry, my_custom_circuit)?;
/// ```
///
/// The second argument is matched as a single identifier (the crate/module
/// name). For multi-segment paths, call `registry.register(some::path::descriptor())`
/// directly.
#[macro_export]
macro_rules! register_circuit {
    ($registry:expr, $crate_name:ident) => {
        $registry.register($crate_name::descriptor())
    };
}
