#[cfg(all(feature = "sha2", feature = "robust"))]
mod sha2_robust;
#[cfg(all(feature = "sha2", feature = "simple"))]
mod sha2_simple;
#[cfg(all(feature = "shake", feature = "robust"))]
mod shake_robust;
#[cfg(all(feature = "shake", feature = "simple"))]
mod shake_simple;
#[cfg(all(feature = "blake2s", feature = "simple"))]
mod blake2s_simple;

#[cfg(all(feature = "sha2", feature = "simple"))]
pub use sha2_simple::*;

#[cfg(all(feature = "sha2", feature = "robust"))]
pub use sha2_robust::*;

#[cfg(all(feature = "shake", feature = "simple"))]
pub use shake_simple::*;

#[cfg(all(feature = "shake", feature = "robust"))]
pub use shake_robust::*;

#[cfg(all(feature = "blake2s", feature = "simple"))]
pub use blake2s_simple::*;
