use vsss_rs::*;
use elliptic_curve::PrimeField;
use k256::{NonZeroScalar, Scalar, SecretKey};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

#[pyfunction]
fn reconstruct_secret(shares: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    let res = combine_shares::<Scalar, u8, Vec<u8>>(&shares);
    assert!(res.is_ok());
    
    let scalar: Scalar = res.unwrap();
    let nzs = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
    let sk = SecretKey::from(nzs);

    Ok(sk.to_bytes().to_vec())
}

#[pymodule]
fn vssspy(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(reconstruct_secret, m)?)?;
    Ok(())
}