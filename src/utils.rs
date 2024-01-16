/// A utility macro that wraps around Result expressions and
/// emits trace logs.
macro_rules! t {
    ($id:expr, $expr:expr $(,)?) => {
        match $expr {
            Ok(val) => {
                trace!("{} ok.", $id);
                Ok(val)
            }
            Err(err) => {
                error!("{} failed. Reason: {err:?}", $id);
                Err(err)
            }
        }
    };
}

pub(crate) use t;
