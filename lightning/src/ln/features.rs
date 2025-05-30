// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Implementations of extensions on features.

use lightning_types::features::ChannelTypeFeatures;
use lightning_types::features::{BlindedHopFeatures, Bolt12InvoiceFeatures};
use lightning_types::features::{Bolt11InvoiceFeatures, InvoiceRequestFeatures, OfferFeatures};
use lightning_types::features::{ChannelFeatures, InitFeatures, NodeFeatures};

#[allow(unused_imports)]
use crate::prelude::*;

use crate::ln::msgs::DecodeError;
use crate::util::ser::{Readable, WithoutLength, Writeable, Writer};
use crate::{io, io_extras};

fn write_be<W: Writer>(w: &mut W, le_flags: &[u8]) -> Result<(), io::Error> {
	// Swap back to big-endian
	for f in le_flags.iter().rev() {
		f.write(w)?;
	}
	Ok(())
}

macro_rules! impl_feature_len_prefixed_write {
	($features: ident) => {
		impl Writeable for $features {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				let bytes = self.le_flags();
				(bytes.len() as u16).write(w)?;
				write_be(w, bytes)
			}
		}
		impl Readable for $features {
			fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
				Ok(Self::from_be_bytes(Vec::<u8>::read(r)?))
			}
		}
	};
}
impl_feature_len_prefixed_write!(InitFeatures);
impl_feature_len_prefixed_write!(ChannelFeatures);
impl_feature_len_prefixed_write!(NodeFeatures);
impl_feature_len_prefixed_write!(Bolt11InvoiceFeatures);
impl_feature_len_prefixed_write!(Bolt12InvoiceFeatures);
impl_feature_len_prefixed_write!(BlindedHopFeatures);

// Some features only appear inside of TLVs, so they don't have a length prefix when serialized.
macro_rules! impl_feature_tlv_write {
	($features: ident) => {
		impl Writeable for $features {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				WithoutLength(self).write(w)
			}
		}
		impl Readable for $features {
			fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
				Ok(WithoutLength::<Self>::read(r)?.0)
			}
		}
	};
}

impl_feature_tlv_write!(ChannelTypeFeatures);

// Some features may appear both in a TLV record and as part of a TLV subtype sequence. The latter
// requires a length but the former does not.

macro_rules! impl_feature_write_without_length {
	($features: ident) => {
		impl Writeable for WithoutLength<&$features> {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
				write_be(w, self.0.le_flags())
			}
		}

		impl Readable for WithoutLength<$features> {
			fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
				let v = io_extras::read_to_end(r)?;
				Ok(WithoutLength($features::from_be_bytes(v)))
			}
		}
	};
}

impl_feature_write_without_length!(Bolt12InvoiceFeatures);
impl_feature_write_without_length!(ChannelTypeFeatures);
impl_feature_write_without_length!(InvoiceRequestFeatures);
impl_feature_write_without_length!(OfferFeatures);
impl_feature_write_without_length!(BlindedHopFeatures);

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util::ser::{Readable, WithoutLength, Writeable};

	#[test]
	fn encodes_features_without_length() {
		let features = OfferFeatures::from_le_bytes(vec![1, 2, 3, 4, 5, 42, 100, 101]);
		assert_eq!(features.le_flags().len(), 8);

		let mut serialized_features = Vec::new();
		WithoutLength(&features).write(&mut serialized_features).unwrap();
		assert_eq!(serialized_features.len(), 8);

		let deserialized_features =
			WithoutLength::<OfferFeatures>::read(&mut &serialized_features[..]).unwrap().0;
		assert_eq!(features, deserialized_features);
	}
}
