Divergences
===========

The spec is still in flux. These are the known divergences/caveats related to how this library represents the spec.

- Status code 0x100 is not currently used. If IDs ever get rolled into the nut, then this could change.

- The spec is unclear about how to handle unsupported options. For now, the library leaves it up to the server to decide whether to hard or soft fail an option request. Hard fail will result in setting TIF codes 0x10 and 0x80 and aborting any requested actions. A soft fail will result in the command being successfully concluded without any notice to the user, unless the server chooses to use the ASK feature.
